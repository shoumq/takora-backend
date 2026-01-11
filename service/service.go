package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"grape/model"
	"grape/repo"
)

var ErrUnauthorized = errors.New("unauthorized")
var ErrUsernameTaken = errors.New("username taken")
var ErrSMSNotConfigured = errors.New("sms not configured")
var ErrInvalidCode = errors.New("invalid code")
var ErrCodeExpired = errors.New("code expired")
var ErrCodeNotFound = errors.New("code not found")

type Service struct {
	repo       *repo.Repository
	tokenTTL   time.Duration
	smsSender  SMSSender
	pushSender PushSender
}

func New(r *repo.Repository, tokenTTL time.Duration, smsSender SMSSender, pushSender PushSender) *Service {
	return &Service{
		repo:       r,
		tokenTTL:   tokenTTL,
		smsSender:  smsSender,
		pushSender: pushSender,
	}
}

func (s *Service) Register(ctx context.Context, username, password, publicKey, phone string) (model.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return model.User{}, err
	}
	userID, err := s.repo.CreateUser(ctx, username, string(hash), publicKey, phone)
	if err != nil {
		if errors.Is(err, repo.ErrUsernameTaken) {
			return model.User{}, ErrUsernameTaken
		}
		if errors.Is(err, repo.ErrPhoneTaken) {
			return model.User{}, repo.ErrPhoneTaken
		}
		return model.User{}, err
	}
	return model.User{ID: userID, Username: username, PublicKey: publicKey}, nil
}

func (s *Service) Login(ctx context.Context, username, password string) (string, int64, time.Time, error) {
	userID, hash, err := s.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return "", 0, time.Time{}, ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", 0, time.Time{}, ErrUnauthorized
	}
	token, err := generateToken(32)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	expiresAt := time.Now().Add(s.tokenTTL)
	if err := s.repo.CreateSession(ctx, userID, token, expiresAt); err != nil {
		return "", 0, time.Time{}, err
	}
	return token, userID, expiresAt, nil
}

func (s *Service) LoginByPhone(ctx context.Context, phone, password string) (string, int64, time.Time, error) {
	userID, hash, err := s.repo.GetUserByPhone(ctx, phone)
	if err != nil {
		return "", 0, time.Time{}, ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", 0, time.Time{}, ErrUnauthorized
	}
	token, err := generateToken(32)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	expiresAt := time.Now().Add(s.tokenTTL)
	if err := s.repo.CreateSession(ctx, userID, token, expiresAt); err != nil {
		return "", 0, time.Time{}, err
	}
	return token, userID, expiresAt, nil
}

const (
	phoneCodeTTL         = 5 * time.Minute
	phoneCodeMaxAttempts = 5
	phoneCodeLength      = 6
)

func (s *Service) SendPhoneCode(ctx context.Context, phone string) error {
	if s.smsSender == nil {
		return ErrSMSNotConfigured
	}
	if _, _, err := s.repo.GetUserByPhone(ctx, phone); err == nil {
		return repo.ErrPhoneTaken
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	code, err := generateNumericCode(phoneCodeLength)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(phoneCodeTTL)
	if err := s.repo.UpsertPhoneVerification(ctx, phone, string(hash), expiresAt); err != nil {
		return err
	}
	message := "Ваш код: " + code
	return s.smsSender.Send(ctx, phone, message)
}

func (s *Service) RegisterByPhoneCode(ctx context.Context, phone, code, username, password, publicKey string) (model.User, error) {
	hash, expiresAt, attempts, err := s.repo.GetPhoneVerification(ctx, phone)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, ErrCodeNotFound
		}
		return model.User{}, err
	}
	if time.Now().After(expiresAt) {
		_ = s.repo.DeletePhoneVerification(ctx, phone)
		return model.User{}, ErrCodeExpired
	}
	if attempts >= phoneCodeMaxAttempts {
		return model.User{}, ErrInvalidCode
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)); err != nil {
		_ = s.repo.IncrementPhoneVerificationAttempts(ctx, phone)
		return model.User{}, ErrInvalidCode
	}
	user, err := s.Register(ctx, username, password, publicKey, phone)
	if err != nil {
		return model.User{}, err
	}
	_ = s.repo.DeletePhoneVerification(ctx, phone)
	return user, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (int64, error) {
	return s.repo.GetSessionUserID(ctx, token)
}

func (s *Service) GetUser(ctx context.Context, userID int64) (model.User, error) {
	return s.repo.GetUser(ctx, userID)
}

func (s *Service) UpdateUser(ctx context.Context, userID int64, update model.UserUpdate) (model.User, error) {
	if err := s.repo.UpdateUser(ctx, userID, update); err != nil {
		if errors.Is(err, repo.ErrPhoneTaken) {
			return model.User{}, repo.ErrPhoneTaken
		}
		return model.User{}, err
	}
	return s.repo.GetUser(ctx, userID)
}

func (s *Service) SearchUsers(ctx context.Context, username string, limit int, excludeUserID int64) ([]model.User, error) {
	return s.repo.SearchUsers(ctx, username, limit, excludeUserID)
}

func (s *Service) RandomUsers(ctx context.Context, limit int, excludeUserID int64) ([]model.User, error) {
	return s.repo.RandomUsers(ctx, limit, excludeUserID)
}

func (s *Service) UserInChat(ctx context.Context, userID, chatID int64) (bool, error) {
	return s.repo.UserInChat(ctx, userID, chatID)
}

func (s *Service) FindOrCreateChat(ctx context.Context, userID, peerID int64) (int64, error) {
	return s.repo.FindOrCreateChat(ctx, userID, peerID)
}

func (s *Service) ListChats(ctx context.Context, userID int64) ([]model.ChatSummary, error) {
	return s.repo.ListChats(ctx, userID)
}

func (s *Service) GetChatSummary(ctx context.Context, userID, chatID int64) (model.ChatSummary, error) {
	return s.repo.GetChatSummary(ctx, userID, chatID)
}

func (s *Service) ListChatMemberIDs(ctx context.Context, chatID int64) ([]int64, error) {
	return s.repo.ListChatMemberIDs(ctx, chatID)
}

func (s *Service) ListMessages(ctx context.Context, chatID, beforeID int64, limit int) ([]model.Message, error) {
	return s.repo.ListMessages(ctx, chatID, beforeID, limit)
}

func (s *Service) StoreMessage(ctx context.Context, chatID, userID int64, ciphertext, nonce string) (model.Message, error) {
	return s.repo.StoreMessage(ctx, chatID, userID, ciphertext, nonce)
}

func generateToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func generateNumericCode(length int) (string, error) {
	if length <= 0 {
		length = 6
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := 0; i < length; i++ {
		buf[i] = '0' + (buf[i] % 10)
	}
	return string(buf), nil
}
