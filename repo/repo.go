package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"grape/model"
)

var ErrUsernameTaken = errors.New("username taken")
var ErrPhoneTaken = errors.New("phone taken")

type Repository struct {
	db *sql.DB
}

func New(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateUser(ctx context.Context, username, passwordHash, publicKey, phone string) (int64, error) {
	var userID int64
	var phoneValue interface{}
	if phone == "" {
		phoneValue = nil
	} else {
		phoneValue = phone
	}
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO users (username, password_hash, public_key, phone) VALUES ($1, $2, $3, $4) RETURNING id`,
		username, passwordHash, publicKey, phoneValue,
	).Scan(&userID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "users_username_key":
				return 0, ErrUsernameTaken
			case "users_phone_key":
				return 0, ErrPhoneTaken
			}
		}
		return 0, err
	}
	return userID, err
}

func (r *Repository) GetUser(ctx context.Context, userID int64) (model.User, error) {
	var u model.User
	var name sql.NullString
	var dob sql.NullTime
	var phone sql.NullString
	var email sql.NullString
	var avatar sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT id, username, public_key, name, date_of_birth, phone, email, avatar
		   FROM users
		  WHERE id = $1`,
		userID,
	).Scan(&u.ID, &u.Username, &u.PublicKey, &name, &dob, &phone, &email, &avatar)
	applyOptionalUserFields(&u, name, dob, phone, email, avatar)
	return u, err
}

func (r *Repository) SearchUsers(ctx context.Context, username string, limit int, excludeUserID int64) ([]model.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, public_key, name, date_of_birth, phone, email, avatar
		   FROM users
		  WHERE id <> $2 AND username ILIKE $1
		  ORDER BY username
		  LIMIT $3`,
		"%"+username+"%", excludeUserID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		var u model.User
		var name sql.NullString
		var dob sql.NullTime
		var phone sql.NullString
		var email sql.NullString
		var avatar sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &u.PublicKey, &name, &dob, &phone, &email, &avatar); err != nil {
			return nil, err
		}
		applyOptionalUserFields(&u, name, dob, phone, email, avatar)
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *Repository) RandomUsers(ctx context.Context, limit int, excludeUserID int64) ([]model.User, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, username, public_key, name, date_of_birth, phone, email, avatar
		   FROM users
		  WHERE id <> $1
		  ORDER BY random()
		  LIMIT $2`,
		excludeUserID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		var u model.User
		var name sql.NullString
		var dob sql.NullTime
		var phone sql.NullString
		var email sql.NullString
		var avatar sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &u.PublicKey, &name, &dob, &phone, &email, &avatar); err != nil {
			return nil, err
		}
		applyOptionalUserFields(&u, name, dob, phone, email, avatar)
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *Repository) UpdateUser(ctx context.Context, userID int64, update model.UserUpdate) error {
	setParts := make([]string, 0, 5)
	args := []interface{}{userID}
	argIndex := 2
	add := func(column string, value interface{}) {
		setParts = append(setParts, fmt.Sprintf("%s = $%d", column, argIndex))
		args = append(args, value)
		argIndex++
	}
	if update.NameSet {
		add("name", update.Name)
	}
	if update.DateOfBirthSet {
		add("date_of_birth", update.DateOfBirth)
	}
	if update.PhoneSet {
		add("phone", update.Phone)
	}
	if update.EmailSet {
		add("email", update.Email)
	}
	if update.AvatarSet {
		add("avatar", update.Avatar)
	}
	if len(setParts) == 0 {
		return errors.New("no fields to update")
	}
	query := `UPDATE users SET ` + strings.Join(setParts, ", ") + ` WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "users_phone_key":
				return ErrPhoneTaken
			}
		}
		return err
	}
	return nil
}

func (r *Repository) GetUserByUsername(ctx context.Context, username string) (int64, string, error) {
	var userID int64
	var hash string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE username = $1`,
		username,
	).Scan(&userID, &hash)
	return userID, hash, err
}

func (r *Repository) GetUserByPhone(ctx context.Context, phone string) (int64, string, error) {
	var userID int64
	var hash string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE phone = $1`,
		phone,
	).Scan(&userID, &hash)
	return userID, hash, err
}

func (r *Repository) UpsertPhoneVerification(ctx context.Context, phone, codeHash string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO phone_verifications (phone, code_hash, expires_at, attempts, created_at)
		 VALUES ($1, $2, $3, 0, NOW())
		 ON CONFLICT (phone) DO UPDATE
		   SET code_hash = EXCLUDED.code_hash,
		       expires_at = EXCLUDED.expires_at,
		       attempts = 0,
		       created_at = NOW()`,
		phone, codeHash, expiresAt,
	)
	return err
}

func (r *Repository) GetPhoneVerification(ctx context.Context, phone string) (string, time.Time, int, error) {
	var codeHash string
	var expiresAt time.Time
	var attempts int
	err := r.db.QueryRowContext(ctx,
		`SELECT code_hash, expires_at, attempts FROM phone_verifications WHERE phone = $1`,
		phone,
	).Scan(&codeHash, &expiresAt, &attempts)
	return codeHash, expiresAt, attempts, err
}

func (r *Repository) IncrementPhoneVerificationAttempts(ctx context.Context, phone string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE phone_verifications SET attempts = attempts + 1 WHERE phone = $1`,
		phone,
	)
	return err
}

func (r *Repository) DeletePhoneVerification(ctx context.Context, phone string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM phone_verifications WHERE phone = $1`,
		phone,
	)
	return err
}

func (r *Repository) CreateSession(ctx context.Context, userID int64, token string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		userID, token, expiresAt,
	)
	return err
}

func (r *Repository) GetSessionUserID(ctx context.Context, token string) (int64, error) {
	var userID int64
	err := r.db.QueryRowContext(ctx,
		`SELECT user_id FROM sessions WHERE token = $1 AND expires_at > NOW()`,
		token,
	).Scan(&userID)
	return userID, err
}

func (r *Repository) UserInChat(ctx context.Context, userID, chatID int64) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2)`,
		chatID, userID,
	).Scan(&exists)
	return exists, err
}

func (r *Repository) FindOrCreateChat(ctx context.Context, userID, peerID int64) (int64, error) {
	var chatID int64
	err := r.db.QueryRowContext(ctx,
		`SELECT m1.chat_id
		 FROM chat_members m1
		 JOIN chat_members m2 ON m1.chat_id = m2.chat_id
		 WHERE m1.user_id = $1 AND m2.user_id = $2
		 LIMIT 1`,
		userID, peerID,
	).Scan(&chatID)
	if err == nil {
		return chatID, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `INSERT INTO chats DEFAULT VALUES RETURNING id`).Scan(&chatID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2), ($1, $3)`,
		chatID, userID, peerID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return chatID, nil
}

func (r *Repository) UpsertPushToken(ctx context.Context, userID int64, token, environment string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO push_tokens (token, user_id, environment)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (token)
		 DO UPDATE SET user_id = EXCLUDED.user_id,
		               environment = EXCLUDED.environment,
		               updated_at = NOW()`,
		token, userID, environment,
	)
	return err
}

func (r *Repository) ListPushTokens(ctx context.Context, userIDs []int64) ([]model.PushToken, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	placeholders := make([]string, 0, len(userIDs))
	args := make([]interface{}, 0, len(userIDs))
	for i, id := range userIDs {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
		args = append(args, id)
	}
	query := fmt.Sprintf(
		`SELECT user_id, token, environment, updated_at
		   FROM push_tokens
		  WHERE user_id IN (%s)`,
		strings.Join(placeholders, ","),
	)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []model.PushToken
	for rows.Next() {
		var token model.PushToken
		if err := rows.Scan(&token.UserID, &token.Token, &token.Environment, &token.UpdatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (r *Repository) ListChatMemberIDs(ctx context.Context, chatID int64) ([]int64, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT user_id FROM chat_members WHERE chat_id = $1`, chatID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []int64
	for rows.Next() {
		var userID int64
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		members = append(members, userID)
	}
	return members, rows.Err()
}

func (r *Repository) ListChats(ctx context.Context, userID int64) ([]model.ChatSummary, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT c.id,
		        c.created_at,
		        u.id,
		        u.username,
		        u.public_key,
		        u.name,
		        u.date_of_birth,
		        u.phone,
		        u.email,
		        u.avatar,
		        m.id,
		        m.sender_id,
		        m.ciphertext,
		        m.nonce,
		        m.created_at
		   FROM chats c
		   JOIN chat_members cm ON cm.chat_id = c.id
		   JOIN chat_members cm2 ON cm2.chat_id = c.id AND cm2.user_id <> $1
		   JOIN users u ON u.id = cm2.user_id
		   LEFT JOIN LATERAL (
		       SELECT id, sender_id, ciphertext, nonce, created_at
		         FROM messages
		        WHERE chat_id = c.id
		        ORDER BY id DESC
		        LIMIT 1
		   ) m ON TRUE
		  WHERE cm.user_id = $1
		  ORDER BY c.id DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var chats []model.ChatSummary
	for rows.Next() {
		var chat model.ChatSummary
		var lastID sql.NullInt64
		var lastSender sql.NullInt64
		var lastCipher sql.NullString
		var lastNonce sql.NullString
		var lastCreated sql.NullTime
		var name sql.NullString
		var dob sql.NullTime
		var phone sql.NullString
		var email sql.NullString
		var avatar sql.NullString
		if err := rows.Scan(
			&chat.ID,
			&chat.CreatedAt,
			&chat.Peer.ID,
			&chat.Peer.Username,
			&chat.Peer.PublicKey,
			&name,
			&dob,
			&phone,
			&email,
			&avatar,
			&lastID,
			&lastSender,
			&lastCipher,
			&lastNonce,
			&lastCreated,
		); err != nil {
			return nil, err
		}
		applyOptionalUserFields(&chat.Peer, name, dob, phone, email, avatar)
		if lastID.Valid {
			chat.LastMessage = &model.Message{
				ID:         lastID.Int64,
				ChatID:     chat.ID,
				SenderID:   lastSender.Int64,
				Ciphertext: lastCipher.String,
				Nonce:      lastNonce.String,
				CreatedAt:  lastCreated.Time,
			}
		}
		chats = append(chats, chat)
	}
	return chats, rows.Err()
}

func (r *Repository) GetChatSummary(ctx context.Context, userID, chatID int64) (model.ChatSummary, error) {
	var chat model.ChatSummary
	var lastID sql.NullInt64
	var lastSender sql.NullInt64
	var lastCipher sql.NullString
	var lastNonce sql.NullString
	var lastCreated sql.NullTime
	var name sql.NullString
	var dob sql.NullTime
	var phone sql.NullString
	var email sql.NullString
	var avatar sql.NullString
	err := r.db.QueryRowContext(ctx,
		`SELECT c.id,
		        c.created_at,
		        u.id,
		        u.username,
		        u.public_key,
		        u.name,
		        u.date_of_birth,
		        u.phone,
		        u.email,
		        u.avatar,
		        m.id,
		        m.sender_id,
		        m.ciphertext,
		        m.nonce,
		        m.created_at
		   FROM chats c
		   JOIN chat_members cm ON cm.chat_id = c.id
		   JOIN chat_members cm2 ON cm2.chat_id = c.id AND cm2.user_id <> $1
		   JOIN users u ON u.id = cm2.user_id
		   LEFT JOIN LATERAL (
		       SELECT id, sender_id, ciphertext, nonce, created_at
		         FROM messages
		        WHERE chat_id = c.id
		        ORDER BY id DESC
		        LIMIT 1
		   ) m ON TRUE
		  WHERE cm.user_id = $1
		    AND c.id = $2`,
		userID, chatID,
	).Scan(
		&chat.ID,
		&chat.CreatedAt,
		&chat.Peer.ID,
		&chat.Peer.Username,
		&chat.Peer.PublicKey,
		&name,
		&dob,
		&phone,
		&email,
		&avatar,
		&lastID,
		&lastSender,
		&lastCipher,
		&lastNonce,
		&lastCreated,
	)
	if err != nil {
		return model.ChatSummary{}, err
	}
	applyOptionalUserFields(&chat.Peer, name, dob, phone, email, avatar)
	if lastID.Valid {
		chat.LastMessage = &model.Message{
			ID:         lastID.Int64,
			ChatID:     chat.ID,
			SenderID:   lastSender.Int64,
			Ciphertext: lastCipher.String,
			Nonce:      lastNonce.String,
			CreatedAt:  lastCreated.Time,
		}
	}
	return chat, nil
}

func applyOptionalUserFields(u *model.User, name sql.NullString, dob sql.NullTime, phone sql.NullString, email sql.NullString, avatar sql.NullString) {
	if name.Valid {
		u.Name = stringPtr(name.String)
	}
	if dob.Valid {
		u.DateOfBirth = timePtr(dob.Time)
	}
	if phone.Valid {
		u.Phone = stringPtr(phone.String)
	}
	if email.Valid {
		u.Email = stringPtr(email.String)
	}
	if avatar.Valid {
		u.Avatar = stringPtr(avatar.String)
	}
}

func stringPtr(value string) *string {
	v := value
	return &v
}

func timePtr(value time.Time) *time.Time {
	v := value
	return &v
}

func (r *Repository) ListMessages(ctx context.Context, chatID, beforeID int64, limit int) ([]model.Message, error) {
	var rows *sql.Rows
	var err error
	if beforeID > 0 {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, chat_id, sender_id, ciphertext, nonce, created_at
			   FROM messages
			  WHERE chat_id = $1 AND id < $2
			  ORDER BY id DESC
			  LIMIT $3`,
			chatID, beforeID, limit,
		)
	} else {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, chat_id, sender_id, ciphertext, nonce, created_at
			   FROM messages
			  WHERE chat_id = $1
			  ORDER BY id DESC
			  LIMIT $2`,
			chatID, limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []model.Message
	for rows.Next() {
		var msg model.Message
		if err := rows.Scan(&msg.ID, &msg.ChatID, &msg.SenderID, &msg.Ciphertext, &msg.Nonce, &msg.CreatedAt); err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}
	return messages, nil
}

func (r *Repository) StoreMessage(ctx context.Context, chatID, userID int64, ciphertext, nonce string) (model.Message, error) {
	var msg model.Message
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO messages (chat_id, sender_id, ciphertext, nonce)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, chat_id, sender_id, ciphertext, nonce, created_at`,
		chatID, userID, ciphertext, nonce,
	).Scan(&msg.ID, &msg.ChatID, &msg.SenderID, &msg.Ciphertext, &msg.Nonce, &msg.CreatedAt)
	return msg, err
}
