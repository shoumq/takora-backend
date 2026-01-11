package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"grape/dto"
	"grape/model"
	"grape/repo"
	"grape/service"
)

type Server struct {
	svc          *service.Service
	upgrader     websocket.Upgrader
	hubMu        sync.Mutex
	chatHubs     map[int64]map[*client]struct{}
	chatListMu   sync.Mutex
	chatListHubs map[int64]map[*chatListClient]struct{}
	onlineMu     sync.Mutex
	online       map[int64]int
	lastSeen     map[int64]time.Time
	baseCtx      context.Context
}

func NewServer(svc *service.Service, baseCtx context.Context) *Server {
	return &Server{
		svc: svc,
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
			return true
		}},
		chatHubs:     make(map[int64]map[*client]struct{}),
		chatListHubs: make(map[int64]map[*chatListClient]struct{}),
		online:       make(map[int64]int),
		lastSeen:     make(map[int64]time.Time),
		baseCtx:      baseCtx,
	}
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		PublicKey string `json:"public_key"`
		Phone     string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.Phone = strings.TrimSpace(req.Phone)
	var phoneNormalized string
	if req.Phone != "" {
		var err error
		phoneNormalized, err = normalizeRUPhone(req.Phone)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid phone")
			return
		}
	}
	if req.Username == "" || len(req.Password) < 8 || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "invalid input")
		return
	}
	user, err := s.svc.Register(r.Context(), req.Username, req.Password, req.PublicKey, phoneNormalized)
	if err != nil {
		if errors.Is(err, service.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "username taken")
			return
		}
		if errors.Is(err, repo.ErrPhoneTaken) {
			writeError(w, http.StatusConflict, "phone taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	writeJSON(w, http.StatusCreated, toUserDTO(user))
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	token, userID, expiresAt, err := s.svc.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "session failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"user_id":    userID,
		"expires_at": expiresAt,
	})
}

func (s *Server) HandlePhoneSendCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Phone = strings.TrimSpace(req.Phone)
	phoneNormalized, err := normalizeRUPhone(req.Phone)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid phone")
		return
	}
	if err := s.svc.SendPhoneCode(r.Context(), phoneNormalized); err != nil {
		if errors.Is(err, repo.ErrPhoneTaken) {
			writeError(w, http.StatusConflict, "phone taken")
			return
		}
		if errors.Is(err, service.ErrSMSNotConfigured) {
			writeError(w, http.StatusServiceUnavailable, "sms not configured")
			return
		}
		writeError(w, http.StatusInternalServerError, "sms failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) HandlePhoneVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Phone     string `json:"phone"`
		Code      string `json:"code"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Phone = strings.TrimSpace(req.Phone)
	req.Code = strings.TrimSpace(req.Code)
	req.Username = strings.TrimSpace(req.Username)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.Code == "" || req.Username == "" || len(req.Password) < 8 || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "invalid input")
		return
	}
	phoneNormalized, err := normalizeRUPhone(req.Phone)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid phone")
		return
	}
	user, err := s.svc.RegisterByPhoneCode(r.Context(), phoneNormalized, req.Code, req.Username, req.Password, req.PublicKey)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCode) || errors.Is(err, service.ErrCodeExpired) || errors.Is(err, service.ErrCodeNotFound) {
			writeError(w, http.StatusBadRequest, "invalid code")
			return
		}
		if errors.Is(err, service.ErrUsernameTaken) {
			writeError(w, http.StatusConflict, "username taken")
			return
		}
		if errors.Is(err, repo.ErrPhoneTaken) {
			writeError(w, http.StatusConflict, "phone taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	writeJSON(w, http.StatusCreated, toUserDTO(user))
}

func (s *Server) HandleLoginByPhone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Phone = strings.TrimSpace(req.Phone)
	phoneNormalized, err := normalizeRUPhone(req.Phone)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid phone")
		return
	}
	token, userID, expiresAt, err := s.svc.LoginByPhone(r.Context(), phoneNormalized, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "session failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"user_id":    userID,
		"expires_at": expiresAt,
	})
}

func (s *Server) HandleMe(w http.ResponseWriter, r *http.Request, userID int64) {
	switch r.Method {
	case http.MethodGet:
		user, err := s.svc.GetUser(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeJSON(w, http.StatusOK, toUserDTO(user))
	case http.MethodPut, http.MethodPatch:
		update, err := parseUserUpdate(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !hasUserUpdate(update) {
			writeError(w, http.StatusBadRequest, "no fields to update")
			return
		}
		user, err := s.svc.UpdateUser(r.Context(), userID, update)
		if err != nil {
			if errors.Is(err, repo.ErrPhoneTaken) {
				writeError(w, http.StatusConflict, "phone taken")
				return
			}
			writeError(w, http.StatusInternalServerError, "update failed")
			return
		}
		writeJSON(w, http.StatusOK, toUserDTO(user))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) HandleUserByID(w http.ResponseWriter, r *http.Request, _ int64) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	idStr = strings.TrimSpace(idStr)
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "bad user id")
		return
	}
	targetID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	user, err := s.svc.GetUser(r.Context(), targetID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserDTO(user))
}

func (s *Server) HandleUserSearch(w http.ResponseWriter, r *http.Request, userID int64) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("username"))
	if query == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}
	limit, err := parseLimit(r, 20, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid limit")
		return
	}
	users, err := s.svc.SearchUsers(r.Context(), query, limit, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "search failed")
		return
	}
	resp := make([]dto.UserResponse, 0, len(users))
	for _, u := range users {
		resp = append(resp, toUserDTO(u))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) HandlePushRegister(w http.ResponseWriter, r *http.Request, userID int64) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Token       string `json:"token"`
		Environment string `json:"environment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	req.Environment = strings.TrimSpace(req.Environment)
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}
	switch req.Environment {
	case service.PushEnvSandbox, service.PushEnvProduction:
	default:
		writeError(w, http.StatusBadRequest, "invalid environment")
		return
	}
	if err := s.svc.RegisterPushToken(r.Context(), userID, req.Token, req.Environment); err != nil {
		writeError(w, http.StatusInternalServerError, "push register failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) HandleUsersOnline(w http.ResponseWriter, r *http.Request, userID int64) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	idsParam := strings.TrimSpace(r.URL.Query().Get("ids"))
	if idsParam == "" {
		idsParam = strings.TrimSpace(r.URL.Query().Get("id"))
	}
	if idsParam == "" {
		writeError(w, http.StatusBadRequest, "ids required")
		return
	}
	rawIDs := strings.Split(idsParam, ",")
	if len(rawIDs) > 200 {
		writeError(w, http.StatusBadRequest, "too many ids")
		return
	}
	ids := make([]int64, 0, len(rawIDs))
	for _, raw := range rawIDs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusBadRequest, "invalid id")
			return
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "ids required")
		return
	}
	log.Printf("users_online requester=%d ids=%v", userID, ids)
	resp := make([]dto.OnlineStatus, 0, len(ids))
	for _, id := range ids {
		online, lastSeen := s.getOnlineStatus(id)
		resp = append(resp, dto.OnlineStatus{
			UserID:   id,
			Online:   online,
			LastSeen: lastSeen,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) HandleRandomUsers(w http.ResponseWriter, r *http.Request, userID int64) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit, err := parseLimit(r, 20, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid limit")
		return
	}
	users, err := s.svc.RandomUsers(r.Context(), limit, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	resp := make([]dto.UserResponse, 0, len(users))
	for _, u := range users {
		resp = append(resp, toUserDTO(u))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) HandleChats(w http.ResponseWriter, r *http.Request, userID int64) {
	switch r.Method {
	case http.MethodGet:
		chats, err := s.svc.ListChats(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list failed")
			return
		}
		resp := make([]dto.ChatResponse, 0, len(chats))
		for _, chat := range chats {
			resp = append(resp, toChatDTO(chat))
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req struct {
			PeerUserID int64 `json:"peer_user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if req.PeerUserID == 0 || req.PeerUserID == userID {
			writeError(w, http.StatusBadRequest, "invalid peer")
			return
		}
		if _, err := s.svc.GetUser(r.Context(), req.PeerUserID); err != nil {
			writeError(w, http.StatusNotFound, "peer not found")
			return
		}
		chatID, err := s.svc.FindOrCreateChat(r.Context(), userID, req.PeerUserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "chat failed")
			return
		}
		s.notifyChatUpdate(chatID)
		writeJSON(w, http.StatusCreated, map[string]interface{}{"id": chatID})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) HandleChatSubroutes(w http.ResponseWriter, r *http.Request, userID int64) {
	path := strings.TrimPrefix(r.URL.Path, "/api/chats/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	chatID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid chat id")
		return
	}
	member, err := s.svc.UserInChat(r.Context(), userID, chatID)
	if err != nil || !member {
		writeError(w, http.StatusForbidden, "not a member")
		return
	}
	switch parts[1] {
	case "messages":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleMessages(w, r, chatID)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request, chatID int64) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	var beforeID int64
	if v := r.URL.Query().Get("before_id"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			beforeID = parsed
		}
	}
	messages, err := s.svc.ListMessages(r.Context(), chatID, beforeID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "messages failed")
		return
	}
	resp := make([]dto.MessageDTO, 0, len(messages))
	for _, msg := range messages {
		resp = append(resp, toMessageDTO(msg))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) RequireAuth(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := s.authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r, userID)
	}
}

func (s *Server) authenticate(r *http.Request) (int64, error) {
	token := extractToken(r)
	if token == "" {
		return 0, errors.New("missing token")
	}
	return s.svc.Authenticate(r.Context(), token)
}

func (s *Server) markOnline(userID int64) {
	now := time.Now()
	s.onlineMu.Lock()
	defer s.onlineMu.Unlock()
	s.online[userID]++
	s.lastSeen[userID] = now
}

func (s *Server) markOffline(userID int64) {
	s.onlineMu.Lock()
	defer s.onlineMu.Unlock()
	if s.online[userID] > 1 {
		s.online[userID]--
		return
	}
	delete(s.online, userID)
}

func (s *Server) getOnlineStatus(userID int64) (bool, *time.Time) {
	s.onlineMu.Lock()
	defer s.onlineMu.Unlock()
	online := s.online[userID] > 0
	if last, ok := s.lastSeen[userID]; ok {
		lt := last
		return online, &lt
	}
	return online, nil
}

func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return r.URL.Query().Get("token")
}

func parseUserUpdate(r *http.Request) (model.UserUpdate, error) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return model.UserUpdate{}, errors.New("invalid json")
	}
	var update model.UserUpdate
	var err error
	update.NameSet, update.Name, err = parseOptionalStringField(raw, "name")
	if err != nil {
		return update, errors.New("invalid name")
	}
	update.DateOfBirthSet, update.DateOfBirth, err = parseOptionalDateField(raw, "date_of_birth")
	if err != nil {
		return update, errors.New("invalid date_of_birth")
	}
	update.PhoneSet, update.Phone, err = parseOptionalStringField(raw, "phone")
	if err != nil {
		return update, errors.New("invalid phone")
	}
	if update.PhoneSet && update.Phone != nil {
		normalized, err := normalizeRUPhone(*update.Phone)
		if err != nil {
			return update, errors.New("invalid phone")
		}
		update.Phone = &normalized
	}
	update.EmailSet, update.Email, err = parseOptionalStringField(raw, "email")
	if err != nil {
		return update, errors.New("invalid email")
	}
	update.AvatarSet, update.Avatar, err = parseOptionalStringField(raw, "avatar")
	if err != nil {
		return update, errors.New("invalid avatar")
	}
	return update, nil
}

func parseOptionalStringField(raw map[string]json.RawMessage, key string) (bool, *string, error) {
	value, ok := raw[key]
	if !ok {
		return false, nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return true, nil, nil
	}
	var parsed string
	if err := json.Unmarshal(value, &parsed); err != nil {
		return true, nil, err
	}
	parsed = strings.TrimSpace(parsed)
	if parsed == "" {
		return true, nil, nil
	}
	return true, &parsed, nil
}

func parseOptionalDateField(raw map[string]json.RawMessage, key string) (bool, *time.Time, error) {
	set, parsed, err := parseOptionalStringField(raw, key)
	if err != nil || !set || parsed == nil {
		return set, nil, err
	}
	value, err := time.Parse("2006-01-02", *parsed)
	if err != nil {
		return set, nil, err
	}
	return set, &value, nil
}

func hasUserUpdate(update model.UserUpdate) bool {
	return update.NameSet || update.DateOfBirthSet || update.PhoneSet || update.EmailSet || update.AvatarSet
}

func toUserDTO(user model.User) dto.UserResponse {
	resp := dto.UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		PublicKey: user.PublicKey,
		Name:      user.Name,
		Phone:     user.Phone,
		Email:     user.Email,
		Avatar:    user.Avatar,
	}
	if user.DateOfBirth != nil {
		formatted := user.DateOfBirth.Format("2006-01-02")
		resp.DateOfBirth = &formatted
	}
	return resp
}

func toMessageDTO(msg model.Message) dto.MessageDTO {
	return dto.MessageDTO{
		ID:         msg.ID,
		ChatID:     msg.ChatID,
		SenderID:   msg.SenderID,
		Ciphertext: msg.Ciphertext,
		Nonce:      msg.Nonce,
		CreatedAt:  msg.CreatedAt,
	}
}

func toChatDTO(chat model.ChatSummary) dto.ChatResponse {
	resp := dto.ChatResponse{
		ID:        chat.ID,
		Peer:      toUserDTO(chat.Peer),
		CreatedAt: chat.CreatedAt,
	}
	if chat.LastMessage != nil {
		msg := toMessageDTO(*chat.LastMessage)
		resp.LastMessage = &msg
	}
	return resp
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func parseLimit(r *http.Request, defaultLimit, maxLimit int) (int, error) {
	limitStr := strings.TrimSpace(r.URL.Query().Get("limit"))
	if limitStr == "" {
		return defaultLimit, nil
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		return 0, errors.New("invalid limit")
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return limit, nil
}
