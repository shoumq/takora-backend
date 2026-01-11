package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/websocket"

	"grape/dto"
	"grape/model"
	"grape/service"
)

type client struct {
	conn   *websocket.Conn
	userID int64
	chatID int64
	send   chan []byte
}

type chatListClient struct {
	conn   *websocket.Conn
	userID int64
	send   chan []byte
}

func (s *Server) HandleWebsocket(w http.ResponseWriter, r *http.Request) {
	chatIDStr := r.URL.Query().Get("chat_id")
	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil || chatID == 0 {
		writeError(w, http.StatusBadRequest, "invalid chat id")
		return
	}
	userID, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	member, err := s.svc.UserInChat(r.Context(), userID, chatID)
	if err != nil || !member {
		writeError(w, http.StatusForbidden, "not a member")
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &client{
		conn:   conn,
		userID: userID,
		chatID: chatID,
		send:   make(chan []byte, 16),
	}
	s.registerClient(c)
	log.Printf("ws connect user_id=%d chat_id=%d addr=%s", userID, chatID, r.RemoteAddr)
	s.markOnline(userID)
	defer s.markOffline(userID)
	go c.writeLoop()
	c.readLoop(s)
	log.Printf("ws disconnect user_id=%d chat_id=%d addr=%s", userID, chatID, r.RemoteAddr)
	s.unregisterClient(c)
}

func (s *Server) HandleChatListWebsocket(w http.ResponseWriter, r *http.Request) {
	userID, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &chatListClient{
		conn:   conn,
		userID: userID,
		send:   make(chan []byte, 16),
	}
	s.registerChatListClient(c)
	log.Printf("ws_chats connect user_id=%d addr=%s", userID, r.RemoteAddr)
	s.markOnline(userID)
	defer s.markOffline(userID)
	go c.writeLoop()
	c.readLoop()
	log.Printf("ws_chats disconnect user_id=%d addr=%s", userID, r.RemoteAddr)
	s.unregisterChatListClient(c)
}

func (c *client) readLoop(s *Server) {
	defer c.conn.Close()
	c.conn.SetReadLimit(64 * 1024)
	for {
		var inbound struct {
			Type       string `json:"type"`
			Ciphertext string `json:"ciphertext"`
			Nonce      string `json:"nonce"`
		}
		if err := c.conn.ReadJSON(&inbound); err != nil {
			return
		}
		if inbound.Type != "send" || inbound.Ciphertext == "" || inbound.Nonce == "" {
			continue
		}
		msg, err := s.svc.StoreMessage(s.baseCtx, c.chatID, c.userID, inbound.Ciphertext, inbound.Nonce)
		if err != nil {
			continue
		}
		out := struct {
			Type string `json:"type"`
			dto.MessageDTO
		}{
			Type:       "message",
			MessageDTO: toMessageDTO(msg),
		}
		payload, err := json.Marshal(out)
		if err != nil {
			continue
		}
		s.broadcast(c.chatID, payload)
		s.notifyChatUpdate(c.chatID)
		go s.sendPushForMessage(msg)
	}
}

func (c *client) writeLoop() {
	defer c.conn.Close()
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}

func (c *chatListClient) readLoop() {
	defer c.conn.Close()
	c.conn.SetReadLimit(64 * 1024)
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (c *chatListClient) writeLoop() {
	defer c.conn.Close()
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}

func (s *Server) registerClient(c *client) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	hub := s.chatHubs[c.chatID]
	if hub == nil {
		hub = make(map[*client]struct{})
		s.chatHubs[c.chatID] = hub
	}
	hub[c] = struct{}{}
}

func (s *Server) unregisterClient(c *client) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	if hub, ok := s.chatHubs[c.chatID]; ok {
		delete(hub, c)
		if len(hub) == 0 {
			delete(s.chatHubs, c.chatID)
		}
	}
	close(c.send)
}

func (s *Server) broadcast(chatID int64, msg []byte) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	for c := range s.chatHubs[chatID] {
		select {
		case c.send <- msg:
		default:
			close(c.send)
			delete(s.chatHubs[chatID], c)
		}
	}
}

func (s *Server) registerChatListClient(c *chatListClient) {
	s.chatListMu.Lock()
	defer s.chatListMu.Unlock()
	hub := s.chatListHubs[c.userID]
	if hub == nil {
		hub = make(map[*chatListClient]struct{})
		s.chatListHubs[c.userID] = hub
	}
	hub[c] = struct{}{}
}

func (s *Server) unregisterChatListClient(c *chatListClient) {
	s.chatListMu.Lock()
	defer s.chatListMu.Unlock()
	if hub, ok := s.chatListHubs[c.userID]; ok {
		delete(hub, c)
		if len(hub) == 0 {
			delete(s.chatListHubs, c.userID)
		}
	}
	close(c.send)
}

func (s *Server) broadcastChatList(userID int64, msg []byte) {
	s.chatListMu.Lock()
	defer s.chatListMu.Unlock()
	for c := range s.chatListHubs[userID] {
		select {
		case c.send <- msg:
		default:
			close(c.send)
			delete(s.chatListHubs[userID], c)
		}
	}
}

func (s *Server) notifyChatUpdate(chatID int64) {
	memberIDs, err := s.svc.ListChatMemberIDs(s.baseCtx, chatID)
	if err != nil {
		return
	}
	for _, memberID := range memberIDs {
		chat, err := s.svc.GetChatSummary(s.baseCtx, memberID, chatID)
		if err != nil {
			continue
		}
		out := struct {
			Type string `json:"type"`
			dto.ChatResponse
		}{
			Type:         "chat_update",
			ChatResponse: toChatDTO(chat),
		}
		payload, err := json.Marshal(out)
		if err != nil {
			continue
		}
		s.broadcastChatList(memberID, payload)
	}
}

func (s *Server) sendPushForMessage(msg model.Message) {
	if !s.svc.PushEnabled() {
		return
	}
	memberIDs, err := s.svc.ListChatMemberIDs(s.baseCtx, msg.ChatID)
	if err != nil {
		return
	}
	targetIDs := make([]int64, 0, len(memberIDs))
	for _, memberID := range memberIDs {
		if memberID == msg.SenderID {
			continue
		}
		online, _ := s.getOnlineStatus(memberID)
		if online {
			continue
		}
		targetIDs = append(targetIDs, memberID)
	}
	if len(targetIDs) == 0 {
		return
	}
	tokens, err := s.svc.ListPushTokens(s.baseCtx, targetIDs)
	if err != nil {
		return
	}
	payload := service.PushPayload{
		Title: "New message",
		Body:  "You have a new message",
		Data: map[string]interface{}{
			"chat_id":    msg.ChatID,
			"message_id": msg.ID,
			"sender_id":  msg.SenderID,
		},
	}
	for _, token := range tokens {
		_ = s.svc.SendPush(s.baseCtx, token, payload)
	}
}
