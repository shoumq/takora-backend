package model

import "time"

type User struct {
	ID          int64
	Username    string
	PublicKey   string
	Name        *string
	DateOfBirth *time.Time
	Phone       *string
	Email       *string
	Avatar      *string
}

type UserUpdate struct {
	Name           *string
	NameSet        bool
	DateOfBirth    *time.Time
	DateOfBirthSet bool
	Phone          *string
	PhoneSet       bool
	Email          *string
	EmailSet       bool
	Avatar         *string
	AvatarSet      bool
}

type Message struct {
	ID         int64
	ChatID     int64
	SenderID   int64
	Ciphertext string
	Nonce      string
	CreatedAt  time.Time
}

type ChatSummary struct {
	ID          int64
	Peer        User
	CreatedAt   time.Time
	LastMessage *Message
}

type PushToken struct {
	UserID      int64
	Token       string
	Environment string
	UpdatedAt   time.Time
}
