package service

import (
	"context"
	"errors"

	"grape/model"
)

const (
	PushEnvSandbox    = "sandbox"
	PushEnvProduction = "production"
)

var ErrPushNotConfigured = errors.New("push not configured")

type PushPayload struct {
	Title string
	Body  string
	Data  map[string]interface{}
}

type PushSender interface {
	Send(ctx context.Context, deviceToken, environment string, payload PushPayload) error
}

func (s *Service) RegisterPushToken(ctx context.Context, userID int64, token, environment string) error {
	return s.repo.UpsertPushToken(ctx, userID, token, environment)
}

func (s *Service) ListPushTokens(ctx context.Context, userIDs []int64) ([]model.PushToken, error) {
	return s.repo.ListPushTokens(ctx, userIDs)
}

func (s *Service) SendPush(ctx context.Context, token model.PushToken, payload PushPayload) error {
	if s.pushSender == nil {
		return ErrPushNotConfigured
	}
	return s.pushSender.Send(ctx, token.Token, token.Environment, payload)
}

func (s *Service) PushEnabled() bool {
	return s.pushSender != nil
}
