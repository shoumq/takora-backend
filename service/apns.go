package service

import (
	"context"
	"fmt"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
)

type APNSSender struct {
	topic string
	dev   *apns2.Client
	prod  *apns2.Client
}

func NewAPNSSender(teamID, keyID, keyPath, topic string) (*APNSSender, error) {
	if teamID == "" || keyID == "" || keyPath == "" || topic == "" {
		return nil, ErrPushNotConfigured
	}
	authKey, err := token.AuthKeyFromFile(keyPath)
	if err != nil {
		return nil, err
	}
	tok := &token.Token{
		AuthKey: authKey,
		KeyID:   keyID,
		TeamID:  teamID,
	}
	return &APNSSender{
		topic: topic,
		dev:   apns2.NewTokenClient(tok).Development(),
		prod:  apns2.NewTokenClient(tok).Production(),
	}, nil
}

func (s *APNSSender) Send(ctx context.Context, deviceToken, environment string, payloadData PushPayload) error {
	var client *apns2.Client
	switch environment {
	case PushEnvSandbox:
		client = s.dev
	case PushEnvProduction:
		client = s.prod
	default:
		return fmt.Errorf("unknown push environment: %s", environment)
	}

	notification := &apns2.Notification{
		DeviceToken: deviceToken,
		Topic:       s.topic,
		Payload:     buildPayload(payloadData),
	}
	res, err := client.PushWithContext(ctx, notification)
	if err != nil {
		return err
	}
	if !res.Sent() {
		return fmt.Errorf("apns failed: %s", res.Reason)
	}
	return nil
}

func buildPayload(data PushPayload) *payload.Payload {
	p := payload.NewPayload().AlertTitle(data.Title).AlertBody(data.Body).Sound("default")
	for key, value := range data.Data {
		p.Custom(key, value)
	}
	return p
}
