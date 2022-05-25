package service

import (
	"context"
	"encoding/json"
	"fmt"

	"cloud.google.com/go/pubsub"
	"github.com/StevanoZ/dv-shared/message"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
)

type NotificationSvc interface {
	ListenAndSendEmail(ctx context.Context) error
}

type NotificationSvcImpl struct {
	config       *shrd_utils.BaseConfig
	emailSvc     shrd_service.EmailSvc
	pubSubClient shrd_service.PubSubClient
}

func NewNotificationSvc(
	config *shrd_utils.BaseConfig,
	pubSubClient shrd_service.PubSubClient,
	emailSvc shrd_service.EmailSvc,
) NotificationSvc {
	return &NotificationSvcImpl{
		config:       config,
		pubSubClient: pubSubClient,
		emailSvc:     emailSvc,
	}
}

func (s *NotificationSvcImpl) ListenAndSendEmail(ctx context.Context) error {
	topic, err := s.pubSubClient.CreateTopicIfNotExists(ctx, message.EMAIL_TOPIC)
	if err != nil {
		return err
	}

	fmt.Println("started listening topic with ID: ", topic.ID())
	return s.pubSubClient.PullMessages(ctx, s.config.ServiceName, topic, func(ctx context.Context, msg *pubsub.Message) {
		var otpPayload message.OtpPayload

		err := json.Unmarshal(msg.Data, &otpPayload)
		fmt.Println("unmarshall message data")
		shrd_utils.LogIfError(err)

		fmt.Println("send otp code to email: ", otpPayload.Email)
		err = s.emailSvc.SendVerifyOtp(ctx, message.OtpPayload{
			Email:   otpPayload.Email,
			OtpCode: otpPayload.OtpCode,
		})

		shrd_utils.LogIfError(err)
	})
}
