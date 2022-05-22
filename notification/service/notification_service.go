package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/StevanoZ/dv-shared/message"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/confluentinc/confluent-kafka-go/kafka"
)

type NotificationSvc interface {
	ListenAndSendEmail(ctx context.Context, isEndlessly bool)
}

type NotificationSvcImpl struct {
	messageBrokerClient shrd_service.MessageBrokerClient
	emailSvc            shrd_service.EmailSvc
}

func NewNotificationSvc(
	msgBrokerClient shrd_service.MessageBrokerClient,
	emailSvc shrd_service.EmailSvc,
) NotificationSvc {
	return &NotificationSvcImpl{
		messageBrokerClient: msgBrokerClient,
		emailSvc:            emailSvc,
	}
}

func (s *NotificationSvcImpl) ListenAndSendEmail(ctx context.Context, isEndlessly bool) {
	err := s.messageBrokerClient.ListenEvent(message.EMAIL_TOPIC, func(payload any, errMsg error, close func()) {
		if !isEndlessly {
			close()
		}

		if errMsg != nil {
			fmt.Println("failed when consuming message with topic: ", message.EMAIL_TOPIC)
			return
		}

		// TYPE MAYBE DIFFERENT DEPENDING ON THE BROKER
		msg, _ := payload.(*kafka.Message)

		if string(msg.Key) == message.SEND_OTP_KEY {
			var otpPayload message.OtpPayload
			err := json.Unmarshal(msg.Value, &otpPayload)

			if err != nil {
				fmt.Println("failed when parsing message: ", err)
			} else {
				fmt.Println("send otp code to email: ", otpPayload.Email)
				err := s.emailSvc.SendVerifyOtp(ctx, message.OtpPayload{
					Email:   otpPayload.Email,
					OtpCode: otpPayload.OtpCode,
				})
				shrd_utils.LogIfError(err)
			}
		}
	})
	shrd_utils.LogIfError(err)
}
