package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/StevanoZ/dv-shared/message"
	shrd_mock_svc "github.com/StevanoZ/dv-shared/service/mock"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	EMAIL_TOPIC  = message.EMAIL_TOPIC
	SERVICE_NAME = "dv-notification"
)

type TopicPubSub struct {
	*pubsub.Topic
}

func (t *TopicPubSub) Exists(ctx context.Context) (bool, error) {
	return true, nil
}

func initNotificationSvc(t *testing.T, ctrl *gomock.Controller) (
	NotificationSvc,
	*shrd_mock_svc.MockPubSubClient,
	*shrd_mock_svc.MockEmailSvc,
) {
	config := shrd_utils.LoadBaseConfig("../app", "test")
	pubSubClient := shrd_mock_svc.NewMockPubSubClient(ctrl)
	emailSvc := shrd_mock_svc.NewMockEmailSvc(ctrl)

	return NewNotificationSvc(config, pubSubClient, emailSvc), pubSubClient, emailSvc
}

func TestNotificationSvc(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	notificationSvc, pubSubClient, emailSvc := initNotificationSvc(t, ctrl)
	otpPayload := message.OtpPayload{
		Email:   shrd_utils.RandomEmail(),
		OtpCode: int(shrd_utils.RandomInt(0, 999999)),
	}

	t.Run("Success send email", func(t *testing.T) {
		pubSubClient.EXPECT().CreateTopicIfNotExists(ctx, EMAIL_TOPIC).
			Return(&pubsub.Topic{}, nil).Times(1)
		pubSubClient.EXPECT().PullMessages(ctx, SERVICE_NAME, gomock.AssignableToTypeOf(&pubsub.Topic{}), gomock.Any()).
			DoAndReturn(func(_ interface{}, _ interface{}, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data, _ := json.Marshal(otpPayload)
				msg := pubsub.Message{
					Data: data,
				}
				cb(ctx, &msg)
				return nil
			})

		emailSvc.EXPECT().SendVerifyOtp(ctx, otpPayload).Times(1)

		err := notificationSvc.ListenAndSendEmail(ctx)
		assert.NoError(t, err)
	})

	t.Run("Failed send email", func(t *testing.T) {
		pubSubClient.EXPECT().CreateTopicIfNotExists(ctx, EMAIL_TOPIC).Return(nil, errors.New("failed")).Times(1)
		pubSubClient.EXPECT().PullMessages(ctx, SERVICE_NAME,
			gomock.AssignableToTypeOf(&pubsub.Topic{}), gomock.Any()).Times(0)
		emailSvc.EXPECT().SendVerifyOtp(ctx, otpPayload).Times(0)

		err := notificationSvc.ListenAndSendEmail(ctx)
		assert.Error(t, err)
	})
}
