package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	kafka_client "github.com/StevanoZ/dv-shared/kafka"
	mock_kafka "github.com/StevanoZ/dv-shared/kafka/mock"
	"github.com/StevanoZ/dv-shared/message"
	shrd_mock_svc "github.com/StevanoZ/dv-shared/service/mock"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

var EMAIL_TOPIC = message.EMAIL_TOPIC

func initNotificationSvc(t *testing.T, ctrl *gomock.Controller) (
	NotificationSvc,
	*mock_kafka.MockKafkaConsumer,
	*shrd_mock_svc.MockEmailSvc,
) {
	consumer := mock_kafka.NewMockKafkaConsumer(ctrl)
	producer := mock_kafka.NewMockKafkaProducer(ctrl)
	msgBrokerSvc := kafka_client.NewKafkaClient(producer, consumer)
	emailSvc := shrd_mock_svc.NewMockEmailSvc(ctrl)

	return NewNotificationSvc(msgBrokerSvc, emailSvc), consumer, emailSvc
}

func TestNotificationSvc(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	notificationSvc, consumer, emailSvc := initNotificationSvc(t, ctrl)
	otpPayload := message.OtpPayload{
		Email:   shrd_utils.RandomEmail(),
		OtpCode: int(shrd_utils.RandomInt(0, 999999)),
	}
	msg, err := json.Marshal(otpPayload)
	assert.NoError(t, err)

	kafkaMessage := kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic:     &EMAIL_TOPIC,
			Partition: kafka.PartitionAny,
		},
		Key:       []byte(message.SEND_OTP_KEY),
		Value:     msg,
		Timestamp: time.Now(),
	}

	t.Run("Success send email", func(t *testing.T) {
		consumer.EXPECT().Subscribe(message.EMAIL_TOPIC, nil).
			Return(nil).Times(1)
		consumer.EXPECT().Close().Times(1)
		consumer.EXPECT().ReadMessage(time.Duration(-1*time.Nanosecond)).Return(&kafkaMessage, nil).Times(1)

		emailSvc.EXPECT().SendVerifyOtp(ctx, otpPayload).Times(1)

		notificationSvc.ListenAndSendEmail(ctx, false)
	})

	t.Run("Failed send email (when parsing message)", func(t *testing.T) {
		kafkaMessage.Value = []byte("failed")
		consumer.EXPECT().Subscribe(message.EMAIL_TOPIC, nil).
			Return(nil).Times(1)
		consumer.EXPECT().Close().Times(1)
		consumer.EXPECT().ReadMessage(time.Duration(-1*time.Nanosecond)).
			Return(&kafkaMessage, nil).Times(1)

		emailSvc.EXPECT().SendVerifyOtp(ctx, otpPayload).Times(0)

		notificationSvc.ListenAndSendEmail(ctx, false)
	})

	t.Run("Failed send email (when consuming message)", func(t *testing.T) {
		kafkaMessage.Value = []byte("failed")
		consumer.EXPECT().Subscribe(message.EMAIL_TOPIC, nil).
			Return(nil).Times(1)
		consumer.EXPECT().Close().Times(1)
		consumer.EXPECT().ReadMessage(time.Duration(-1*time.Nanosecond)).
			Return(nil, errors.New("failed")).Times(1)

		emailSvc.EXPECT().SendVerifyOtp(ctx, otpPayload).Times(0)

		notificationSvc.ListenAndSendEmail(ctx, false)
	})

}
