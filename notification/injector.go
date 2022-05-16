//go:build wireinject
// +build wireinject

package main

import (
	"github.com/StevanoZ/dv-notification/service"
	kafka_client "github.com/StevanoZ/dv-shared/kafka"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/google/wire"
	"github.com/sendgrid/sendgrid-go"
)

var msgBrokerSet = wire.NewSet(
	wire.Bind(new(kafka_client.KafkaProducer), new(*kafka.Producer)),
	wire.Bind(new(kafka_client.KafkaConsumer), new(*kafka.Consumer)),
	kafka_client.NewKafkaProducer,
	kafka_client.NewKafkaConsumer,
	kafka_client.NewKafkaClient,
)

var emailSet = wire.NewSet(
	wire.Bind(new(shrd_service.EmailClient), new(*sendgrid.Client)),
	shrd_service.NewSgClient,
	shrd_service.NewEmailSvc,
)

func InitializedApp(config *shrd_utils.BaseConfig) (service.NotificationSvc, error) {
	wire.Build(msgBrokerSet, emailSet, service.NewNotificationSvc)

	return nil, nil
}
