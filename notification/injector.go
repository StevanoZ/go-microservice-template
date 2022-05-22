//go:build wireinject
// +build wireinject

package main

import (
	"github.com/StevanoZ/dv-notification/app"
	"github.com/StevanoZ/dv-notification/handler"
	"github.com/StevanoZ/dv-notification/service"
	kafka_client "github.com/StevanoZ/dv-shared/kafka"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/go-chi/chi/v5"
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

var notificationSet = wire.NewSet(
	service.NewNotificationSvc,
	handler.NewNotificationHandler,
)

func InitializedApp(r *chi.Mux, config *shrd_utils.BaseConfig) (
	app.Server,
	error,
) {
	wire.Build(
		msgBrokerSet,
		emailSet,
		notificationSet,
		app.NewServer,
	)

	return nil, nil
}
