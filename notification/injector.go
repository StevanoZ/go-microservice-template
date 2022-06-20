//go:build wireinject
// +build wireinject

package main

import (
	"database/sql"

	"cloud.google.com/go/pubsub"
	"github.com/StevanoZ/dv-notification/app"
	querier "github.com/StevanoZ/dv-notification/db/repository"
	"github.com/StevanoZ/dv-notification/handler"
	"github.com/StevanoZ/dv-notification/service"
	pubsub_client "github.com/StevanoZ/dv-shared/pubsub"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/go-chi/chi"
	"github.com/google/wire"
	"github.com/sendgrid/sendgrid-go"
)

// var msgBrokerSet = wire.NewSet(
// 	wire.Bind(new(kafka_client.KafkaProducer), new(*kafka.Producer)),
// 	wire.Bind(new(kafka_client.KafkaConsumer), new(*kafka.Consumer)),
// 	kafka_client.NewKafkaProducer,
// 	kafka_client.NewKafkaConsumer,
// 	kafka_client.NewKafkaClient,
// )

var pubSubSet = wire.NewSet(
	wire.Bind(new(pubsub_client.GooglePubSub), new(*pubsub.Client)),
	pubsub_client.NewGooglePubSub,
	pubsub_client.NewPubSubClient,
)

var emailSet = wire.NewSet(
	wire.Bind(new(shrd_service.EmailClient), new(*sendgrid.Client)),
	shrd_service.NewSgClient,
	shrd_service.NewEmailSvc,
)

var notificationSet = wire.NewSet(
	querier.NewRepository,
	service.NewNotificationSvc,
	handler.NewNotificationHandler,
)

func InitializedApp(
	r *chi.Mux, 
	DB *sql.DB,
	config *shrd_utils.BaseConfig,
	) (
	app.Server,
	error,
) {
	wire.Build(
		pubSubSet,
		emailSet,
		notificationSet,
		app.NewServer,
	)

	return nil, nil
}
