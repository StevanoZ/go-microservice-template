//go:build wireinject
// +build wireinject

package main

import (
	"database/sql"

	kafka_client "github.com/StevanoZ/dv-shared/kafka"
	shrd_middleware "github.com/StevanoZ/dv-shared/middleware"
	s3_client "github.com/StevanoZ/dv-shared/s3"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_token "github.com/StevanoZ/dv-shared/token"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/StevanoZ/dv-user/app"
	user_db "github.com/StevanoZ/dv-user/db/user/sqlc"
	"github.com/StevanoZ/dv-user/handler"
	"github.com/StevanoZ/dv-user/service"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/go-chi/chi/v5"
	"github.com/go-redis/redis/v8"
	"github.com/google/wire"
)

var fileset = wire.NewSet(
	wire.Bind(new(s3_client.S3Client), new(*s3.Client)),
	wire.Bind(new(s3_client.S3PreSign), new(*s3.PresignClient)),
	s3_client.Init,
	s3_client.PreSignClient,
	s3_client.NewS3Client,
)

var userSet = wire.NewSet(
	user_db.NewUserRepo,
	service.NewUserSvc,
	shrd_middleware.NewAuthMiddleware,
	handler.NewUserHandler,
)

var tokenSet = wire.NewSet(
	shrd_token.NewPasetoMaker,
)

var messageBrokerSet = wire.NewSet(
	wire.Bind(new(kafka_client.KafkaProducer), new(*kafka.Producer)),
	wire.Bind(new(kafka_client.KafkaConsumer), new(*kafka.Consumer)),
	kafka_client.NewKafkaProducer,
	kafka_client.NewKafkaConsumer,
	kafka_client.NewKafkaClient,
)

var cacheSet = wire.NewSet(
	wire.Bind(new(shrd_service.RedisClient), new(*redis.Client)),
	shrd_service.NewRedisClient,
	shrd_service.NewCacheSvc,
)

func InitializedApp(
	route *chi.Mux,
	DB *sql.DB,
	config *shrd_utils.BaseConfig,
) (app.Server, error) {
	wire.Build(
		fileset,
		messageBrokerSet,
		tokenSet,
		userSet,
		cacheSet,
		app.NewServer,
	)

	return nil, nil
}
