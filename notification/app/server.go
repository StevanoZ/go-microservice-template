package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/StevanoZ/dv-notification/handler"
	shrd_middleware "github.com/StevanoZ/dv-shared/middleware"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/go-chi/chi/v5"
)

type Server interface {
	Start()
	ListenEvent(ctx context.Context)
}

type ServerImpl struct {
	route               *chi.Mux
	config              *shrd_utils.BaseConfig
	notificationHandler handler.NotificationHandler
}

func NewServer(route *chi.Mux,
	config *shrd_utils.BaseConfig,
	notificationHandler handler.NotificationHandler,
) Server {
	return &ServerImpl{
		route:               route,
		config:              config,
		notificationHandler: notificationHandler,
	}
}

func (s *ServerImpl) Start() {
	s.route.Use(shrd_middleware.Recovery)
	s.notificationHandler.SetupUserRoutes(s.route)

	fmt.Println("server started")

	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%s", s.config.ServerPort), s.route)
		shrd_utils.LogIfError(err)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
}

func (s *ServerImpl) ListenEvent(ctx context.Context) {
	s.notificationHandler.ListenEvent(ctx, true)
}
