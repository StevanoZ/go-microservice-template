package app

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	shrd_middleware "github.com/StevanoZ/dv-shared/middleware"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/StevanoZ/dv-user/handler"
	"github.com/go-chi/chi/v5"
)

type Server interface {
	Start()
}

type ServerImpl struct {
	route       *chi.Mux
	config      *shrd_utils.BaseConfig
	userHandler handler.UserHandler
}

func NewServer(
	route *chi.Mux,
	config *shrd_utils.BaseConfig,
	userHandler handler.UserHandler,
) Server {
	return &ServerImpl{
		route:       route,
		config:      config,
		userHandler: userHandler,
	}
}

func (s *ServerImpl) Start() {
	s.route.Use(shrd_middleware.Recovery)
	s.userHandler.SetupUserRoutes(s.route)

	fmt.Println("server started")

	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%s", s.config.ServerPort), s.route)
		shrd_utils.LogIfError(err)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
}
