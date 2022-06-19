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
	"github.com/go-chi/chi"
	chitrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/go-chi/chi"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
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
	// Start the tracer
	tracer.Start(
		tracer.WithService(s.config.ServiceName),
		tracer.WithEnv(s.config.Environment),
		tracer.WithAgentAddr(s.config.DATA_DOG_AGENT_HOST),
	)
	defer tracer.Stop()

	s.route.Use(chitrace.Middleware(chitrace.WithServiceName(s.config.ServiceName)))
	shrd_middleware.SetupMiddleware(s.route, s.config)
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
	go func() {
		err := s.notificationHandler.ListenForUserTopic(ctx)
		shrd_utils.LogIfError(err)
	}()
	go func() {
		err := s.notificationHandler.ListenForEmailTopic(ctx)
		shrd_utils.LogIfError(err)
	}()
	go func() {
		err := s.notificationHandler.ListenForUserImageTopic(ctx)
		shrd_utils.LogIfError(err)
	}()
}
