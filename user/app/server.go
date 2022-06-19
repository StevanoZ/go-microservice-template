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
	"github.com/go-chi/chi"
	chitrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/go-chi/chi"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
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
	// Start the tracer
	tracer.Start(
		tracer.WithService(s.config.ServiceName),
		tracer.WithEnv(s.config.Environment),
		tracer.WithAgentAddr(s.config.DATA_DOG_AGENT_HOST),
	)
	defer tracer.Stop()

	s.route.Use(chitrace.Middleware(chitrace.WithServiceName(s.config.ServiceName)))
	shrd_middleware.SetupMiddleware(s.route, s.config)
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
