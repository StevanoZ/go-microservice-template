package app

import (
	"os"
	"syscall"
	"testing"
	"time"

	shrd_middleware "github.com/StevanoZ/dv-shared/middleware"
	shrd_token "github.com/StevanoZ/dv-shared/token"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/StevanoZ/dv-user/handler"
	mock_svc "github.com/StevanoZ/dv-user/service/mock"
	"github.com/go-chi/chi/v5"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func initServer(t *testing.T, ctrl *gomock.Controller) Server {
	r := chi.NewRouter()
	config := shrd_utils.LoadBaseConfig(".", "test")
	userSvc := mock_svc.NewMockUserSvc(ctrl)
	tokenMaker, err := shrd_token.NewPasetoMaker(config)
	assert.NoError(t, err)
	authMiddleware := shrd_middleware.NewAuthMiddleware(tokenMaker)
	userHandler := handler.NewUserHandler(userSvc, authMiddleware)
	server := NewServer(r, config, userHandler)

	return server
}

func TestNewServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	server := initServer(t, ctrl)

	assert.NotNil(t, server)
	assert.IsType(t, &ServerImpl{}, server)
}

func TestStartServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	server := initServer(t, ctrl)

	// START SERVER ON BACKGROUND
	go server.Start()

	time.Sleep(500 * time.Millisecond)
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(syscall.SIGINT)
}
