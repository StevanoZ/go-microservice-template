package app

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/StevanoZ/dv-notification/handler"
	mock_svc "github.com/StevanoZ/dv-notification/service/mock"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/go-chi/chi"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func initServer(ctrl *gomock.Controller) (Server, *mock_svc.MockNotificationSvc) {
	r := chi.NewRouter()
	config := shrd_utils.LoadBaseConfig(".", "test")
	notificationSvc := mock_svc.NewMockNotificationSvc(ctrl)
	userHandler := handler.NewNotificationHandler(notificationSvc)
	server := NewServer(r, config, userHandler)

	return server, notificationSvc
}

func TestNewServer(t *testing.T) {
	ctr := gomock.NewController(t)
	server, _ := initServer(ctr)

	assert.NotNil(t, server)
	assert.IsType(t, &ServerImpl{}, server)
}

func TestStartServer(t *testing.T) {
	ctr := gomock.NewController(t)
	server, _ := initServer(ctr)

	go server.Start()

	time.Sleep(500 * time.Millisecond)
	p, _ := os.FindProcess(os.Getpid())
	err := p.Signal(syscall.SIGINT)
	assert.NoError(t, err)
}

func TestListenForEvent(t *testing.T) {
	ctx := context.Background()
	ctr := gomock.NewController(t)
	server, notificationSvc := initServer(ctr)

	ctxCancel, cancel := context.WithCancel(ctx)
	notificationSvc.EXPECT().ListenForEmailTopic(ctxCancel).Times(1)
	notificationSvc.EXPECT().ListenForUserTopic(ctxCancel).Times(1)
	notificationSvc.EXPECT().ListenForUserImageTopic(ctxCancel).Times(1)
	server.ListenEvent(ctxCancel)
	time.Sleep(700 * time.Millisecond)
	cancel()
}
