package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	mock_svc "github.com/StevanoZ/dv-notification/service/mock"
	shrd_helper "github.com/StevanoZ/dv-shared/helper"
	shrd_middleware "github.com/StevanoZ/dv-shared/middleware"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/go-chi/chi/v5"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func initNotificationHandler(notificationSvc *mock_svc.MockNotificationSvc) NotificationHandler {
	return NewNotificationHandler(notificationSvc)
}

func TestNotificationHandler(t *testing.T) {
	notificationHandlersTestCase := []shrd_helper.TestCaseHandler{
		{
			Name:   "Ping (status code 200)",
			ReqUrl: "/api/notification/ping",
			Method: http.MethodGet,
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				var resp shrd_utils.Response

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, "PONG!", resp.Data)
			},
		},
		{
			Name:   "Not found (status code 404)",
			ReqUrl: "/api/notification/test/xxx",
			Method: http.MethodGet,
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				var resp shrd_utils.Response

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse404(t, resp)
				assert.Nil(t, resp.Data)
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	r := chi.NewRouter()
	r.Use(shrd_middleware.Recovery)
	notificationSvc := mock_svc.NewMockNotificationSvc(ctrl)
	notificationHandler := initNotificationHandler(notificationSvc)
	notificationHandler.SetupUserRoutes(r)

	for i := range notificationHandlersTestCase {
		tc := notificationHandlersTestCase[i]
		t.Run(tc.Name, func(t *testing.T) {
			shrd_helper.SetupRequest(t, r, tc, notificationSvc)
		})
	}

}

func TestListeningTopic(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	notificationSvc := mock_svc.NewMockNotificationSvc(ctrl)
	notificationHandler := initNotificationHandler(notificationSvc)

	t.Run("Listen for email topic", func(t *testing.T) {
		ctxCancel, cancel := context.WithCancel(ctx)
		notificationSvc.EXPECT().ListenForEmailTopic(ctxCancel).Times(1)
		err := notificationHandler.ListenForEmailTopic(ctxCancel)
		assert.NoError(t, err)
		cancel()
	})

	t.Run("Listen for user topic", func(t *testing.T) {
		ctxCancel, cancel := context.WithCancel(ctx)
		notificationSvc.EXPECT().ListenForUserTopic(ctxCancel).Times(1)
		err := notificationHandler.ListenForUserTopic(ctxCancel)
		assert.NoError(t, err)
		cancel()
	})

	t.Run("Listen for user image topic", func(t *testing.T) {
		ctxCancel, cancel := context.WithCancel(ctx)
		notificationSvc.EXPECT().ListenForUserImageTopic(ctxCancel).Times(1)
		err := notificationHandler.ListenForUserImageTopic(ctxCancel)
		assert.NoError(t, err)
		cancel()
	})
}
