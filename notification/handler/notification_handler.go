package handler

import (
	"context"
	"net/http"

	"github.com/StevanoZ/dv-notification/service"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/go-chi/chi"
	"github.com/go-openapi/runtime/middleware"
)

type NotificationHandler interface {
	Ping(w http.ResponseWriter, r *http.Request)
	ListenForEmailTopic(ctx context.Context) error
	ListenForUserTopic(ctx context.Context) error
	ListenForUserImageTopic(ctx context.Context) error
	SetupUserRoutes(route *chi.Mux)
}

type NotificationHandlerImpl struct {
	notificationSvc service.NotificationSvc
}

func NewNotificationHandler(notificationSvc service.NotificationSvc) NotificationHandler {
	return &NotificationHandlerImpl{
		notificationSvc: notificationSvc,
	}
}

func (h *NotificationHandlerImpl) Ping(w http.ResponseWriter, r *http.Request) {
	shrd_utils.GenerateSuccessResp(w, "PONG!", 200)
}

func (h *NotificationHandlerImpl) SetupUserRoutes(route *chi.Mux) {
	shrd_utils.EnableCORS(route)
	route.Mount("/api/notification", route)

	opts := middleware.SwaggerUIOpts{SpecURL: "/swagger.json", Path: "/api/doc"}
	sh := middleware.SwaggerUI(opts, nil)
	route.Handle("/api/doc/*", sh)
	route.Handle("/swagger.json", http.FileServer(http.Dir("./docs")))

	route.Get("/ping", h.Ping)

	route.NotFound(func(w http.ResponseWriter, r *http.Request) {
		shrd_utils.GenerateErrorResp(w, nil, 404)
	})
}

func (h *NotificationHandlerImpl) ListenForEmailTopic(ctx context.Context) error {
	return h.notificationSvc.ListenForEmailTopic(ctx)
}

func (h *NotificationHandlerImpl) ListenForUserTopic(ctx context.Context) error {
	return h.notificationSvc.ListenForUserTopic(ctx)
}

func (h *NotificationHandlerImpl) ListenForUserImageTopic(ctx context.Context) error {
	return h.notificationSvc.ListenForUserImageTopic(ctx)
}
