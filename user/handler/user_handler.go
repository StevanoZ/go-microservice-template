package handler

import (
	"context"
	"net/http"

	shrd_middleware "github.com/StevanoZ/dv-shared/middleware"
	shrd_token "github.com/StevanoZ/dv-shared/token"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/StevanoZ/dv-user/dtos/request"
	"github.com/StevanoZ/dv-user/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-openapi/runtime/middleware"
)

type UserHandler interface {
	SignUp(w http.ResponseWriter, r *http.Request)
	LogIn(w http.ResponseWriter, r *http.Request)
	UpdateUser(w http.ResponseWriter, r *http.Request)
	VerifyOtp(w http.ResponseWriter, r *http.Request)
	ResendOtp(w http.ResponseWriter, r *http.Request)
	GetUsers(w http.ResponseWriter, r *http.Request)
	GetUser(w http.ResponseWriter, r *http.Request)
	GetUserImages(w http.ResponseWriter, r *http.Request)
	UploadImages(w http.ResponseWriter, r *http.Request)
	SetMainImage(w http.ResponseWriter, r *http.Request)
	DeleteImage(w http.ResponseWriter, r *http.Request)
	SetupUserRoutes(route *chi.Mux)
}

type UserHandlerImpl struct {
	userSvc        service.UserSvc
	authMiddleware shrd_middleware.AuthMiddleware
}

func NewUserHandler(
	userSvc service.UserSvc,
	authMiddleware shrd_middleware.AuthMiddleware,
) UserHandler {
	return &UserHandlerImpl{
		userSvc:        userSvc,
		authMiddleware: authMiddleware,
	}
}

func (h *UserHandlerImpl) SetupUserRoutes(
	route *chi.Mux,
) {
	shrd_utils.EnableCORS(route)

	route.Mount("/api/user", route)

	opts := middleware.SwaggerUIOpts{SpecURL: "/api/user/swagger.json", Path: "/doc"}
	sh := middleware.SwaggerUI(opts, nil)
	route.Handle("/doc/*", sh)
	route.Handle("/swagger.json", http.FileServer(http.Dir("./docs")))

	route.Post("/sign-up", h.SignUp)
	route.Post("/log-in", h.LogIn)
	route.Post("/verify-otp", h.VerifyOtp)
	route.Post("/resend-otp", h.ResendOtp)
	route.Get("/list", h.GetUsers)
	route.Get("/{id}", h.authMiddleware.CheckIsAuthenticated(h.GetUser))
	route.Put("/{id}", h.authMiddleware.CheckIsAuthenticated(h.UpdateUser))
	route.Post("/{id}/upload", h.authMiddleware.CheckIsAuthenticated(h.UploadImages))
	route.Get("/{id}/image", h.authMiddleware.CheckIsAuthenticated(h.GetUserImages))
	route.Put("/{userId}/image/{imageId}", h.authMiddleware.CheckIsAuthenticated(h.SetMainImage))
	route.Delete("/{userId}/image/{imageId}", h.authMiddleware.CheckIsAuthenticated(h.DeleteImage))

	route.NotFound(func(w http.ResponseWriter, r *http.Request) {
		shrd_utils.GenerateErrorResp(w, nil, 404)
	})
}

func (h *UserHandlerImpl) SignUp(w http.ResponseWriter, r *http.Request) {
	var input request.SignUpReq
	shrd_utils.ValidateBodyPayload(r.Body, &input)

	resp := h.userSvc.SignUp(context.Background(), input)
	shrd_utils.GenerateSuccessResp(w, resp, 201)
}

func (h *UserHandlerImpl) LogIn(w http.ResponseWriter, r *http.Request) {
	var input request.LogInReq
	shrd_utils.ValidateBodyPayload(r.Body, &input)

	resp := h.userSvc.LogIn(context.Background(), input)
	shrd_utils.GenerateSuccessResp(w, resp, 200)
}

func (h *UserHandlerImpl) UpdateUser(w http.ResponseWriter, r *http.Request) {
	var input request.UpdateUserReq
	userId := shrd_utils.ValidateUrlParamUUID(r, "id")

	shrd_utils.ValidateBodyPayload(r.Body, &input)
	shrd_token.CheckIsAuthorize(r, userId)

	resp := h.userSvc.UpdateUser(r.Context(), userId, input)
	shrd_utils.GenerateSuccessResp(w, resp, 200)
}

func (h *UserHandlerImpl) VerifyOtp(w http.ResponseWriter, r *http.Request) {
	var input request.VerifyOtpReq
	shrd_utils.ValidateBodyPayload(r.Body, &input)

	resp := h.userSvc.VerifyOtp(context.Background(), input)
	shrd_utils.GenerateSuccessResp(w, resp, 200)
}

func (h *UserHandlerImpl) ResendOtp(w http.ResponseWriter, r *http.Request) {
	var input request.ResendOtpReq
	shrd_utils.ValidateBodyPayload(r.Body, &input)

	h.userSvc.ResendOtp(context.Background(), input)
	shrd_utils.GenerateSuccessResp(w, nil, 200)
}

func (h *UserHandlerImpl) UploadImages(w http.ResponseWriter, r *http.Request) {
	userId := shrd_utils.ValidateUrlParamUUID(r, "id")
	err := r.ParseMultipartForm(5242880)

	if err != nil {
		shrd_utils.PanicIfError(shrd_utils.CustomErrorWithTrace(err, "failed when parsing form", 400))
	}

	shrd_token.CheckIsAuthorize(r, userId)

	files := r.MultipartForm.File["files"]

	resp := h.userSvc.UploadImages(r.Context(), files, userId)
	shrd_utils.GenerateSuccessResp(w, resp, 200)
}

func (h *UserHandlerImpl) SetMainImage(w http.ResponseWriter, r *http.Request) {
	userId := shrd_utils.ValidateUrlParamUUID(r, "userId")
	imageId := shrd_utils.ValidateUrlParamUUID(r, "imageId")

	shrd_token.CheckIsAuthorize(r, userId)

	resp := h.userSvc.SetMainImage(r.Context(), userId, imageId)
	shrd_utils.GenerateSuccessResp(w, resp, 200)
}

func (h *UserHandlerImpl) GetUsers(w http.ResponseWriter, r *http.Request) {
	page := shrd_utils.ValidateQueryParamInt(r, "page")
	limit := shrd_utils.ValidateQueryParamInt(r, "limit")
	searchFieldQuery := r.URL.Query().Get("searchField")
	searchValueQuery := r.URL.Query().Get("searchValue")
	filterByQuery := r.URL.Query().Get("filterBy")
	sortByQuery := r.URL.Query().Get("sortBy")

	input := request.PaginationReq{
		Page:        (page - 1) * limit,
		Limit:       limit,
		SearchField: searchFieldQuery,
		SearchValue: searchValueQuery,
		FilterBy:    filterByQuery,
		SortBy:      sortByQuery,
	}

	resp := h.userSvc.GetUsers(context.Background(), input)
	shrd_utils.GenerateSuccessResp(w, resp, 200)
}

func (h *UserHandlerImpl) GetUser(w http.ResponseWriter, r *http.Request) {
	userId := shrd_utils.ValidateUrlParamUUID(r, "id")

	resp := h.userSvc.GetUser(r.Context(), userId)
	shrd_utils.GenerateSuccessResp(w, resp, 200)
}

func (h *UserHandlerImpl) GetUserImages(w http.ResponseWriter, r *http.Request) {
	userId := shrd_utils.ValidateUrlParamUUID(r, "id")

	resp := h.userSvc.GetUserImages(r.Context(), userId)

	shrd_utils.GenerateSuccessResp(w, resp, 200)
}

func (h *UserHandlerImpl) DeleteImage(w http.ResponseWriter, r *http.Request) {
	userId := shrd_utils.ValidateUrlParamUUID(r, "userId")
	imageId := shrd_utils.ValidateUrlParamUUID(r, "imageId")

	shrd_token.CheckIsAuthorize(r, userId)

	h.userSvc.DeleteImage(r.Context(), userId, imageId)

	shrd_utils.GenerateSuccessResp(w, nil, 200)
}
