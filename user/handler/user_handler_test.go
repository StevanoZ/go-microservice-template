package handler

import (
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	shrd_helper "github.com/StevanoZ/dv-shared/helper"
	shrd_middleware "github.com/StevanoZ/dv-shared/middleware"
	shrd_token "github.com/StevanoZ/dv-shared/token"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	mock_svc "github.com/StevanoZ/dv-user/service/mock"

	"github.com/StevanoZ/dv-user/dtos/mapping"
	"github.com/StevanoZ/dv-user/dtos/request"
	"github.com/StevanoZ/dv-user/dtos/response"

	"github.com/go-chi/chi"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	POST                   = http.MethodPost
	PUT                    = http.MethodPut
	GET                    = http.MethodGet
	DELETE                 = http.MethodDelete
	USER_ID                = uuid.New()
	IMAGE_ID               = uuid.New()
	SYMMETRIC_KEY          = shrd_utils.LoadBaseConfig("../app", "test").TokenSymmetricKey
	FILES, MULTI_PART_FORM = shrd_helper.CreateFormFile(3, "test-image.png")
)

func initUserHandler(ctrl *gomock.Controller, config *shrd_utils.BaseConfig) (UserHandler, *mock_svc.MockUserSvc) {
	userSvc := mock_svc.NewMockUserSvc(ctrl)
	tokenMaker, _ := shrd_token.NewPasetoMaker(config)
	authMiddleware := shrd_middleware.NewAuthMiddleware(tokenMaker)
	return NewUserHandler(userSvc, authMiddleware), userSvc
}

func createUserResp() response.UserResp {
	return response.UserResp{
		ID:        uuid.New(),
		Email:     shrd_utils.RandomEmail(),
		Username:  shrd_utils.RandomUsername(),
		Status:    "not-active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func createUserWithTokenResp() response.UserWithTokenResp {
	return response.UserWithTokenResp{
		ID:        uuid.New(),
		Email:     shrd_utils.RandomEmail(),
		Username:  shrd_utils.RandomUsername(),
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Token:     shrd_utils.RandomString(30),
	}
}

func createDefaultPaginationReq() request.PaginationReq {
	return request.PaginationReq{
		Page:        0,
		Limit:       10,
		FilterBy:    "active",
		SearchField: "email",
		SearchValue: "test",
		SortBy:      "-username",
	}
}

func createUserWithPaginationResp() response.UsersWithPaginationResp {
	usersResp := []response.UserResp{}

	for i := 0; i < 10; i++ {
		userResp := response.UserResp{
			ID:        uuid.New(),
			Email:     shrd_utils.RandomEmail(),
			Username:  shrd_utils.RandomUsername(),
			Status:    "active",
			UpdatedAt: time.Now(),
			CreatedAt: time.Now(),
		}

		usersResp = append(usersResp, userResp)
	}

	pagination := mapping.ToPaginationResp(1, 10, 15)

	return response.UsersWithPaginationResp{
		Users:      usersResp,
		Pagination: pagination,
	}
}

func createUserWithImagesResp(userId uuid.UUID) response.UserWithImagesResp {
	imagesResp := []response.UserImageResp{}

	for i := 0; i < 4; i++ {
		imageResp := response.UserImageResp{
			ID:        uuid.New(),
			UserId:    userId,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if i == 2 {
			imageResp.IsMain = true
		}
		imagesResp = append(imagesResp, imageResp)
	}

	return response.UserWithImagesResp{
		ID:        userId,
		Email:     shrd_utils.RandomEmail(),
		Username:  shrd_utils.RandomUsername(),
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Images:    imagesResp,
	}
}

func createUserImagesResp(userId uuid.UUID) []response.UserImageResp {
	userImagesResp := []response.UserImageResp{}

	for i := 0; i < 3; i++ {
		userImageResp := response.UserImageResp{
			ID:        uuid.New(),
			UserId:    userId,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if i == 0 {
			userImageResp.IsMain = true
		}
		userImagesResp = append(userImagesResp, userImageResp)
	}
	return userImagesResp
}

func TestUserHandlers(t *testing.T) {
	userHandlersTestCase := []shrd_helper.TestCaseHandler{
		{
			Name: "SignUp (status code 201)",
			Payload: request.SignUpReq{
				Username: "Testing",
				Email:    "test@test.com",
				Password: "xxxxxxx",
			},
			Method: POST,
			ReqUrl: "/api/user/sign-up",
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().SignUp(gomock.Any(), input).
					DoAndReturn(func(_ interface{}, input request.SignUpReq) response.UserResp {
						userResp := createUserResp()
						userResp.Email = input.Email
						userResp.Username = input.Username

						return userResp
					}).Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.ResponseMap{}
				expectedResp := expected.(request.SignUpReq)

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse201(t, resp)
				assert.Equal(t, expectedResp.Email, resp.Data["email"])
				assert.Equal(t, expectedResp.Username, resp.Data["username"])
				assert.Equal(t, "not-active", resp.Data["status"])
				assert.Equal(t, nil, resp.Data["token"])
			},
		},
		{
			Name: "LogIn (status code 200)",
			Payload: request.LogInReq{
				Email:    "testing@test.com",
				Password: "xxxxxxx",
			},
			Method: POST,
			ReqUrl: "/api/user/log-in",
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().LogIn(gomock.Any(), input).
					DoAndReturn(func(_ interface{}, input request.LogInReq) response.UserWithTokenResp {
						userWithTokenResp := createUserWithTokenResp()
						userWithTokenResp.Email = input.Email

						return userWithTokenResp
					}).Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.ResponseMap{}
				expectedResp := expected.(request.LogInReq)

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, expectedResp.Email, resp.Data["email"])
				assert.Equal(t, "active", resp.Data["status"])
				assert.Equal(t, 30, len(resp.Data["token"].(string)))
			},
		},
		{
			Name: "VerifyOtp (status code 200)",
			Payload: request.VerifyOtpReq{
				OtpCode: "552277",
				Email:   "test@test.com",
			},
			Method: POST,
			ReqUrl: "/api/user/verify-otp",
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().VerifyOtp(gomock.Any(), input).
					DoAndReturn(func(_ interface{}, input request.VerifyOtpReq) response.UserWithTokenResp {
						userWithTokenResp := createUserWithTokenResp()
						userWithTokenResp.Email = input.Email

						return userWithTokenResp
					}).Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.ResponseMap{}
				expectedResp := expected.(request.VerifyOtpReq)

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, expectedResp.Email, resp.Data["email"])
				assert.Equal(t, 30, len(resp.Data["token"].(string)))
			},
		},
		{
			Name: "ResendOtp (status code 200)",
			Payload: request.ResendOtpReq{
				Email: "test@test.com",
			},
			Method: POST,
			ReqUrl: "/api/user/resend-otp",
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().ResendOtp(gomock.Any(), input).
					Return().Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.ResponseMap{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, nil, resp.Data["data"])
			},
		},
		{
			Name: "UpdateUser [authentication] (status code 200)",
			Payload: request.UpdateUserReq{
				Username:    "Updated",
				PhoneNumber: "082266337367",
			},
			Method: PUT,
			ReqUrl: fmt.Sprintf("/api/user/%s", USER_ID),
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
				shrd_helper.SetAuthorizationHeader(req, SYMMETRIC_KEY, USER_ID)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().UpdateUser(shrd_helper.TokenPayloadContextMatcher(USER_ID), USER_ID, input).
					DoAndReturn(func(_ interface{}, userId uuid.UUID, input request.UpdateUserReq) response.UserResp {
						userResp := createUserResp()
						userResp.Username = input.Username
						userResp.PhoneNumber = input.PhoneNumber

						return userResp
					}).Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.ResponseMap{}
				expectedResp := expected.(request.UpdateUserReq)

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, expectedResp.Username, resp.Data["username"])
				assert.Equal(t, expectedResp.PhoneNumber, resp.Data["phoneNumber"])
			},
		},
		{
			Name:   "GetUsers (status code 200)",
			Method: GET,
			ReqUrl: `/api/user/list?page=1&limit=10&filterBy=active&searchField=email&searchValue=test&sortBy=-username`,
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().GetUsers(gomock.Any(), createDefaultPaginationReq()).
					Return(createUserWithPaginationResp()).Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.Response{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				users := shrd_helper.ParseInterfaceToSlice(resp.Data, "users")
				pagination := shrd_helper.ParseInterfaceToMap(resp.Data, "pagination")

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, 10, len(users))
				assert.Equal(t, float64(2), pagination["next"].(map[string]interface{})["page"])
				assert.Equal(t, float64(-1), pagination["prev"].(map[string]interface{})["page"])
				assert.Equal(t, true, pagination["isLoadMore"])
			},
		},
		{
			Name:   "GetUser [authentication] (status code 200)",
			ReqUrl: fmt.Sprintf("/api/user/%s", USER_ID),
			Method: GET,
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
				shrd_helper.SetAuthorizationHeader(req, SYMMETRIC_KEY, USER_ID)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().GetUser(shrd_helper.TokenPayloadContextMatcher(USER_ID), USER_ID).
					Return(createUserWithImagesResp(USER_ID)).Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.ResponseMap{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, USER_ID.String(), resp.Data["id"].(string))
				assert.Equal(t, 4, len(resp.Data["images"].([]interface{})))
			},
		},
		{
			Name:   "UploadImages [authentication] (status code 200)",
			Method: POST,
			ReqUrl: fmt.Sprintf("/api/user/%s/upload", USER_ID),
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderMultiPartForm(req, MULTI_PART_FORM)
				shrd_helper.SetAuthorizationHeader(req, SYMMETRIC_KEY, USER_ID)
			},
			Payload: FILES,
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().UploadImages(shrd_helper.TokenPayloadContextMatcher(USER_ID), gomock.AssignableToTypeOf([]*multipart.FileHeader{}), USER_ID).
					Return(createUserImagesResp(USER_ID)).Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.Response{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, 3, len(resp.Data.([]interface{})))
			},
		},
		{
			Name:   "UploadImages [authentication] (status code 400)",
			Method: POST,
			ReqUrl: fmt.Sprintf("/api/user/%s/upload", USER_ID),
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderMultiPartForm(req, "form-data")
				shrd_helper.SetAuthorizationHeader(req, SYMMETRIC_KEY, USER_ID)
			},
			Payload: FILES,
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().UploadImages(gomock.Any(), gomock.AssignableToTypeOf([]*multipart.FileHeader{}), USER_ID).
					Return(createUserImagesResp(USER_ID)).Times(0)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.Response{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse400(t, resp)
				assert.Equal(t, false, resp.Success)
			},
		},
		{
			Name:   "SetMainImage [authentication] (status code 200)",
			ReqUrl: fmt.Sprintf("/api/user/%s/image/%s", USER_ID, IMAGE_ID),
			Method: PUT,
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
				shrd_helper.SetAuthorizationHeader(req, SYMMETRIC_KEY, USER_ID)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().SetMainImage(shrd_helper.TokenPayloadContextMatcher(USER_ID), USER_ID, IMAGE_ID).
					DoAndReturn(func(_ interface{}, userId uuid.UUID, imageId uuid.UUID) response.UserImageResp {
						return response.UserImageResp{
							ID:        imageId,
							UserId:    userId,
							IsMain:    true,
							UpdatedAt: time.Now(),
						}
					}).Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.ResponseMap{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)
				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, IMAGE_ID.String(), resp.Data["id"])
				assert.Equal(t, USER_ID.String(), resp.Data["userId"])
				assert.Equal(t, true, resp.Data["isMain"])
			},
		},
		{
			Name:   "DeleteImage [authentication] (status code 200)",
			ReqUrl: fmt.Sprintf("/api/user/%s/image/%s", USER_ID, IMAGE_ID),
			Method: DELETE,
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
				shrd_helper.SetAuthorizationHeader(req, SYMMETRIC_KEY, USER_ID)
			},
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().DeleteImage(shrd_helper.TokenPayloadContextMatcher(USER_ID), USER_ID, IMAGE_ID).
					Return().Times(1)
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.ResponseMap{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Nil(t, resp.Data)
			},
		},
		{
			Name:   "GetUserImages (status code 200)",
			ReqUrl: fmt.Sprintf("/api/user/%s/image", USER_ID),
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
				shrd_helper.SetAuthorizationHeader(req, SYMMETRIC_KEY, USER_ID)
			},
			Method: GET,
			BuildStub: func(input interface{}, stubs ...interface{}) {
				userSvc := stubs[0].(*mock_svc.MockUserSvc)

				userSvc.EXPECT().GetUserImages(shrd_helper.TokenPayloadContextMatcher(USER_ID), USER_ID).
					Return(createUserImagesResp(USER_ID))
			},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.Response{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse200(t, resp)
				assert.Equal(t, 3, len(resp.Data.([]interface{})))
				assert.Equal(t, USER_ID.String(), resp.Data.([]interface{})[1].(map[string]interface{})["userId"])
			},
		},
		{
			Name:   "Not found route (status code 404)",
			ReqUrl: "/api/user/test/xxx",
			SetHeaders: func(req *http.Request) {
				shrd_helper.SetHeaderApplicationJson(req)
			},
			Method:    GET,
			BuildStub: func(input interface{}, stubs ...interface{}) {},
			CheckResponse: func(recorder *httptest.ResponseRecorder, expected interface{}) {
				resp := shrd_utils.Response{}

				shrd_helper.ParseResponseBody(recorder.Body, &resp)

				shrd_helper.CheckResponse404(t, resp)
				assert.Nil(t, resp.Data)
			},
		},
	}

	r := chi.NewRouter()
	r.Use(shrd_middleware.Recovery)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := shrd_utils.LoadBaseConfig("../app", "test")

	userHanlder, userSvc := initUserHandler(ctrl, config)
	userHanlder.SetupUserRoutes(r)

	for i := range userHandlersTestCase {
		tc := userHandlersTestCase[i]

		t.Run(tc.Name, func(t *testing.T) {
			shrd_helper.SetupRequest(t, r, tc, userSvc)
		})
	}
}
