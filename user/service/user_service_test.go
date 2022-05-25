package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"strconv"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/pubsub"
	shrd_helper "github.com/StevanoZ/dv-shared/helper"
	message "github.com/StevanoZ/dv-shared/message"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_token "github.com/StevanoZ/dv-shared/token"

	shrd_mock_svc "github.com/StevanoZ/dv-shared/service/mock"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	user_db "github.com/StevanoZ/dv-user/db/user/sqlc"
	"github.com/StevanoZ/dv-user/dtos/request"
	"github.com/StevanoZ/dv-user/utils"

	mock_user_repo "github.com/StevanoZ/dv-user/db/user/sqlc/mock"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var USER_ID = uuid.New()

const (
	UNPROCESSABLE_ENTITY = "unprocessable entity"
	BAD_REQUEST          = "bad request"
	NOT_FOUND            = "not found"

	EMAIL    = "test@test.com"
	PASSWORD = "xxxxxxx"
	USERNAME = "Testing"
	OTP_CODE = "111777"

	DEFAULT_FILES_LENGTH = 3
	IMAGE_NAME           = "test-image.png"
	TEST_IMAGE_1         = "test-image-1"
	TEST_IMAGE_2         = "test-image-2"
	TEST_IMAGE_3         = "test-image-3"
)

func LoadConfigAndSetUpDb() (*shrd_utils.BaseConfig, *sql.DB) {
	config := shrd_utils.LoadBaseConfig("../app", "test")
	DB := shrd_utils.ConnectDB(config.DBDriver, config.DBSource)
	return config, DB
}

func initUserSvc(ctrl *gomock.Controller, config *shrd_utils.BaseConfig) (
	UserSvc,
	*mock_user_repo.MockUserRepo,
	*shrd_mock_svc.MockFileSvc,
	*shrd_mock_svc.MockPubSubClient,
	shrd_service.CacheSvc,
) {
	pubSubClient := shrd_mock_svc.NewMockPubSubClient(ctrl)
	fileSvc := shrd_mock_svc.NewMockFileSvc(ctrl)
	userRepo := mock_user_repo.NewMockUserRepo(ctrl)
	tokenMaker, _ := shrd_token.NewPasetoMaker(config)
	redisClient := shrd_service.NewRedisClientForTesting(config)
	cacheSvc := shrd_service.NewCacheSvc(config, redisClient)

	userSvc := NewUserSvc(userRepo, fileSvc, pubSubClient, cacheSvc, tokenMaker, config)

	return userSvc, userRepo, fileSvc, pubSubClient, cacheSvc
}

func setupAndMockTx(t *testing.T, DB *sql.DB, userRepo *mock_user_repo.MockUserRepo) {
	tx, err := DB.BeginTx(context.Background(), nil)
	assert.NoError(t, err)
	userRepo.EXPECT().GetDB().Return(DB).Times(1)
	userRepo.EXPECT().WithTx(gomock.AssignableToTypeOf(tx)).Return(userRepo).Times(1)
}

func createUser() user_db.User {
	otpCodeParsed, _ := strconv.Atoi(OTP_CODE)
	return user_db.User{
		ID:          uuid.New(),
		Email:       EMAIL,
		Password:    PASSWORD,
		Username:    USERNAME,
		Status:      "not-active",
		OtpCode:     int64(otpCodeParsed),
		AttemptLeft: 5,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func createUsersActive() []user_db.User {
	users := []user_db.User{}
	for i := 0; i < 10; i++ {
		user := user_db.User{
			ID:            uuid.New(),
			Email:         fmt.Sprintf("testing.user-%d", i+1),
			Username:      shrd_utils.RandomUsername(),
			Password:      shrd_utils.RandomString(12),
			OtpCode:       0,
			AttemptLeft:   0,
			Status:        "active",
			MainImageUrl:  buildUploadUrl(IMAGE_NAME),
			MainImagePath: fmt.Sprintf("users/userId/%s", IMAGE_NAME),
		}

		users = append(users, user)
	}
	return users
}

func buildUploadUrl(path string) string {
	return fmt.Sprintf("https://amazon.s3.com/%s", path)
}

func createUserWithImages(userId uuid.UUID, isSetMainImage bool) (user_db.FindUserWithImagesRow, uuid.UUID) {
	isMain := false
	firstImageId := uuid.New()

	if isSetMainImage {
		isMain = true
	}

	images := []user_db.UserImage{
		{
			ID:        firstImageId,
			UserID:    userId,
			ImageUrl:  buildUploadUrl(TEST_IMAGE_1),
			ImagePath: fmt.Sprintf("users/%s/%s", userId, TEST_IMAGE_1),
			IsMain:    isMain,
		},
		{
			ID:        uuid.New(),
			UserID:    userId,
			ImageUrl:  buildUploadUrl(TEST_IMAGE_2),
			ImagePath: fmt.Sprintf("users/%s/%s", userId, TEST_IMAGE_2),
			IsMain:    false,
		},
		{
			ID:        uuid.New(),
			UserID:    userId,
			ImageUrl:  buildUploadUrl(TEST_IMAGE_3),
			ImagePath: fmt.Sprintf("users/%s/%s", userId, TEST_IMAGE_3),
			IsMain:    false,
		},
		{
			ID:        shrd_utils.DEFAULT_UUID,
			UserID:    userId,
			ImageUrl:  "",
			ImagePath: "",
			IsMain:    false,
		},
	}

	jsonRawMessage, _ := json.Marshal(images)

	return user_db.FindUserWithImagesRow{
		ID:          userId,
		Email:       shrd_utils.RandomEmail(),
		Username:    shrd_utils.RandomUsername(),
		Password:    shrd_utils.RandomString(12),
		Status:      "active",
		AttemptLeft: 0,
		OtpCode:     0,
		Images:      jsonRawMessage,
	}, firstImageId
}

func createUserImages(userId uuid.UUID) []user_db.UserImage {
	userImages := []user_db.UserImage{}

	for i := 0; i < 7; i++ {
		userImage := user_db.UserImage{
			ID:        uuid.New(),
			UserID:    userId,
			ImageUrl:  buildUploadUrl(IMAGE_NAME),
			ImagePath: fmt.Sprintf("users/%s/%s", userId, IMAGE_NAME),
			IsMain:    false,
		}

		if i == 2 {
			userImage.IsMain = true
		}

		userImages = append(userImages, userImage)
	}

	return userImages
}

func createPaginationReq() request.PaginationReq {
	return request.PaginationReq{
		SearchField: "email",
		SearchValue: "testing",
		SortBy:      "username",
		FilterBy:    "active",
		Page:        0,
		Limit:       10,
	}
}

func createFindUserParams(searchValue string) user_db.FindUsersParams {
	return user_db.FindUsersParams{
		SearchField: "email",
		SearchValue: "%" + searchValue + "%",
		SortBy:      "username",
		FilterBy:    "active",
		Offset:      0,
		Limit:       10,
	}
}

func createPaginationCountParams(searchValue string) user_db.GetUsersPaginationCountParams {
	return user_db.GetUsersPaginationCountParams{
		SearchField: "email",
		SearchValue: "%" + searchValue + "%",
		FilterBy:    "active",
	}
}

func TestSignUp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()

	defer DB.Close()

	userSvc,
		userRepo,
		_, pubSubClient, _ := initUserSvc(ctrl, config)

	t.Run("Success Request", func(t *testing.T) {
		var userId uuid.UUID
		otpCode := shrd_utils.RandomInt(0, 999999)
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{}, nil).Times(1)
		userRepo.EXPECT().CreateUser(ctx, gomock.AssignableToTypeOf(user_db.CreateUserParams{})).
			DoAndReturn(func(_ interface{}, params user_db.CreateUserParams) (user_db.User, error) {
				assert.NotEqual(t, PASSWORD, params.Password)
				assert.Equal(t, USERNAME, params.Username)
				user := createUser()
				userId = user.ID
				user.OtpCode = otpCode

				return user, nil
			})

		pubSubClient.EXPECT().CreateTopicIfNotExists(gomock.Any(), message.EMAIL_TOPIC).
			Return(&pubsub.Topic{}, nil).Times(1)
		pubSubClient.EXPECT().PublishTopics(gomock.Any(), gomock.AssignableToTypeOf([]*pubsub.Topic{}), message.OtpPayload{
			Email:   EMAIL,
			OtpCode: int(otpCode),
		}, message.SEND_OTP_KEY).Return(nil).Times(1)

		assert.NotPanics(t, func() {
			resp := userSvc.SignUp(ctx, request.SignUpReq{Email: EMAIL, Username: USERNAME, Password: PASSWORD})
			assert.Equal(t, userId, resp.ID)
		})
	})
	t.Run("Sql error (status code 422)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{}, errors.New(UNPROCESSABLE_ENTITY)).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("|%s", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.SignUp(ctx, request.SignUpReq{
				Email:    EMAIL,
				Username: USERNAME,
				Password: PASSWORD,
			})
		})
	})

	t.Run("Email already in used (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(createUser(), nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|email already in used",
			StatusCode: 400,
		}, func() {
			userSvc.SignUp(ctx, request.SignUpReq{
				Email:    EMAIL,
				Username: USERNAME,
				Password: PASSWORD,
			})
		})
	})
	t.Run("Failed when creating user (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{}, nil).Times(1)
		userRepo.EXPECT().CreateUser(ctx, gomock.AssignableToTypeOf(user_db.CreateUserParams{})).
			Return(user_db.User{}, errors.New(UNPROCESSABLE_ENTITY)).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when creating user", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.SignUp(ctx, request.SignUpReq{
				Email:    EMAIL,
				Username: USERNAME,
				Password: PASSWORD,
			})
		})
	})
}

func TestLogIn(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config, DB := LoadConfigAndSetUpDb()
	ctx := context.Background()
	defer DB.Close()

	userSvc,
		userRepo,
		fileSvc, _, _ := initUserSvc(ctrl, config)

	imagePath := fmt.Sprintf("user/%s", USER_ID)
	preSignedUrl := fmt.Sprintf("https://amazon.s3/%s/test-image.png", imagePath)
	hashedPassword, err := shrd_utils.HashedPassword(PASSWORD)
	assert.NoError(t, err)
	userDbActive := user_db.User{
		ID:            USER_ID,
		Password:      hashedPassword,
		Status:        "active",
		Email:         EMAIL,
		Username:      USERNAME,
		MainImagePath: imagePath,
	}
	t.Run("Success Request", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(userDbActive, nil).Times(1)
		fileSvc.EXPECT().GetPreSignUrl(ctx, imagePath).Return(preSignedUrl, nil).Times(1)

		assert.NotPanics(t, func() {
			resp := userSvc.LogIn(ctx, request.LogInReq{Email: EMAIL, Password: PASSWORD})
			assert.Equal(t, USER_ID, resp.ID)
			assert.NotNil(t, resp.Token)
			assert.Equal(t, preSignedUrl, resp.MainImageUrl)
		})
	})

	t.Run("User not found (status code 404)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{}, sql.ErrNoRows).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|user not found", sql.ErrNoRows),
			StatusCode: 404,
		}, func() {
			userSvc.LogIn(ctx, request.LogInReq{Email: EMAIL, Password: PASSWORD})
		})
	})

	t.Run("Invalid request status = not-active (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{Status: "not-active"}, nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|please verify your email first",
			StatusCode: 400,
		}, func() {
			userSvc.LogIn(ctx, request.LogInReq{Email: EMAIL, Password: PASSWORD})
		})
	})

	t.Run("Invalid credential (status code 401)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{
			Password: PASSWORD,
			Status:   "active",
			Email:    EMAIL,
			Username: USERNAME,
		}, nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|invalid credentials",
			StatusCode: 401,
		}, func() {
			userSvc.LogIn(ctx, request.LogInReq{Email: EMAIL, Password: PASSWORD})
		})
	})
	t.Run("Not call get pre sign URL when user main image path is empty", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{
			ID:            USER_ID,
			Status:        "active",
			Password:      hashedPassword,
			MainImagePath: "",
		}, nil).Times(1)
		fileSvc.EXPECT().GetPreSignUrl(ctx, imagePath).Return("", errors.New(UNPROCESSABLE_ENTITY)).Times(0)

		assert.NotPanics(t, func() {
			resp := userSvc.LogIn(ctx, request.LogInReq{Email: EMAIL, Password: PASSWORD})
			assert.Equal(t, USER_ID, resp.ID)
			assert.NotNil(t, resp.Token)
		})
	})
	t.Run("Failed when getting pre sign URL", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(userDbActive, nil).Times(1)
		fileSvc.EXPECT().GetPreSignUrl(ctx, imagePath).Return("", errors.New(UNPROCESSABLE_ENTITY)).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			StatusCode: 422,
			Message:    fmt.Sprintf("%s|failed when trying to log in", UNPROCESSABLE_ENTITY),
		}, func() {
			userSvc.LogIn(ctx, request.LogInReq{Email: EMAIL, Password: PASSWORD})
		})
	})
}

func TestVerifyOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	ctx := context.Background()
	userSvc, userRepo, _, _, _ := initUserSvc(ctrl, config)

	t.Run("Success Request", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		parsedOtpCode, err := strconv.Atoi(OTP_CODE)
		assert.NoError(t, err)

		user := createUser()
		user.OtpCode = int64(parsedOtpCode)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user, nil).Times(1)

		userRepo.EXPECT().UpdateUser(ctx, user_db.UpdateUserParams{
			ID:          user.ID,
			Username:    USERNAME,
			Password:    PASSWORD,
			PhoneNumber: "",
			Status:      "active",
			AttemptLeft: 0,
			OtpCode:     0,
		}).DoAndReturn(func(_ interface{}, params user_db.UpdateUserParams) (user_db.User, error) {
			user.Status = params.Status
			user.OtpCode = params.OtpCode
			user.AttemptLeft = params.AttemptLeft
			return user, nil
		}).Times(1)

		assert.NotPanics(t, func() {
			resp := userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: OTP_CODE})
			assert.Equal(t, user.ID, resp.ID)
			assert.Equal(t, "active", resp.Status)
			assert.NotNil(t, resp.Token)
		})
	})

	t.Run("User not found (status code 404)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{}, sql.ErrNoRows).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|user not found", sql.ErrNoRows),
			StatusCode: 404,
		}, func() {
			userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: OTP_CODE})
		})
	})

	t.Run("Invalid request status = active (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{
			Status: "active",
		}, nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|invalid request",
			StatusCode: 400,
		}, func() {
			userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: OTP_CODE})
		})
	})

	t.Run("Invalid request attempt left = 0 (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{
			AttemptLeft: 0,
		}, nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|your attempt left is 0",
			StatusCode: 400,
		}, func() {
			userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: OTP_CODE})
		})
	})

	t.Run("Expired otp code (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{
			AttemptLeft: 5,
			UpdatedAt:   time.Now().Add(-5 * time.Minute),
		}, nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|otp code has expired",
			StatusCode: 400,
		}, func() {
			userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: OTP_CODE})
		})
	})

	t.Run("Invalid otp code (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		invalidOtpCode := 123456
		user := createUser()
		user.OtpCode = int64(invalidOtpCode)

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user, nil).Times(1)
		userRepo.EXPECT().UpdateUser(ctx, user_db.UpdateUserParams{
			ID:          user.ID,
			Username:    USERNAME,
			Password:    PASSWORD,
			PhoneNumber: "",
			Status:      "not-active",
			AttemptLeft: 4,
			OtpCode:     int64(invalidOtpCode),
		}).DoAndReturn(func(_ interface{}, _ interface{}) (user_db.User, error) {
			user.AttemptLeft = user.AttemptLeft - 1
			return user, nil
		}).Times(1)
		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|invalid otp code",
			StatusCode: 400,
		}, func() {
			userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: OTP_CODE})
		})
	})

	t.Run("Invalid otp code, failed parsing input (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		otpCode := "1234xx"
		strconvErr := "strconv.Atoi: parsing \"1234xx\": invalid syntax|invalid otp code"

		user := createUser()

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user, nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    strconvErr,
			StatusCode: 400,
		}, func() {
			userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: otpCode})
		})
	})
	t.Run("Invalid otp code and failed updating user (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		invalidOtpCode := 123456
		user := createUser()
		user.OtpCode = int64(invalidOtpCode)

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user, nil).Times(1)
		userRepo.EXPECT().UpdateUser(ctx, user_db.UpdateUserParams{
			ID:          user.ID,
			Username:    USERNAME,
			Password:    PASSWORD,
			PhoneNumber: "",
			Status:      "not-active",
			AttemptLeft: 4,
			OtpCode:     int64(invalidOtpCode),
		}).Return(user_db.User{}, errors.New(UNPROCESSABLE_ENTITY)).Times(1)
		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when updating user", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: OTP_CODE})
		})
	})

	t.Run("Valid otp code and failed updating (status code 422)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)
		parsedOtpCode, err := strconv.Atoi(OTP_CODE)
		assert.NoError(t, err)

		user := createUser()
		user.OtpCode = int64(parsedOtpCode)

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user, nil).Times(1)

		userRepo.EXPECT().UpdateUser(ctx, user_db.UpdateUserParams{
			ID:          user.ID,
			Username:    USERNAME,
			Password:    PASSWORD,
			PhoneNumber: "",
			Status:      "active",
			AttemptLeft: 0,
			OtpCode:     0,
		}).Return(user_db.User{}, errors.New(UNPROCESSABLE_ENTITY)).Times(1)
		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when updating user", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.VerifyOtp(ctx, request.VerifyOtpReq{Email: EMAIL, OtpCode: OTP_CODE})
		})
	})
}

func TestResendOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	userSvc, userRepo, _, pubSubClient, _ := initUserSvc(ctrl, config)

	t.Run("Success Request", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)

		user := createUser()
		user.Email = EMAIL
		var newOtpCode int64
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user, nil).
			Times(1)
		userRepo.EXPECT().UpdateUser(ctx, gomock.AssignableToTypeOf(user_db.UpdateUserParams{})).
			DoAndReturn(func(_ interface{}, params user_db.UpdateUserParams) (user_db.User, error) {
				newOtpCode = params.OtpCode
				user.OtpCode = newOtpCode
				user.AttemptLeft = params.AttemptLeft

				pubSubClient.EXPECT().CreateTopicIfNotExists(gomock.Any(), message.EMAIL_TOPIC).
					Return(&pubsub.Topic{}, nil).Times(1)
				pubSubClient.EXPECT().PublishTopics(gomock.Any(), gomock.AssignableToTypeOf([]*pubsub.Topic{}), message.OtpPayload{
					Email:   EMAIL,
					OtpCode: int(newOtpCode),
				}, message.SEND_OTP_KEY).Return(nil).Times(1)

				return user, nil
			}).Times(1)

		assert.NotPanics(t, func() {
			userSvc.ResendOtp(ctx, request.ResendOtpReq{Email: EMAIL})
		})
	})

	t.Run("User not found (status code 404)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{}, errors.New(NOT_FOUND)).
			Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|user not found", NOT_FOUND),
			StatusCode: 404,
		}, func() {
			userSvc.ResendOtp(ctx, request.ResendOtpReq{Email: EMAIL})
		})
	})

	t.Run("Invalid request status = active (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{
			Status: "active",
		}, nil).
			Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|invalid request",
			StatusCode: 400,
		}, func() {
			userSvc.ResendOtp(ctx, request.ResendOtpReq{Email: EMAIL})
		})
	})

	t.Run("Invalid request status = active (status code 400)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)

		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user_db.User{
			AttemptLeft: 0,
		}, nil).
			Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|can't sent OTP, your attempt left is 0",
			StatusCode: 400,
		}, func() {
			userSvc.ResendOtp(ctx, request.ResendOtpReq{Email: EMAIL})
		})
	})

	t.Run("Failed when updating user (status code 422)", func(t *testing.T) {
		setupAndMockTx(t, DB, userRepo)

		user := createUser()
		user.Email = EMAIL
		userRepo.EXPECT().FindUserByEmail(ctx, EMAIL).Return(user, nil).
			Times(1)
		userRepo.EXPECT().UpdateUser(ctx, gomock.AssignableToTypeOf(user_db.UpdateUserParams{})).
			DoAndReturn(func(_ interface{}, params user_db.UpdateUserParams) (user_db.User, error) {
				assert.NotEqual(t, user.OtpCode, params.OtpCode)
				assert.Equal(t, user.AttemptLeft-1, params.AttemptLeft)

				return user_db.User{}, errors.New(UNPROCESSABLE_ENTITY)
			}).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when updating user", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.ResendOtp(ctx, request.ResendOtpReq{Email: EMAIL})
		})
	})
}

func TestUpdateUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	userSvc, userRepo, _, _, _ := initUserSvc(ctrl, config)

	t.Run("Success Request", func(t *testing.T) {
		userId := USER_ID
		input := request.UpdateUserReq{
			Username:    "TestX",
			PhoneNumber: "082112158745",
		}
		setupAndMockTx(t, DB, userRepo)
		user := createUser()
		user.ID = userId

		userRepo.EXPECT().FindUserById(ctx, userId).Return(user, nil).Times(1)
		userRepo.EXPECT().UpdateUser(ctx, gomock.AssignableToTypeOf(user_db.UpdateUserParams{})).
			DoAndReturn(func(_ interface{}, params user_db.UpdateUserParams) (user_db.User, error) {
				updatedUsername := params.Username
				updatedPhoneNumber := params.PhoneNumber
				assert.Equal(t, input.Username, updatedUsername)
				assert.Equal(t, input.PhoneNumber, updatedPhoneNumber)

				user.Username = updatedUsername
				user.PhoneNumber = updatedPhoneNumber

				return user, nil
			})
		assert.NotPanics(t, func() {
			resp := userSvc.UpdateUser(ctx, userId, input)

			assert.Equal(t, resp.ID, userId)
			assert.Equal(t, resp.Username, input.Username)
			assert.Equal(t, resp.PhoneNumber, input.PhoneNumber)
		})
	})

	t.Run("User not found (status code 404)", func(t *testing.T) {
		userId := USER_ID
		input := request.UpdateUserReq{
			Username:    "TestX",
			PhoneNumber: "082112158745",
		}
		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserById(ctx, userId).Return(user_db.User{}, errors.New(NOT_FOUND)).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|user not found", NOT_FOUND),
			StatusCode: 404,
		}, func() {
			userSvc.UpdateUser(ctx, userId, input)
		})
	})

	t.Run("Failed when updating user (status code 400)", func(t *testing.T) {
		userId := USER_ID
		input := request.UpdateUserReq{
			Username:    "TestX",
			PhoneNumber: "082112158745",
		}
		setupAndMockTx(t, DB, userRepo)
		user := createUser()
		user.ID = userId

		userRepo.EXPECT().FindUserById(ctx, userId).Return(user, nil).Times(1)
		userRepo.EXPECT().UpdateUser(ctx, user_db.UpdateUserParams{
			ID:          userId,
			Username:    input.Username,
			PhoneNumber: input.PhoneNumber,
			OtpCode:     user.OtpCode,
			AttemptLeft: user.AttemptLeft,
			Password:    user.Password,
			Status:      user.Status,
		}).Return(user_db.User{}, errors.New(UNPROCESSABLE_ENTITY)).Times(1)
		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when updating user", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.UpdateUser(ctx, userId, input)
		})
	})
}

func TestUploadImages(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	userSvc, userRepo, fileSvc, _, _ := initUserSvc(ctrl, config)

	t.Run("Request Success and SET user main image", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)
		user := createUser()
		user.ID = userId

		fileSvc.EXPECT().UploadPrivateFile(ctx, gomock.Not(nil), gomock.Any()).
			DoAndReturn(func(_ interface{}, _ interface{}, path string) (string, error) {
				pathSlice := strings.Split(path, "/")
				assert.Equal(t, "users", pathSlice[0])
				assert.Equal(t, userId.String(), pathSlice[1])
				return buildUploadUrl(IMAGE_NAME), nil
			}).Times(3)

		userRepo.EXPECT().CreateUserImage(ctx, gomock.AssignableToTypeOf(user_db.CreateUserImageParams{})).
			DoAndReturn(func(_ interface{}, params user_db.CreateUserImageParams) (user_db.UserImage, error) {
				assert.Equal(t, userId, params.UserID)
				assert.Equal(t, buildUploadUrl(IMAGE_NAME), params.ImageUrl)
				assert.Contains(t, params.ImagePath, fmt.Sprintf("users/%s", userId))
				userImage := user_db.UserImage{
					ID:        uuid.New(),
					ImageUrl:  buildUploadUrl(IMAGE_NAME),
					ImagePath: fmt.Sprintf("users/%s/%s.png", userId, IMAGE_NAME),
				}
				return userImage, nil
			}).Times(3)

		filesHeader := shrd_helper.CreateFilesHeader(DEFAULT_FILES_LENGTH, IMAGE_NAME)

		// FOR UNWAITED GO ROUTINES
		setupAndMockTx(t, DB, userRepo)
		userImages, firstImageId := createUserWithImages(userId, false)

		userRepo.EXPECT().FindUserWithImages(ctx, userId).Return(
			userImages, nil,
		).Times(1)

		userRepo.EXPECT().UpdateUserImage(ctx, user_db.UpdateUserImageParams{
			ID:     firstImageId,
			IsMain: true,
		}).
			Return(user_db.UserImage{}, nil).Times(1)

		userRepo.EXPECT().UpdateUserMainImage(ctx, gomock.Any()).
			DoAndReturn(func(_ interface{}, params user_db.UpdateUserMainImageParams) (user_db.User, error) {
				assert.Equal(t, userId, params.ID)
				assert.Equal(t, buildUploadUrl(TEST_IMAGE_1), params.MainImageUrl)
				assert.Contains(t, params.MainImagePath, fmt.Sprintf("users/%s", userId))
				return user_db.User{}, nil
			}).Times(1)

		assert.NotPanics(t, func() {
			resp := userSvc.UploadImages(ctx, filesHeader, userId)
			assert.Equal(t, DEFAULT_FILES_LENGTH, len(resp))
			time.Sleep(500 * time.Millisecond)
		})
	})

	t.Run("Request Success and NOT SET user main image", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)
		user := createUser()
		user.ID = userId

		fileSvc.EXPECT().UploadPrivateFile(ctx, gomock.Not(nil), gomock.Any()).
			DoAndReturn(func(_ interface{}, _ interface{}, path string) (string, error) {
				pathSlice := strings.Split(path, "/")
				assert.Equal(t, "users", pathSlice[0])
				assert.Equal(t, userId.String(), pathSlice[1])
				return buildUploadUrl(IMAGE_NAME), nil
			}).Times(3)

		userRepo.EXPECT().CreateUserImage(ctx, gomock.AssignableToTypeOf(user_db.CreateUserImageParams{})).
			DoAndReturn(func(_ interface{}, params user_db.CreateUserImageParams) (user_db.UserImage, error) {
				assert.Equal(t, userId, params.UserID)
				assert.Equal(t, buildUploadUrl(IMAGE_NAME), params.ImageUrl)
				assert.Contains(t, params.ImagePath, fmt.Sprintf("users/%s", userId))
				userImage := user_db.UserImage{
					ID:        uuid.New(),
					ImageUrl:  buildUploadUrl(IMAGE_NAME),
					ImagePath: fmt.Sprintf("users/%s/%s.png", userId, IMAGE_NAME),
				}
				return userImage, nil
			}).Times(3)

		filesHeader := shrd_helper.CreateFilesHeader(DEFAULT_FILES_LENGTH, IMAGE_NAME)

		// FOR UNWAITED GO ROUTINES
		setupAndMockTx(t, DB, userRepo)
		userImages, _ := createUserWithImages(userId, true)

		userRepo.EXPECT().FindUserWithImages(ctx, userId).Return(
			userImages, nil,
		).Times(1)

		// SHOULD NOT CALL THIS BECAUSE MAIN IMAGE ALREADY SET
		userRepo.EXPECT().UpdateUserImage(ctx, gomock.Any()).Times(0)
		userRepo.EXPECT().UpdateUserMainImage(ctx, gomock.Any()).Times(0)

		assert.NotPanics(t, func() {
			resp := userSvc.UploadImages(ctx, filesHeader, userId)
			assert.Equal(t, DEFAULT_FILES_LENGTH, len(resp))
			time.Sleep(500 * time.Millisecond)
		})
	})

	t.Run("Upload more than 10 (status code 400)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		filesHeader := shrd_helper.CreateFilesHeader(11, IMAGE_NAME)

		fileSvc.EXPECT().UploadPrivateFile(ctx, gomock.Any(), gomock.Any()).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|can't upload more than 10 files at once",
			StatusCode: 400,
		}, func() {
			userSvc.UploadImages(ctx, filesHeader, userId)
		})
	})

	t.Run("Failed when opening file (status code 400)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		filesHeader := []*multipart.FileHeader{
			{Filename: TEST_IMAGE_3, Size: 1024},
		}

		fileSvc.EXPECT().UploadPrivateFile(ctx, gomock.Any(), gomock.Any()).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "open : no such file or directory|failed when uploading file",
			StatusCode: 400,
		}, func() {
			userSvc.UploadImages(ctx, filesHeader, userId)
		})
	})

	t.Run("Failed when uploading file (status code 422)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		filesHeader := shrd_helper.CreateFilesHeader(DEFAULT_FILES_LENGTH, IMAGE_NAME)

		fileSvc.EXPECT().UploadPrivateFile(ctx, gomock.Not(nil), gomock.Any()).
			Return("", errors.New(UNPROCESSABLE_ENTITY)).Times(3)

		// IF ERROR SHOULD NOT CALL THIS
		tx, err := DB.BeginTx(context.Background(), nil)
		assert.NoError(t, err)
		userRepo.EXPECT().GetDB().Return(DB).Times(0)
		userRepo.EXPECT().WithTx(gomock.AssignableToTypeOf(tx)).Return(userRepo).Times(0)
		userRepo.EXPECT().FindUserWithImages(ctx, userId).Times(0)
		userRepo.EXPECT().UpdateUserImage(ctx, gomock.Any()).Times(0)
		userRepo.EXPECT().UpdateUserMainImage(ctx, gomock.Any()).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when uploading file", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.UploadImages(ctx, filesHeader, userId)
		})
	})

	t.Run("Failed when creating user image (status code 422)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		filesHeader := shrd_helper.CreateFilesHeader(DEFAULT_FILES_LENGTH, IMAGE_NAME)

		fileSvc.EXPECT().UploadPrivateFile(ctx, gomock.Not(nil), gomock.Any()).
			Return(buildUploadUrl(IMAGE_NAME), nil).Times(3)
		userRepo.EXPECT().CreateUserImage(ctx, gomock.AssignableToTypeOf(user_db.CreateUserImageParams{})).
			Return(user_db.UserImage{}, errors.New(UNPROCESSABLE_ENTITY)).Times(3)

		// IF ERROR SHOULD NOT CALL THIS
		tx, err := DB.BeginTx(context.Background(), nil)
		assert.NoError(t, err)
		userRepo.EXPECT().GetDB().Return(DB).Times(0)
		userRepo.EXPECT().WithTx(gomock.AssignableToTypeOf(tx)).Return(userRepo).Times(0)
		userRepo.EXPECT().FindUserWithImages(ctx, userId).Times(0)
		userRepo.EXPECT().UpdateUserImage(ctx, gomock.Any()).Times(0)
		userRepo.EXPECT().UpdateUserMainImage(ctx, gomock.Any()).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when uploading file", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.UploadImages(ctx, filesHeader, userId)
		})
	})

	t.Run("Go Routine failed when get user with images", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		filesHeader := shrd_helper.CreateFilesHeader(DEFAULT_FILES_LENGTH, IMAGE_NAME)

		fileSvc.EXPECT().UploadPrivateFile(ctx, gomock.Not(nil), gomock.Any()).
			Return(buildUploadUrl(IMAGE_NAME), nil).Times(3)
		userRepo.EXPECT().CreateUserImage(ctx, gomock.AssignableToTypeOf(user_db.CreateUserImageParams{})).
			Return(user_db.UserImage{}, nil).Times(3)

		setupAndMockTx(t, DB, userRepo)
		userRepo.EXPECT().FindUserWithImages(ctx, userId).Return(user_db.FindUserWithImagesRow{}, errors.New(UNPROCESSABLE_ENTITY)).
			Times(1)
		userRepo.EXPECT().UpdateUserImage(ctx, gomock.Any()).Times(0)
		userRepo.EXPECT().UpdateUserMainImage(ctx, gomock.Any()).Times(0)

		assert.NotPanics(t, func() {
			resp := userSvc.UploadImages(ctx, filesHeader, userId)
			assert.Equal(t, DEFAULT_FILES_LENGTH, len(resp))
			time.Sleep(500 * time.Millisecond)
		})
	})

	t.Run("Go Routine failed when updating image", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		filesHeader := shrd_helper.CreateFilesHeader(DEFAULT_FILES_LENGTH, IMAGE_NAME)

		fileSvc.EXPECT().UploadPrivateFile(ctx, gomock.Not(nil), gomock.Any()).
			Return(buildUploadUrl(IMAGE_NAME), nil).Times(3)
		userRepo.EXPECT().CreateUserImage(ctx, gomock.AssignableToTypeOf(user_db.CreateUserImageParams{})).
			Return(user_db.UserImage{}, nil).Times(3)

		setupAndMockTx(t, DB, userRepo)
		userImages, _ := createUserWithImages(userId, false)

		userRepo.EXPECT().FindUserWithImages(ctx, userId).Return(userImages, nil).
			Times(1)
		userRepo.EXPECT().UpdateUserImage(ctx, gomock.Any()).
			Return(user_db.UserImage{}, errors.New(UNPROCESSABLE_ENTITY)).MinTimes(1)
		userRepo.EXPECT().UpdateUserMainImage(ctx, gomock.Any()).
			Return(user_db.User{}, nil).MinTimes(1)

		assert.NotPanics(t, func() {
			resp := userSvc.UploadImages(ctx, filesHeader, userId)
			assert.Equal(t, DEFAULT_FILES_LENGTH, len(resp))
			time.Sleep(500 * time.Millisecond)
		})
	})
}

func TestSetMainImage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	userSvc, userRepo, _, _, _ := initUserSvc(ctrl, config)

	t.Run("Success Request", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		userImages, oldMainImageId := createUserWithImages(userId, true)
		images := []user_db.UserImage{}
		err := json.Unmarshal(userImages.Images, &images)
		assert.NoError(t, err)
		newMainImage := images[2]

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(userImages, nil).Times(1)

		userRepo.EXPECT().UpdateUserImage(ctx, user_db.UpdateUserImageParams{
			ID:     newMainImage.ID,
			IsMain: true,
		}).DoAndReturn(func(_ interface{}, params user_db.UpdateUserImageParams) (user_db.UserImage, error) {
			newMainImage.IsMain = params.IsMain

			return newMainImage, nil
		}).Times(1)

		userRepo.EXPECT().UpdateUserImage(ctx, user_db.UpdateUserImageParams{
			ID:     oldMainImageId,
			IsMain: false,
		}).Return(user_db.UserImage{}, nil).Times(1)

		userRepo.EXPECT().UpdateUserMainImage(ctx, user_db.UpdateUserMainImageParams{
			ID:            userId,
			MainImageUrl:  newMainImage.ImageUrl,
			MainImagePath: newMainImage.ImagePath,
		}).Return(user_db.User{}, nil).Times(1)

		assert.NotPanics(t, func() {
			resp := userSvc.SetMainImage(ctx, userId, newMainImage.ID)
			assert.Equal(t, newMainImage.ID, resp.ID)
			assert.Equal(t, true, resp.IsMain)
		})
	})

	t.Run("User not found (status code 404)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(user_db.FindUserWithImagesRow{}, errors.New(NOT_FOUND)).Times(1)

		userRepo.EXPECT().UpdateUserImage(ctx, gomock.Any()).Times(0)
		userRepo.EXPECT().UpdateUserImage(ctx, gomock.Any()).Times(0)
		userRepo.EXPECT().UpdateUserMainImage(ctx, gomock.Any()).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|user not found", NOT_FOUND),
			StatusCode: 404,
		}, func() { userSvc.SetMainImage(ctx, userId, uuid.New()) })
	})

	t.Run("Can't set the same main image (status code 400)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		userImages, mainImageId := createUserWithImages(userId, true)

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(userImages, nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|you can't set the same main image",
			StatusCode: 400,
		}, func() {
			userSvc.SetMainImage(ctx, userId, mainImageId)
		})
	})

	t.Run("Image not found (status code 404)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		userImages, _ := createUserWithImages(userId, true)

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(userImages, nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|image not found",
			StatusCode: 404,
		}, func() {
			userSvc.SetMainImage(ctx, userId, uuid.New())
		})
	})

	t.Run("Failed updating user main image (status code 422)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		userImages, oldMainImageId := createUserWithImages(userId, true)
		images := []user_db.UserImage{}
		err := json.Unmarshal(userImages.Images, &images)

		assert.NoError(t, err)
		newMainImage := images[1]

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(userImages, nil).Times(1)

		userRepo.EXPECT().UpdateUserImage(ctx, user_db.UpdateUserImageParams{
			ID:     oldMainImageId,
			IsMain: false,
		}).Return(user_db.UserImage{}, nil).MinTimes(1)
		userRepo.EXPECT().UpdateUserImage(ctx, user_db.UpdateUserImageParams{
			ID:     newMainImage.ID,
			IsMain: true,
		}).Return(user_db.UserImage{}, nil).MinTimes(1)
		userRepo.EXPECT().UpdateUserMainImage(ctx, user_db.UpdateUserMainImageParams{
			ID:            userId,
			MainImageUrl:  newMainImage.ImageUrl,
			MainImagePath: newMainImage.ImagePath,
		}).Return(user_db.User{}, errors.New(UNPROCESSABLE_ENTITY)).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when set the main image", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.SetMainImage(ctx, userId, newMainImage.ID)
		})
	})

	t.Run("status code 422 (failed updating user image)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		userImages, oldMainImageId := createUserWithImages(userId, true)
		images := []user_db.UserImage{}
		err := json.Unmarshal(userImages.Images, &images)

		assert.NoError(t, err)
		newMainImage := images[1]

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(userImages, nil).Times(1)

		userRepo.EXPECT().UpdateUserImage(ctx, user_db.UpdateUserImageParams{
			ID:     oldMainImageId,
			IsMain: false,
		}).Return(user_db.UserImage{}, nil).Times(1)
		userRepo.EXPECT().UpdateUserImage(ctx, user_db.UpdateUserImageParams{
			ID:     newMainImage.ID,
			IsMain: true,
		}).Return(user_db.UserImage{}, errors.New(UNPROCESSABLE_ENTITY)).Times(1)
		userRepo.EXPECT().UpdateUserMainImage(ctx, user_db.UpdateUserMainImageParams{
			ID:            userId,
			MainImageUrl:  newMainImage.ImageUrl,
			MainImagePath: newMainImage.ImagePath,
		}).Return(user_db.User{}, nil).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when set the main image", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.SetMainImage(ctx, userId, newMainImage.ID)
		})
	})
}

func TestDeleteImage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	userSvc, userRepo, fileSvc, _, _ := initUserSvc(ctrl, config)

	t.Run("Success Request", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		_, imageId := createUserWithImages(userId, false)
		path := fmt.Sprintf("users/%s/%s", userId, IMAGE_NAME)
		userRepo.EXPECT().FindUserImageById(ctx, imageId).Return(user_db.UserImage{
			ID:        imageId,
			UserID:    userId,
			IsMain:    false,
			ImagePath: path,
		}, nil).Times(1)

		fileSvc.EXPECT().DeleteFile(ctx, config.S3PrivateBucketName, path).
			Return(nil).Times(1)

		userRepo.EXPECT().DeleteUserImage(ctx, imageId).Return(nil).Times(1)

		assert.NotPanics(t, func() {
			userSvc.DeleteImage(ctx, userId, imageId)
		})
	})

	t.Run("Image not found (status code 404)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		imageId := uuid.New()

		userRepo.EXPECT().FindUserImageById(ctx, imageId).Return(user_db.UserImage{}, errors.New(NOT_FOUND)).Times(1)

		fileSvc.EXPECT().DeleteFile(ctx, gomock.Any(), gomock.Any()).
			Return(nil).Times(0)

		userRepo.EXPECT().DeleteUserImage(ctx, gomock.Any()).Return(nil).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|image not found", NOT_FOUND),
			StatusCode: 404,
		}, func() {
			userSvc.DeleteImage(ctx, userId, imageId)
		})
	})

	t.Run("Can't delete the main image (status code 400)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		_, mainImageId := createUserWithImages(userId, true)

		userRepo.EXPECT().FindUserImageById(ctx, mainImageId).Return(user_db.UserImage{
			ID:     mainImageId,
			UserID: userId,
			IsMain: true,
		}, nil).Times(1)

		fileSvc.EXPECT().DeleteFile(ctx, gomock.Any(), gomock.Any()).
			Return(nil).Times(0)

		userRepo.EXPECT().DeleteUserImage(ctx, gomock.Any()).Return(nil).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|you can't delete the main image",
			StatusCode: 400,
		}, func() {
			userSvc.DeleteImage(ctx, userId, mainImageId)
		})
	})

	t.Run("Not authorize (status code 403)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		_, mainImageId := createUserWithImages(userId, true)

		userRepo.EXPECT().FindUserImageById(ctx, mainImageId).Return(user_db.UserImage{
			ID:     mainImageId,
			UserID: uuid.New(),
			IsMain: false,
		}, nil).Times(1)

		fileSvc.EXPECT().DeleteFile(ctx, gomock.Any(), gomock.Any()).
			Return(nil).Times(0)

		userRepo.EXPECT().DeleteUserImage(ctx, gomock.Any()).Return(nil).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    "|not authorize to perform this operation",
			StatusCode: 403,
		}, func() {
			userSvc.DeleteImage(ctx, userId, mainImageId)
		})
	})

	t.Run("Failed deleting image (status code 422)", func(t *testing.T) {
		userId := USER_ID
		setupAndMockTx(t, DB, userRepo)

		_, imageId := createUserWithImages(userId, false)
		path := fmt.Sprintf("users/%s/%s", userId, IMAGE_NAME)
		userRepo.EXPECT().FindUserImageById(ctx, imageId).Return(user_db.UserImage{
			ID:        imageId,
			UserID:    userId,
			IsMain:    false,
			ImagePath: path,
		}, nil).Times(1)

		fileSvc.EXPECT().DeleteFile(ctx, config.S3PrivateBucketName, path).
			Return(errors.New(UNPROCESSABLE_ENTITY)).Times(1)

		userRepo.EXPECT().DeleteUserImage(ctx, imageId).Return(nil).Times(1)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when deleting image", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.DeleteImage(ctx, userId, imageId)
		})
	})
}

func TestGetUsers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	userSvc, userRepo, fileSvc, _, cacheSvc := initUserSvc(ctrl, config)
	defer shrd_utils.DeferCheck(cacheSvc.CloseClient)

	t.Run("Failed when finding user (status code 400)", func(t *testing.T) {
		reqParams := createPaginationReq()
		findUsersParams := createFindUserParams(reqParams.SearchValue)

		getUsersPaginationCountParams := createPaginationCountParams(reqParams.SearchValue)

		userRepo.EXPECT().FindUsers(ctx, findUsersParams).
			Return([]user_db.User{}, errors.New(BAD_REQUEST)).Times(1)

		userRepo.EXPECT().GetUsersPaginationCount(ctx, getUsersPaginationCountParams).
			Return(int64(0), nil).Times(1)

		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when finding user", BAD_REQUEST),
			StatusCode: 400,
		}, func() {
			userSvc.GetUsers(ctx, reqParams)
		})
	})

	t.Run("Failed when getting pre sign url (status code 422)", func(t *testing.T) {
		reqParams := createPaginationReq()
		findUsersParams := createFindUserParams(reqParams.SearchValue)

		getUsersPaginationCountParams := createPaginationCountParams(reqParams.SearchValue)

		userRepo.EXPECT().FindUsers(ctx, findUsersParams).
			Return(createUsersActive(), nil).Times(1)
		userRepo.EXPECT().GetUsersPaginationCount(ctx, getUsersPaginationCountParams).
			Return(int64(12), nil).Times(1)
		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			Return("", errors.New(UNPROCESSABLE_ENTITY)).Times(10)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when getting pre signed url", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.GetUsers(ctx, reqParams)
		})
	})

	t.Run("Success Request", func(t *testing.T) {
		reqParams := createPaginationReq()
		findUsersParams := createFindUserParams(reqParams.SearchValue)

		getUsersPaginationCountParams := createPaginationCountParams(reqParams.SearchValue)

		userRepo.EXPECT().FindUsers(ctx, findUsersParams).
			Return(createUsersActive(), nil).Times(1)

		userRepo.EXPECT().GetUsersPaginationCount(ctx, getUsersPaginationCountParams).
			Return(int64(12), nil).Times(1)

		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			DoAndReturn(func(_ interface{}, path string) (string, error) {
				pathSlice := strings.Split(path, "/")
				assert.Equal(t, IMAGE_NAME, pathSlice[2])
				assert.Contains(t, fmt.Sprintf("users/userId/%s", pathSlice[2]), path)

				return buildUploadUrl(pathSlice[2]), nil
			}).Times(10)

		assert.NotPanics(t, func() {
			resp := userSvc.GetUsers(ctx, reqParams)

			assert.Equal(t, 10, len(resp.Users))
			assert.Equal(t, -1, resp.Pagination.Prev.Page)
			assert.Equal(t, 2, resp.Pagination.Next.Page)
			assert.Equal(t, true, resp.Pagination.IsLoadMore)
		})
	})

	t.Run("Success Request (get data from cache)", func(t *testing.T) {
		reqParams := createPaginationReq()
		findUsersParams := createFindUserParams(reqParams.SearchValue)

		getUsersPaginationCountParams := createPaginationCountParams(reqParams.SearchValue)

		userRepo.EXPECT().FindUsers(ctx, findUsersParams).
			Return(createUsersActive(), nil).Times(0)

		userRepo.EXPECT().GetUsersPaginationCount(ctx, getUsersPaginationCountParams).
			Return(int64(12), nil).Times(0)

		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			DoAndReturn(func(_ interface{}, path string) (string, error) {
				pathSlice := strings.Split(path, "/")
				assert.Equal(t, IMAGE_NAME, pathSlice[2])
				assert.Contains(t, fmt.Sprintf("users/userId/%s", pathSlice[2]), path)

				return buildUploadUrl(pathSlice[2]), nil
			}).Times(0)

		assert.NotPanics(t, func() {
			resp := userSvc.GetUsers(ctx, reqParams)
			cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)

			assert.Equal(t, 10, len(resp.Users))
			assert.Equal(t, -1, resp.Pagination.Prev.Page)
			assert.Equal(t, 2, resp.Pagination.Next.Page)
			assert.Equal(t, true, resp.Pagination.IsLoadMore)
		})
	})
}

func TestGetUserImages(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	userSvc, userRepo, fileSvc, _, cacheSvc := initUserSvc(ctrl, config)
	defer shrd_utils.DeferCheck(cacheSvc.CloseClient)

	t.Run("Failed when finding user images (status code 400)", func(t *testing.T) {
		userId := USER_ID

		userRepo.EXPECT().FindUserImagesByUserId(ctx, userId).
			Return([]user_db.UserImage{}, errors.New(BAD_REQUEST)).Times(1)

		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when finding user images", BAD_REQUEST),
			StatusCode: 400,
		}, func() {
			userSvc.GetUserImages(ctx, userId)
		})
	})

	t.Run("Failed when getting pre signed url (status code 422)", func(t *testing.T) {
		userid := USER_ID

		userRepo.EXPECT().FindUserImagesByUserId(ctx, userid).
			Return(createUserImages(userid), nil).Times(1)

		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			Return("", errors.New(UNPROCESSABLE_ENTITY)).Times(7)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when getting pre signed url", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.GetUserImages(ctx, userid)
		})
	})

	t.Run("Success Request", func(t *testing.T) {
		userId := USER_ID

		userRepo.EXPECT().FindUserImagesByUserId(ctx, userId).
			Return(createUserImages(userId), nil).Times(1)

		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			DoAndReturn(func(_ interface{}, path string) (string, error) {
				pathSlice := strings.Split(path, "/")
				assert.Equal(t, IMAGE_NAME, pathSlice[2])
				assert.Equal(t, fmt.Sprintf("users/%s/%s", pathSlice[1], pathSlice[2]), path)

				return buildUploadUrl(pathSlice[2]), nil
			}).Times(7)

		assert.NotPanics(t, func() {
			resp := userSvc.GetUserImages(ctx, userId)
			assert.Equal(t, 7, len(resp))
			assert.Equal(t, true, resp[2].IsMain)
		})
	})

	t.Run("Success request (get data from cache)", func(t *testing.T) {
		userId := USER_ID

		userRepo.EXPECT().FindUserImagesByUserId(ctx, userId).
			Return(createUserImages(userId), nil).Times(0)

		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			DoAndReturn(func(_ interface{}, path string) (string, error) {
				pathSlice := strings.Split(path, "/")
				assert.Equal(t, IMAGE_NAME, pathSlice[2])
				assert.Equal(t, fmt.Sprintf("users/%s/%s", pathSlice[1], pathSlice[2]), path)

				return buildUploadUrl(pathSlice[2]), nil
			}).Times(0)

		assert.NotPanics(t, func() {
			resp := userSvc.GetUserImages(ctx, userId)
			cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
			assert.Equal(t, 7, len(resp))
			assert.Equal(t, true, resp[2].IsMain)
		})
	})
}

func TestGetUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	config, DB := LoadConfigAndSetUpDb()
	defer DB.Close()

	userSvc, userRepo, fileSvc, _, cacheSvc := initUserSvc(ctrl, config)
	defer shrd_utils.DeferCheck(cacheSvc.CloseClient)

	t.Run("User not found (status code 404)", func(t *testing.T) {
		userId := USER_ID

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(user_db.FindUserWithImagesRow{}, errors.New(NOT_FOUND)).Times(1)
		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).Times(0)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|user not found", NOT_FOUND),
			StatusCode: 404,
		}, func() {
			userSvc.GetUser(ctx, userId)
		})
	})

	t.Run("Failed when getting pre signed url (status code 422)", func(t *testing.T) {
		userId := USER_ID

		userImages, _ := createUserWithImages(userId, true)
		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(userImages, nil).Times(1)
		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			Return("", errors.New(UNPROCESSABLE_ENTITY)).Times(3)

		assert.PanicsWithValue(t, shrd_utils.AppError{
			Message:    fmt.Sprintf("%s|failed when getting pre signed url", UNPROCESSABLE_ENTITY),
			StatusCode: 422,
		}, func() {
			userSvc.GetUser(ctx, userId)
		})
	})

	t.Run("Success Request", func(t *testing.T) {
		userId := USER_ID

		userImages, _ := createUserWithImages(userId, true)

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(userImages, nil).Times(1)
		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			DoAndReturn(func(_ interface{}, path string) (string, error) {
				assert.Contains(t, path, fmt.Sprintf("users/%s", userId))
				pathSlice := strings.Split(path, "/")

				return buildUploadUrl(pathSlice[2]), nil
			}).Times(3)

		assert.NotPanics(t, func() {
			user := userSvc.GetUser(ctx, userId)
			assert.Equal(t, 3, len(user.Images))
		})
	})

	t.Run("Success request (get data from cache)", func(t *testing.T) {
		userId := USER_ID

		userImages, _ := createUserWithImages(userId, true)

		userRepo.EXPECT().FindUserWithImages(ctx, userId).
			Return(userImages, nil).Times(0)
		fileSvc.EXPECT().GetPreSignUrl(ctx, gomock.Any()).
			DoAndReturn(func(_ interface{}, path string) (string, error) {
				assert.Contains(t, path, fmt.Sprintf("users/%s", userId))
				pathSlice := strings.Split(path, "/")

				return buildUploadUrl(pathSlice[2]), nil
			}).Times(0)

		assert.NotPanics(t, func() {
			user := userSvc.GetUser(ctx, userId)
			cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
			assert.Equal(t, 3, len(user.Images))
		})
	})
}
