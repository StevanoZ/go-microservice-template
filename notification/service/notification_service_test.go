package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"cloud.google.com/go/pubsub"
	querier "github.com/StevanoZ/dv-notification/db/repository"
	mock_querier "github.com/StevanoZ/dv-notification/db/repository/mock"
	"github.com/google/uuid"

	"github.com/StevanoZ/dv-shared/message"
	shrd_mock_svc "github.com/StevanoZ/dv-shared/service/mock"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	EMAIL_TOPIC      = message.EMAIL_TOPIC
	USER_TOPIC       = message.USER_TOPIC
	USER_IMAGE_TOPIC = message.USER_IMAGE_TOPIC
	SERVICE_NAME     = "dv-notification"
	MESSAGE_ID       = "123"
	FAILED           = "FAILED"
	UNKNOWN_KEY      = "UNKNOWN"
	IMAGE_URL        = "https://test-image.com"
	IMAGE_PATH       = "images/testing"
)

var errMsg = errors.New("failed")
var attempt = 5
var CONFIG = shrd_utils.LoadBaseConfig("../app", "test")

func initNotificationSvc(t *testing.T, ctrl *gomock.Controller) (
	NotificationSvc,
	*mock_querier.MockRepository,
	*shrd_mock_svc.MockPubSubClient,
	*shrd_mock_svc.MockEmailSvc,
) {
	config := shrd_utils.LoadBaseConfig("../app", "test")
	repository := mock_querier.NewMockRepository(ctrl)
	pubSubClient := shrd_mock_svc.NewMockPubSubClient(ctrl)
	emailSvc := shrd_mock_svc.NewMockEmailSvc(ctrl)

	return NewNotificationSvc(config, repository, pubSubClient, emailSvc), repository, pubSubClient, emailSvc
}

func buildTopicName(topic string) string {
	return fmt.Sprintf("%s_%s", SERVICE_NAME, topic)
}

func setupPullMsgMock(
	ctx context.Context,
	topic string,
	pubsubClient *shrd_mock_svc.MockPubSubClient,
	cb func(_ interface{}, _ interface{}, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error,
	isFailed ...bool) {
	isSuccess := true
	if len(isFailed) > 0 {
		isSuccess = !isFailed[0]
	}
	if isSuccess {
		pubsubClient.EXPECT().CreateTopicIfNotExists(ctx, topic).
			Return(&pubsub.Topic{}, nil).Times(1)
		pubsubClient.EXPECT().PullMessages(ctx, buildTopicName(topic), gomock.AssignableToTypeOf(&pubsub.Topic{}), gomock.Any()).
			DoAndReturn(cb).Times(1)
	} else {
		pubsubClient.EXPECT().CreateTopicIfNotExists(ctx, topic).
			Return(nil, errMsg).Times(1)
		pubsubClient.EXPECT().PullMessages(ctx, buildTopicName(topic),
			gomock.AssignableToTypeOf(&pubsub.Topic{}), gomock.Any()).Times(0)
	}
}

func setupAndMockTx(t *testing.T, repo *mock_querier.MockRepository) {
	config := shrd_utils.LoadBaseConfig("../app", "test")
	DB := shrd_utils.ConnectDB(config.DBDriver, config.DBSource)

	tx, err := DB.BeginTx(context.Background(), nil)
	assert.NoError(t, err)

	repo.EXPECT().GetDB().Return(DB).Times(1)
	repo.EXPECT().WithTx(gomock.AssignableToTypeOf(tx)).Return(repo).Times(1)
}

func marshalData(t *testing.T, data any) []byte {
	payload, err := json.Marshal(data)
	assert.NoError(t, err)

	return payload
}

func buildPubsubMsg(orderingKey string, data []byte, attempt ...int) *pubsub.Message {
	if len(attempt) > 0 {
		return &pubsub.Message{
			ID:              MESSAGE_ID,
			OrderingKey:     orderingKey,
			Data:            data,
			DeliveryAttempt: &attempt[0],
		}
	}

	return &pubsub.Message{
		ID:          MESSAGE_ID,
		OrderingKey: orderingKey,
		Data:        data,
	}
}

func buildJsonUnMarshalErr(payloadType string) error {
	return fmt.Errorf("failed when unmarshall message, Error: json: cannot unmarshal string into Go value of type message.%s", payloadType)
}

func TestListenForEmailTopic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	notificationSvc, repository, pubsubClient, emailSvc := initNotificationSvc(t, ctrl)
	payload := message.OtpPayload{
		Email:   shrd_utils.RandomEmail(),
		OtpCode: int(shrd_utils.RandomInt(0, 999999)),
	}
	errMsgParams := querier.CreateErrorMessageParams{
		ServiceName: CONFIG.ServiceName,
		PayloadName: otpPayload,
		Topic:       message.EMAIL_TOPIC,
		OrderingKey: message.SEND_OTP_KEY,
		MessageID:   MESSAGE_ID,
		PayloadData: string(string(marshalData(t, payload))),
		Description: message.BuildDescErrorMsg(failedSendEmail, errMsg),
	}

	t.Run("Successfully send email", func(t *testing.T) {
		setupPullMsgMock(ctx, message.EMAIL_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
			data := marshalData(t, payload)
			msg := buildPubsubMsg(message.SEND_OTP_KEY, data)

			cb(ctx, msg)
			return nil
		})

		repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
			Times(0)
		emailSvc.EXPECT().SendVerifyOtp(ctx, payload).Times(1)

		err := notificationSvc.ListenForEmailTopic(ctx)
		assert.NoError(t, err)
	})

	t.Run("Failed sending email and save data to DB", func(t *testing.T) {
		setupPullMsgMock(ctx, message.EMAIL_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
			data := marshalData(t, payload)

			msg := buildPubsubMsg(message.SEND_OTP_KEY, data, attempt)
			cb(ctx, msg)
			return nil
		})

		repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
			Times(1)
		emailSvc.EXPECT().SendVerifyOtp(ctx, payload).Return(errMsg).Times(1)
		err := notificationSvc.ListenForEmailTopic(ctx)
		assert.NoError(t, err)
	})

	t.Run("Failed sending email (unmarshal json) and save data to DB", func(t *testing.T) {
		setupPullMsgMock(ctx, message.EMAIL_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
			data := marshalData(t, FAILED)
			msg := buildPubsubMsg(message.SEND_OTP_KEY, data, attempt)

			cb(ctx, msg)
			return nil
		})

		errMsgParams.Description = buildJsonUnMarshalErr("OtpPayload").Error()
		errMsgParams.PayloadData = string(marshalData(t, FAILED))
		repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
			Times(1)
		emailSvc.EXPECT().SendVerifyOtp(ctx, payload).Times(0)
		err := notificationSvc.ListenForEmailTopic(ctx)
		assert.NoError(t, err)
	})

	t.Run("Not consume the message (no matches key)", func(t *testing.T) {
		setupPullMsgMock(ctx, message.EMAIL_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
			data := marshalData(t, payload)
			msg := buildPubsubMsg(UNKNOWN_KEY, data)
			cb(ctx, msg)
			return nil
		})

		emailSvc.EXPECT().SendVerifyOtp(ctx, payload).Times(0)
		err := notificationSvc.ListenForEmailTopic(ctx)
		assert.NoError(t, err)
	})

	t.Run("Failed sending email (create topic)", func(t *testing.T) {
		setupPullMsgMock(ctx, message.EMAIL_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
			return nil
		}, true)
		emailSvc.EXPECT().SendVerifyOtp(ctx, payload).Times(0)

		err := notificationSvc.ListenForEmailTopic(ctx)
		assert.Error(t, err)
	})
}

func TestListenForUserTopic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	notificationSvc, repository, pubsubClient, _ := initNotificationSvc(t, ctrl)

	t.Run("Created Key", func(t *testing.T) {
		payload := message.CreatedUserPayload{
			ID:        uuid.New(),
			Email:     shrd_utils.RandomEmail(),
			Username:  shrd_utils.RandomUsername(),
			Password:  shrd_utils.RandomString(12),
			OtpCode:   shrd_utils.RandomInt(0, 999999),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		params := querier.CreateUserParams{
			ID:        payload.ID,
			Email:     payload.Email,
			Username:  payload.Username,
			Password:  payload.Password,
			OtpCode:   payload.OtpCode,
			CreatedAt: payload.CreatedAt,
			UpdatedAt: payload.UpdatedAt,
		}
		errMsgParams := querier.CreateErrorMessageParams{
			ServiceName: CONFIG.ServiceName,
			Topic:       message.USER_TOPIC,
			OrderingKey: message.CREATED_KEY,
			MessageID:   MESSAGE_ID,
			PayloadName: createUserPayload,
			PayloadData: string(marshalData(t, params)),
			Description: buildJsonUnMarshalErr("CreatedUserPayload").Error(),
		}

		t.Run("Successfully created user", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.CREATED_KEY, data)

				cb(ctx, msg)
				return nil
			})

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().CreateUser(ctx, params).Return(querier.User{}, nil).Times(1)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed creating user (unmarshal json)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, FAILED)
				msg := buildPubsubMsg(message.CREATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, FAILED))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().CreateUser(ctx, params).Return(querier.User{}, nil).
				Times(0)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed creating user (not save to DB)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.CREATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.Description = message.BuildDescErrorMsg(failedCreateUser, errMsg)
			errMsgParams.PayloadData = string(marshalData(t, payload))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().CreateUser(ctx, params).Return(querier.User{}, errMsg).
				Times(1)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})
	})

	t.Run("Updated Key", func(t *testing.T) {
		payload := message.UpdatedUserPayload{
			ID:          uuid.New(),
			Username:    shrd_utils.RandomUsername(),
			Password:    shrd_utils.RandomString(12),
			OtpCode:     shrd_utils.RandomInt(0, 999999),
			AttemptLeft: 3,
			PhoneNumber: "08219998743",
			Status:      "active",
			UpdatedAt:   time.Now().UTC(),
		}
		params := querier.UpdateUserParams{
			ID:          payload.ID,
			Username:    payload.Username,
			Password:    payload.Password,
			OtpCode:     payload.OtpCode,
			PhoneNumber: payload.PhoneNumber,
			AttemptLeft: payload.AttemptLeft,
			Status:      payload.Status,
			UpdatedAt:   payload.UpdatedAt,
		}
		errMsgParams := querier.CreateErrorMessageParams{
			ServiceName: CONFIG.ServiceName,
			Topic:       message.USER_TOPIC,
			OrderingKey: message.UPDATED_KEY,
			MessageID:   MESSAGE_ID,
			PayloadName: updateUserPayload,
			PayloadData: string(marshalData(t, payload)),
			Description: buildJsonUnMarshalErr("UpdatedUserPayload").Error(),
		}

		t.Run("Successfully updated user", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_KEY, data)

				cb(ctx, msg)
				return nil
			})

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, nil).
				Times(1)
			repository.EXPECT().UpdateUser(ctx, params).Return(querier.User{}, nil).
				Times(1)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating user (unmarshal json)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, FAILED)
				msg := buildPubsubMsg(message.UPDATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, FAILED))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, nil).
				Times(0)
			repository.EXPECT().UpdateUser(ctx, params).Return(querier.User{}, nil).
				Times(0)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating user (user not found)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.Description = message.BuildDescErrorMsg("user not found", errMsg)
			errMsgParams.PayloadData = string(marshalData(t, payload))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, errMsg).
				Times(1)
			repository.EXPECT().UpdateUser(ctx, params).Return(querier.User{}, nil).
				Times(0)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating user (not save to DB)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.Description = message.BuildDescErrorMsg("failed when updating user", errMsg)
			errMsgParams.PayloadData = string(marshalData(t, payload))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, nil).
				Times(1)
			repository.EXPECT().UpdateUser(ctx, params).Return(querier.User{}, errMsg).
				Times(1)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})
	})

	t.Run("Updated user main image key", func(t *testing.T) {
		payload := message.UpdatedUserMainImagePayload{
			ID:            uuid.New(),
			MainImageUrl:  IMAGE_URL,
			MainImagePath: IMAGE_PATH,
			UpdatedAt:     time.Now().UTC(),
		}
		params := querier.UpdateUserMainImageParams{
			ID:            payload.ID,
			MainImageUrl:  payload.MainImageUrl,
			MainImagePath: payload.MainImagePath,
			UpdatedAt:     payload.UpdatedAt,
		}
		errMsgParams := querier.CreateErrorMessageParams{
			ServiceName: CONFIG.ServiceName,
			Topic:       message.USER_TOPIC,
			OrderingKey: message.UPDATED_USER_MAIN_IMAGE_KEY,
			MessageID:   MESSAGE_ID,
			Description: buildJsonUnMarshalErr("UpdatedUserMainImagePayload").Error(),
			PayloadName: updatedUserMainImagePayload,
			PayloadData: string(marshalData(t, payload)),
		}

		t.Run("Successfully updated user main image", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_USER_MAIN_IMAGE_KEY, data)

				cb(ctx, msg)
				return nil
			})

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, nil).
				Times(1)
			repository.EXPECT().UpdateUserMainImage(ctx, params).Return(querier.User{}, nil).
				Times(1)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating user main image (unmarshal json)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, FAILED)
				msg := buildPubsubMsg(message.UPDATED_USER_MAIN_IMAGE_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, FAILED))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, nil).
				Times(0)
			repository.EXPECT().UpdateUserMainImage(ctx, params).Return(querier.User{}, nil).
				Times(0)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating user main image (user not found)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_USER_MAIN_IMAGE_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, payload))
			errMsgParams.Description = message.BuildDescErrorMsg(failedUserNotFound, errMsg)
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, errMsg).
				Times(1)
			repository.EXPECT().UpdateUserMainImage(ctx, params).Return(querier.User{}, nil).
				Times(0)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating user main image (not save to DB)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_USER_MAIN_IMAGE_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, payload))
			errMsgParams.Description = message.BuildDescErrorMsg(failedUpdateUserMainImage, errMsg)
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, nil).
				Times(1)
			repository.EXPECT().UpdateUserMainImage(ctx, params).Return(querier.User{}, errMsg).
				Times(1)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed when trying to create topic", func(t *testing.T) {
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				return nil
			}, true)

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, nil).
				Times(0)
			repository.EXPECT().UpdateUserMainImage(ctx, params).Return(querier.User{}, nil).
				Times(0)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.Error(t, err)
		})

		t.Run("Not consume the message (no matches key)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(UNKNOWN_KEY, data)

				cb(ctx, msg)
				return nil
			})

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().FindUserByIdForUpdate(ctx, payload.ID).Return(querier.User{}, nil).
				Times(0)
			repository.EXPECT().UpdateUserMainImage(ctx, params).Return(querier.User{}, nil).
				Times(0)
			err := notificationSvc.ListenForUserTopic(ctx)
			assert.NoError(t, err)
		})
	})
}

func TestListenForUserImageTopic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	notificationSvc, repository, pubsubClient, _ := initNotificationSvc(t, ctrl)

	t.Run("Created Key", func(t *testing.T) {
		payload := []message.CreatedUserImagePayload{
			{ID: uuid.New(),
				ImageUrl:  IMAGE_URL,
				ImagePath: IMAGE_PATH,
				UserID:    uuid.New(),
				IsMain:    false,
				UpdatedAt: time.Now().UTC(),
				CreatedAt: time.Now().UTC(),
			},
			{ID: uuid.New(),
				ImageUrl:  IMAGE_URL,
				ImagePath: IMAGE_PATH,
				UserID:    uuid.New(),
				IsMain:    true,
				UpdatedAt: time.Now().UTC(),
				CreatedAt: time.Now().UTC(),
			},
			{ID: uuid.New(),
				ImageUrl:  IMAGE_URL,
				ImagePath: IMAGE_PATH,
				UserID:    uuid.New(),
				IsMain:    false,
				UpdatedAt: time.Now().UTC(),
				CreatedAt: time.Now().UTC(),
			},
		}
		params := []querier.CreateUserImageParams{
			{ID: payload[0].ID,
				ImageUrl:  payload[0].ImageUrl,
				ImagePath: payload[0].ImagePath,
				UserID:    payload[0].UserID,
				IsMain:    payload[0].IsMain,
				UpdatedAt: payload[0].UpdatedAt,
				CreatedAt: payload[0].CreatedAt,
			},
			{ID: payload[1].ID,
				ImageUrl:  payload[1].ImageUrl,
				ImagePath: payload[1].ImagePath,
				UserID:    payload[1].UserID,
				IsMain:    payload[1].IsMain,
				UpdatedAt: payload[1].UpdatedAt,
				CreatedAt: payload[1].CreatedAt,
			},
			{ID: payload[2].ID,
				ImageUrl:  payload[2].ImageUrl,
				ImagePath: payload[2].ImagePath,
				UserID:    payload[2].UserID,
				IsMain:    payload[2].IsMain,
				UpdatedAt: payload[2].UpdatedAt,
				CreatedAt: payload[2].CreatedAt,
			},
		}
		errMsgParams := querier.CreateErrorMessageParams{
			ServiceName: CONFIG.ServiceName,
			Topic:       message.USER_IMAGE_TOPIC,
			OrderingKey: message.CREATED_KEY,
			MessageID:   MESSAGE_ID,
			PayloadName: createdUserImagePayload,
			PayloadData: string(marshalData(t, payload)),
			Description: "failed when unmarshall message, Error: json: cannot unmarshal string into Go value of type []message.CreatedUserImagePayload",
		}

		t.Run("Successfully created image", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.CREATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().CreateUserImage(ctx, gomock.AssignableToTypeOf(querier.CreateUserImageParams{})).Return(querier.UserImage{}, nil).
				Times(3)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed creating image (unmarshal json)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, FAILED)
				msg := buildPubsubMsg(message.CREATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, FAILED))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().CreateUserImage(ctx, params).Return(querier.UserImage{}, nil).
				Times(0)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed creating image (not save to DB)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.CREATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, payload))
			errMsgParams.Description = message.BuildDescErrorMsg(failedCreateUserImage, errMsg)
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().CreateUserImage(ctx, gomock.AssignableToTypeOf(querier.CreateUserImageParams{})).Return(querier.UserImage{}, errMsg).
				Times(3)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})
	})

	t.Run("Updated Key", func(t *testing.T) {
		payload := message.UpdatedUserImagePayload{
			ID:        uuid.New(),
			IsMain:    true,
			UpdatedAt: time.Now().UTC(),
		}
		params := querier.UpdateUserImageParams{
			ID:        payload.ID,
			IsMain:    payload.IsMain,
			UpdatedAt: payload.UpdatedAt,
		}
		errMsgParams := querier.CreateErrorMessageParams{
			ServiceName: CONFIG.ServiceName,
			Topic:       message.USER_IMAGE_TOPIC,
			OrderingKey: message.UPDATED_KEY,
			MessageID:   MESSAGE_ID,
			PayloadName: updatedUserImagePayload,
			PayloadData: string(marshalData(t, payload)),
			Description: buildJsonUnMarshalErr("UpdatedUserImagePayload").Error(),
		}

		t.Run("Successfully updated image", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(1)
			repository.EXPECT().FindUserMainImageByUserIdForUpdate(ctx, payload.UserID).Return(querier.UserImage{}, nil).
				Times(1)
			repository.EXPECT().UpdateUserImage(ctx, gomock.AssignableToTypeOf(querier.UpdateUserImageParams{})).Return(querier.UserImage{}, nil).
				Times(2)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating image (unmarshal json)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, FAILED)
				msg := buildPubsubMsg(message.UPDATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, FAILED))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(0)
			repository.EXPECT().UpdateUserImage(ctx, params).Return(querier.UserImage{}, nil).
				Times(0)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating image (user image not found)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, payload))
			errMsgParams.Description = message.BuildDescErrorMsg(failedUserImageNotFound, errMsg)
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, errMsg).
				Times(1)

			// SHOULD NOT CALL THIS
			repository.EXPECT().FindUserMainImageByUserIdForUpdate(ctx, payload.UserID).Return(querier.UserImage{}, nil).
				Times(0)
			repository.EXPECT().UpdateUserImage(ctx, params).Return(querier.UserImage{}, nil).
				Times(0)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating image (user old main image not found)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, payload))
			errMsgParams.Description = message.BuildDescErrorMsg(failedUserImageNotFound, errMsg)
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(1)
			repository.EXPECT().FindUserMainImageByUserIdForUpdate(ctx, payload.UserID).Return(querier.UserImage{}, errMsg).
				Times(1)

			// SHOULD NOT CALL THIS
			repository.EXPECT().UpdateUserImage(ctx, params).Return(querier.UserImage{}, nil).
				Times(0)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed updating image (not save to DB)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.UPDATED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, payload))
			errMsgParams.Description = message.BuildDescErrorMsg(failedUpdateUserImage, errMsg)
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(1)
			repository.EXPECT().FindUserMainImageByUserIdForUpdate(ctx, payload.UserID).Return(querier.UserImage{}, nil).
				Times(1)
			repository.EXPECT().UpdateUserImage(ctx, gomock.AssignableToTypeOf(querier.UpdateUserImageParams{})).Return(querier.UserImage{}, errMsg).
				Times(2)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})
	})

	t.Run("Deleted Key", func(t *testing.T) {
		payload := message.DeletedUserImagePayload{
			ID: uuid.New(),
		}
		errMsgParams := querier.CreateErrorMessageParams{
			ServiceName: CONFIG.ServiceName,
			Topic:       message.USER_IMAGE_TOPIC,
			OrderingKey: message.DELETED_KEY,
			PayloadName: deletedUserImagePayload,
			MessageID:   MESSAGE_ID,
			PayloadData: string(marshalData(t, payload)),
			Description: buildJsonUnMarshalErr("DeletedUserImagePayload").Error(),
		}

		t.Run("Successfully deleted user image", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.DELETED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(1)
			repository.EXPECT().DeleteUserImage(ctx, payload.ID).Return(nil).Times(1)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed deleting user image (unmarshal json)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, FAILED)
				msg := buildPubsubMsg(message.DELETED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.PayloadData = string(marshalData(t, FAILED))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(0)
			repository.EXPECT().DeleteUserImage(ctx, payload.ID).Return(nil).
				Times(0)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed deleting user image (user image not found)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.DELETED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.Description = message.BuildDescErrorMsg(failedUserImageNotFound, errMsg)
			errMsgParams.PayloadData = string(marshalData(t, payload))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, errMsg).
				Times(1)
			repository.EXPECT().DeleteUserImage(ctx, payload.ID).Return(nil).Times(0)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed deleting user image (not save to DB)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.DELETED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			errMsgParams.Description = message.BuildDescErrorMsg(failedDeleteUserImage, errMsg)
			errMsgParams.PayloadData = string(marshalData(t, payload))
			repository.EXPECT().CreateErrorMessage(ctx, errMsgParams).Return(querier.ErrorMessage{}, nil).
				Times(1)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(1)
			repository.EXPECT().DeleteUserImage(ctx, payload.ID).Return(errMsg).Times(1)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})

		t.Run("Failed when trying to create topic", func(t *testing.T) {
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(message.DELETED_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			}, true)

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(0)
			repository.EXPECT().DeleteUserImage(ctx, payload.ID).Return(nil).Times(0)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.Error(t, err)
		})

		t.Run("Not consume the message (no matches key)", func(t *testing.T) {
			setupAndMockTx(t, repository)
			setupPullMsgMock(ctx, message.USER_IMAGE_TOPIC, pubsubClient, func(_, _, _ interface{}, cb func(ctx context.Context, msg *pubsub.Message)) error {
				data := marshalData(t, payload)
				msg := buildPubsubMsg(UNKNOWN_KEY, data, attempt)

				cb(ctx, msg)
				return nil
			})

			repository.EXPECT().CreateErrorMessage(ctx, gomock.Any()).Return(querier.ErrorMessage{}, nil).
				Times(0)
			repository.EXPECT().FindUserImageByIdForUpdate(ctx, payload.ID).Return(querier.UserImage{}, nil).
				Times(0)
			repository.EXPECT().DeleteUserImage(ctx, payload.ID).Return(nil).Times(0)

			err := notificationSvc.ListenForUserImageTopic(ctx)
			assert.NoError(t, err)
		})
	})
}
