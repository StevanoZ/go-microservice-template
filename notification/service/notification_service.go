package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"cloud.google.com/go/pubsub"
	querier "github.com/StevanoZ/dv-notification/db/repository"
	"github.com/StevanoZ/dv-shared/message"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"golang.org/x/sync/errgroup"
)

const (
	failedUnmarshalMsg        = "failed when unmarshall message"
	failedSendEmail           = "failed when sending email"
	failedCreateUser          = "failed when creating user"
	failedUpdateUser          = "failed when updating user"
	failedCreateUserImage     = "failed when creating user image"
	failedDeleteUserImage     = "failed when deleting user image"
	failedUpdateUserImage     = "failed when updating user image"
	failedUpdateUserMainImage = "failed when updating user main image"
	failedUserNotFound        = "user not found"
	failedUserImageNotFound   = "user image not found"
)

const (
	otpPayload                  = "OtpPayload"
	createUserPayload           = "CreatedUserPayload"
	updateUserPayload           = "UpdatedUserPayload"
	updatedUserMainImagePayload = "UpdatedUserMainImagePayload"
	createdUserImagePayload     = "CreatedUserImagePayload"
	updatedUserImagePayload     = "UpdatedUserImagePayload"
	deletedUserImagePayload     = "DeletedUserImagePayload"
)

const startedListening = "started listening topic: "

type NotificationSvc interface {
	ListenForEmailTopic(ctx context.Context) error
	ListenForUserTopic(ctx context.Context) error
	ListenForUserImageTopic(ctx context.Context) error
}

type NotificationSvcImpl struct {
	config       *shrd_utils.BaseConfig
	repository   querier.Repository
	emailSvc     shrd_service.EmailSvc
	pubSubClient shrd_service.PubSubClient
}

func NewNotificationSvc(
	config *shrd_utils.BaseConfig,
	repository querier.Repository,
	pubSubClient shrd_service.PubSubClient,
	emailSvc shrd_service.EmailSvc,
) NotificationSvc {
	return &NotificationSvcImpl{
		config:       config,
		repository:   repository,
		pubSubClient: pubSubClient,
		emailSvc:     emailSvc,
	}
}

func (s *NotificationSvcImpl) ListenForEmailTopic(ctx context.Context) error {
	topic, err := s.pubSubClient.CreateTopicIfNotExists(ctx, message.EMAIL_TOPIC)
	if err != nil {
		return err
	}

	log.Println(startedListening, message.EMAIL_TOPIC)
	return s.pubSubClient.PullMessages(ctx, fmt.Sprintf("%s_%s", s.config.ServiceName, message.EMAIL_TOPIC), topic, func(ctx context.Context, msg *pubsub.Message) {
		switch msg.OrderingKey {
		case message.SEND_OTP_KEY:
			var payload message.OtpPayload
			log.Println("unmarshall message [OtpPayload]")
			err := json.Unmarshal(msg.Data, &payload)
			if err != nil {
				log.Println("failed when unmarshall message [OtpPayload]")
				message.SetRetryOrSetDataToDB(s.config, msg, func() {
					params := querier.CreateErrorMessageParams{
						ServiceName: s.config.ServiceName,
						PayloadName: otpPayload,
						PayloadData: string(msg.Data),
						Topic:       message.EMAIL_TOPIC,
						MessageID:   msg.ID,
						OrderingKey: msg.OrderingKey,
						Description: message.BuildDescErrorMsg(failedUnmarshalMsg, err),
					}
					_, err := s.repository.CreateErrorMessage(ctx, params)
					shrd_utils.LogIfError(err)
				})
				return
			}

			log.Println("send otp code to email: ", payload.Email)
			err = s.emailSvc.SendVerifyOtp(ctx, message.OtpPayload{
				Email:   payload.Email,
				OtpCode: payload.OtpCode,
			})

			if err != nil {
				log.Println("failed when sending email to user")
				message.SetRetryOrSetDataToDB(s.config, msg, func() {
					params := querier.CreateErrorMessageParams{
						ServiceName: s.config.ServiceName,
						PayloadName: otpPayload,
						PayloadData: string(msg.Data),
						Topic:       message.EMAIL_TOPIC,
						MessageID:   msg.ID,
						OrderingKey: msg.OrderingKey,
						Description: message.BuildDescErrorMsg(failedSendEmail, err),
					}
					_, err := s.repository.CreateErrorMessage(ctx, params)
					shrd_utils.LogIfError(err)
				})
				return
			}

			msg.Ack()
			log.Println("success send email to user from payload [OtpPayload]")
			return

		default:
			log.Println("no key matches for topic [Email]")
			// FOR SAFETY USECASE, JUST ACKNOWLEDGED THE MESSAGE
			msg.Ack()
		}
	})
}

func (s *NotificationSvcImpl) ListenForUserTopic(ctx context.Context) error {
	topic, err := s.pubSubClient.CreateTopicIfNotExists(ctx, message.USER_TOPIC)
	if err != nil {
		return err
	}

	log.Println(startedListening, message.USER_TOPIC)
	return s.pubSubClient.PullMessages(ctx, fmt.Sprintf("%s_%s", s.config.ServiceName, message.USER_TOPIC), topic, func(ctx context.Context, msg *pubsub.Message) {
		err := shrd_utils.ExecTx(ctx, s.repository.GetDB(), func(tx *sql.Tx) error {
			repoTx := s.repository.WithTx(tx)

			switch msg.OrderingKey {
			case message.CREATED_KEY:
				var payload message.CreatedUserPayload

				log.Println("unmarshall message [CreatedUserPayload]")
				err := json.Unmarshal(msg.Data, &payload)
				if err != nil {
					log.Println("failed when unmarshall message [CreatedUserPayload]")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							PayloadName: createUserPayload,
							PayloadData: string(msg.Data),
							Topic:       message.USER_TOPIC,
							MessageID:   msg.ID,
							OrderingKey: msg.OrderingKey,
							Description: message.BuildDescErrorMsg(failedUnmarshalMsg, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}
				_, err = repoTx.CreateUser(ctx, querier.CreateUserParams{
					ID:        payload.ID,
					Email:     payload.Email,
					Password:  payload.Password,
					Username:  payload.Username,
					OtpCode:   payload.OtpCode,
					CreatedAt: payload.CreatedAt,
					UpdatedAt: payload.UpdatedAt,
				})
				if err != nil {
					log.Println("failed when creating user")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							PayloadName: createUserPayload,
							PayloadData: string(msg.Data),
							Topic:       message.USER_TOPIC,
							MessageID:   msg.ID,
							OrderingKey: msg.OrderingKey,
							Description: message.BuildDescErrorMsg(failedCreateUser, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				msg.Ack()
				log.Println("success created user from payload [CreatedUserPayload]")
				return nil

			case message.UPDATED_KEY:
				var payload message.UpdatedUserPayload

				log.Println("unmarshall message [UpdatedUserPayload]")
				err := json.Unmarshal(msg.Data, &payload)
				if err != nil {
					log.Println("failed when unmarshall message [UpdatedUserPayload]")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_TOPIC,
							PayloadName: updateUserPayload,
							PayloadData: string(msg.Data),
							MessageID:   msg.ID,
							OrderingKey: msg.OrderingKey,
							Description: message.BuildDescErrorMsg(failedUnmarshalMsg, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}
				_, err = repoTx.FindUserByIdForUpdate(ctx, payload.ID)
				if err != nil {
					log.Println(failedUserNotFound)
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_TOPIC,
							PayloadName: updateUserPayload,
							PayloadData: string(msg.Data),
							MessageID:   msg.ID,
							OrderingKey: msg.OrderingKey,
							Description: message.BuildDescErrorMsg(failedUserNotFound, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				_, err = repoTx.UpdateUser(ctx, querier.UpdateUserParams{
					ID:          payload.ID,
					Password:    payload.Password,
					PhoneNumber: payload.PhoneNumber,
					Username:    payload.Username,
					OtpCode:     payload.OtpCode,
					AttemptLeft: payload.AttemptLeft,
					Status:      payload.Status,
					UpdatedAt:   payload.UpdatedAt,
				})
				if err != nil {
					log.Println("failed when updating user")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_TOPIC,
							PayloadName: updateUserPayload,
							PayloadData: string(msg.Data),
							MessageID:   msg.ID,
							OrderingKey: msg.OrderingKey,
							Description: message.BuildDescErrorMsg(failedUpdateUser, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				msg.Ack()
				log.Println("success updated user from payload [UpdatedUserPayload]")
				return nil

			case message.UPDATED_USER_MAIN_IMAGE_KEY:
				var payload message.UpdatedUserMainImagePayload

				log.Println("unmarshall message [UpdatedUserMainImagePayload]")
				err := json.Unmarshal(msg.Data, &payload)
				if err != nil {
					log.Println("failed when unmarshall message [UpdatedUserMainImagePayload]")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_TOPIC,
							PayloadName: updatedUserMainImagePayload,
							PayloadData: string(msg.Data),
							MessageID:   msg.ID,
							OrderingKey: msg.OrderingKey,
							Description: message.BuildDescErrorMsg(failedUnmarshalMsg, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				_, err = repoTx.FindUserByIdForUpdate(ctx, payload.ID)
				if err != nil {
					log.Println(failedUserNotFound)
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_TOPIC,
							PayloadName: updatedUserMainImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUserNotFound, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}
				_, err = repoTx.UpdateUserMainImage(ctx, querier.UpdateUserMainImageParams{
					ID:            payload.ID,
					MainImageUrl:  payload.MainImageUrl,
					MainImagePath: payload.MainImagePath,
					UpdatedAt:     payload.UpdatedAt,
				})
				if err != nil {
					log.Println("failed when updating user main image")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_TOPIC,
							PayloadName: updatedUserMainImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUpdateUserMainImage, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				msg.Ack()
				log.Println("success updated user from payload [UpdatedUserMainImagePayload]")
				return nil

			default:
				log.Println("no key matches for topic [User]")
				// FOR SAFETY USECASE, JUST ACKNOWLEDGED THE MESSAGE
				msg.Ack()
				return nil
			}
		})
		shrd_utils.LogIfError(err)
	})
}

func (s *NotificationSvcImpl) ListenForUserImageTopic(ctx context.Context) error {
	topic, err := s.pubSubClient.CreateTopicIfNotExists(ctx, message.USER_IMAGE_TOPIC)
	if err != nil {
		return err
	}

	log.Println(startedListening, message.USER_IMAGE_TOPIC)
	return s.pubSubClient.PullMessages(ctx, fmt.Sprintf("%s_%s", s.config.ServiceName, message.USER_IMAGE_TOPIC), topic, func(ctx context.Context, msg *pubsub.Message) {
		err := shrd_utils.ExecTx(ctx, s.repository.GetDB(), func(tx *sql.Tx) error {
			repoTx := s.repository.WithTx(tx)

			switch msg.OrderingKey {
			case message.CREATED_KEY:
				var payloads []message.CreatedUserImagePayload

				log.Println("unmarshall message [CreatedUserImagePayload]")
				err := json.Unmarshal(msg.Data, &payloads)
				if err != nil {
					log.Println("failed when unmarshall message [CreatedUserImagePayload]")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: createdUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUnmarshalMsg, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				ewg := errgroup.Group{}
				// mu := sync.Mutex{}

				for _, p := range payloads {
					payload := p
					ewg.Go(func() error {
						//	mu.Lock()
						_, err := repoTx.CreateUserImage(ctx, querier.CreateUserImageParams{
							ID:        payload.ID,
							UserID:    payload.UserID,
							IsMain:    payload.IsMain,
							ImageUrl:  payload.ImageUrl,
							ImagePath: payload.ImagePath,
							CreatedAt: payload.CreatedAt,
							UpdatedAt: payload.UpdatedAt,
						})
						//	mu.Unlock()
						return err
					})
				}

				if err := ewg.Wait(); err != nil {
					log.Println("failed when creating user image")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: createdUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedCreateUserImage, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				msg.Ack()
				log.Println("success created user image from payload [CreatedUserImagePayload]")
				return nil

			case message.UPDATED_KEY:
				var payload message.UpdatedUserImagePayload

				log.Println("unmarshall message [UpdatedUserImagePayload]")
				err := json.Unmarshal(msg.Data, &payload)
				if err != nil {
					log.Println("failed when unmarshall message [UpdatedUserImagePayload]")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: updatedUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUnmarshalMsg, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				_, err = repoTx.FindUserImageByIdForUpdate(ctx, payload.ID)
				if err != nil {
					log.Println(failedUserImageNotFound)
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: updatedUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUserImageNotFound, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				oldMainImage, err := repoTx.FindUserMainImageByUserIdForUpdate(ctx, payload.UserID)
				if err != nil {
					log.Println("cant't update, user old main image not found")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: updatedUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUserImageNotFound, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				var ewg errgroup.Group

				ewg.Go(func() error {
					_, err := repoTx.UpdateUserImage(ctx, querier.UpdateUserImageParams{
						ID:        oldMainImage.ID,
						IsMain:    false,
						UpdatedAt: payload.UpdatedAt,
					})
					return err
				})

				ewg.Go(func() error {
					_, err := repoTx.UpdateUserImage(ctx, querier.UpdateUserImageParams{
						ID:        payload.ID,
						IsMain:    payload.IsMain,
						UpdatedAt: payload.UpdatedAt,
					})
					return err
				})

				if err := ewg.Wait(); err != nil {
					log.Println("failed when updating user image")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: updatedUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUpdateUserImage, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				msg.Ack()
				log.Println("success updated user image from payload [UpdatedUserImagePayload]")
				return nil

			case message.DELETED_KEY:
				var payload message.DeletedUserImagePayload

				log.Println("unmarshall message [DeletedUserImagePayload]")
				err := json.Unmarshal(msg.Data, &payload)
				if err != nil {
					log.Println("failed when unmarshall message [DeletedUserImagePayload]")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: deletedUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUnmarshalMsg, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				_, err = repoTx.FindUserImageByIdForUpdate(ctx, payload.ID)
				if err != nil {
					log.Println(failedUserImageNotFound)
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: deletedUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedUserImageNotFound, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				err = repoTx.DeleteUserImage(ctx, payload.ID)
				if err != nil {
					log.Println("failed when deleting user image")
					message.SetRetryOrSetDataToDB(s.config, msg, func() {
						params := querier.CreateErrorMessageParams{
							ServiceName: s.config.ServiceName,
							Topic:       message.USER_IMAGE_TOPIC,
							PayloadName: deletedUserImagePayload,
							PayloadData: string(msg.Data),
							OrderingKey: msg.OrderingKey,
							MessageID:   msg.ID,
							Description: message.BuildDescErrorMsg(failedDeleteUserImage, err),
						}
						_, err := s.repository.CreateErrorMessage(ctx, params)
						shrd_utils.LogIfError(err)
					})
					return err
				}

				msg.Ack()
				log.Println("success deleted user image from payload [DeletedUserImagePayload]")
				return nil

			default:
				log.Println("no key matches for topic [User-Image]")
				// FOR SAFETY USECASE, JUST ACKNOWLEDGED THE MESSAGE
				msg.Ack()
				return nil
			}
		})
		shrd_utils.LogIfError(err)
	})
}
