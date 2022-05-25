package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/StevanoZ/dv-shared/message"
	shrd_service "github.com/StevanoZ/dv-shared/service"
	shrd_token "github.com/StevanoZ/dv-shared/token"
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	user_db "github.com/StevanoZ/dv-user/db/user/sqlc"
	"github.com/StevanoZ/dv-user/utils"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/StevanoZ/dv-user/dtos/mapping"
	"github.com/StevanoZ/dv-user/dtos/request"
	"github.com/StevanoZ/dv-user/dtos/response"
)

// JUST FOR PRIVATE CONSTANT
const active = "active"

const (
	userNotFound                = "user not found"
	failedWhenUpdatingUser      = "failed when updating user"
	failedWhenUploadingFile     = "failed when uploading file"
	failedWhenGettingPresignUrl = "failed when getting pre signed url"
)

type UserSvc interface {
	SignUp(ctx context.Context, input request.SignUpReq) response.UserResp
	LogIn(cxt context.Context, input request.LogInReq) response.UserWithTokenResp
	UpdateUser(ctx context.Context, userId uuid.UUID, input request.UpdateUserReq) response.UserResp
	VerifyOtp(ctx context.Context, input request.VerifyOtpReq) response.UserWithTokenResp
	ResendOtp(ctx context.Context, input request.ResendOtpReq)
	UploadImages(ctx context.Context, files []*multipart.FileHeader, userId uuid.UUID) []response.UserImageResp
	GetUserImages(ctx context.Context, userId uuid.UUID) []response.UserImageResp
	SetMainImage(ctx context.Context, userId uuid.UUID, imageId uuid.UUID) response.UserImageResp
	DeleteImage(ctx context.Context, userId uuid.UUID, imageId uuid.UUID)
	GetUsers(ctx context.Context, input request.PaginationReq) response.UsersWithPaginationResp
	GetUser(ctx context.Context, userId uuid.UUID) response.UserWithImagesResp
}

type UserSvcImpl struct {
	userRepo     user_db.UserRepo
	fileSvc      shrd_service.FileSvc
	pubSubClient shrd_service.PubSubClient
	cacheSvc     shrd_service.CacheSvc
	tokenMaker   shrd_token.Maker
	config       *shrd_utils.BaseConfig
}

func NewUserSvc(
	userRepo user_db.UserRepo,
	fileSvc shrd_service.FileSvc,
	pubSubClient shrd_service.PubSubClient,
	cacheSvc shrd_service.CacheSvc,
	token shrd_token.Maker,
	config *shrd_utils.BaseConfig,
) UserSvc {
	return &UserSvcImpl{
		userRepo:     userRepo,
		fileSvc:      fileSvc,
		pubSubClient: pubSubClient,
		cacheSvc:     cacheSvc,
		config:       config,
		tokenMaker:   token,
	}
}

func (s *UserSvcImpl) SignUp(ctx context.Context, input request.SignUpReq) response.UserResp {
	userResp := response.UserResp{}
	err := shrd_utils.ExecTx(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)
		user, err := uTx.FindUserByEmail(ctx, input.Email)

		if err != nil && err != sql.ErrNoRows {
			return shrd_utils.CustomError(err.Error(), 422)
		}

		if user.Email != "" {
			return shrd_utils.CustomError("email already in used", 400)
		}

		hashedPassword, err := shrd_utils.HashedPassword(input.Password)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when hashing password", 400)
		}

		input.ID = uuid.New()
		input.Password = hashedPassword
		otpCode := shrd_utils.RandomInt(0, 999999)
		params := mapping.ToCreateUserParams(input)
		params.OtpCode = otpCode
		user, err = uTx.CreateUser(ctx, params)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when creating user", 422)
		}

		userResp = mapping.ToUserResp(user)

		go func() {
			ctx := context.Background()
			topic, err := s.pubSubClient.CreateTopicIfNotExists(ctx, message.EMAIL_TOPIC)
			shrd_utils.LogIfError(err)
			err = s.pubSubClient.PublishTopics(ctx, []*pubsub.Topic{topic}, message.OtpPayload{
				Email:   user.Email,
				OtpCode: int(user.OtpCode),
			}, message.SEND_OTP_KEY)
			shrd_utils.LogIfError(err)
		}()

		go func() {
			ctx := context.Background()
			s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
		}()

		return nil
	})

	shrd_utils.PanicIfError(err)

	return userResp
}

func (s *UserSvcImpl) LogIn(ctx context.Context, input request.LogInReq) response.UserWithTokenResp {
	userWithTokenResp := response.UserWithTokenResp{}
	err := shrd_utils.ExecTx(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		ewg := errgroup.Group{}
		token := ""
		preSignedUrl := ""
		var err1 error
		var err2 error

		uTx := s.userRepo.WithTx(tx)
		user, err := uTx.FindUserByEmail(ctx, input.Email)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
		}

		if user.Status == "not-active" {
			return shrd_utils.CustomError("please verify your email first", 400)
		}
		err = shrd_utils.ComparedPasswrd(user.Password, input.Password)

		if err != nil {
			return shrd_utils.CustomError("invalid credentials", 401)
		}

		ewg.Go(func() error {
			token, _, err1 = s.tokenMaker.CreateToken(shrd_token.PayloadParams{
				UserId: user.ID,
				Email:  user.Email,
				Status: user.Status,
			}, s.config.AccessTokenDuration)

			return err1
		})

		ewg.Go(func() error {
			if user.MainImagePath != "" {
				preSignedUrl, err2 = s.fileSvc.GetPreSignUrl(ctx, user.MainImagePath)
				return err2
			}
			return nil
		})

		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when trying to log in", 422)
		}

		userWithTokenResp = mapping.ToUserWithTokenResp(user)
		userWithTokenResp.Token = token
		userWithTokenResp.MainImageUrl = preSignedUrl

		return nil
	})

	shrd_utils.PanicIfError(err)

	return userWithTokenResp
}

func (s *UserSvcImpl) UpdateUser(ctx context.Context, userId uuid.UUID, input request.UpdateUserReq) response.UserResp {
	userResp := response.UserResp{}

	err := shrd_utils.ExecTx(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)
		user, err := uTx.FindUserById(ctx, userId)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
		}

		user, err = uTx.UpdateUser(ctx, user_db.UpdateUserParams{
			ID:          user.ID,
			Username:    input.Username,
			PhoneNumber: input.PhoneNumber,
			Password:    user.Password,
			OtpCode:     user.OtpCode,
			AttemptLeft: user.AttemptLeft,
			Status:      user.Status,
		})

		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUpdatingUser, 422)
		}

		userResp = mapping.ToUserResp(user)
		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()

	return userResp
}

func verifyOtpHelper(user user_db.User, input request.VerifyOtpReq) (int, error) {
	if user.Status == active {
		return 0, shrd_utils.CustomError("invalid request", 400)
	}

	if user.AttemptLeft == 0 {
		return 0, shrd_utils.CustomError("your attempt left is 0", 400)
	}

	expiredTime := user.UpdatedAt.Add(time.Millisecond * 300000)

	if expiredTime.Before(time.Now()) {
		return 0, shrd_utils.CustomError("otp code has expired", 400)
	}

	otpCode, err := strconv.Atoi(input.OtpCode)
	if err != nil {
		return 0, shrd_utils.CustomErrorWithTrace(err, "invalid otp code", 400)
	}

	return otpCode, nil
}

func (s *UserSvcImpl) VerifyOtp(ctx context.Context, input request.VerifyOtpReq) response.UserWithTokenResp {
	userWithTokenResp := response.UserWithTokenResp{}
	err := shrd_utils.ExecTx(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)

		user, err := uTx.FindUserByEmail(ctx, input.Email)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
		}

		otpCode, err := verifyOtpHelper(user, input)
		if err != nil {
			return err
		}

		if user.OtpCode != int64(otpCode) {
			params := mapping.ToUpdateUserParams(user)
			params.AttemptLeft = user.AttemptLeft - 1
			_, err := s.userRepo.UpdateUser(ctx, params)
			if err != nil {
				return shrd_utils.CustomErrorWithTrace(err, failedWhenUpdatingUser, 422)
			}
			return shrd_utils.CustomError("invalid otp code", 400)
		}
		params := mapping.ToUpdateUserParams(user)
		params.OtpCode = 0
		params.AttemptLeft = 0
		params.Status = active

		user, err = uTx.UpdateUser(ctx, params)

		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUpdatingUser, 422)
		}

		userWithTokenResp = mapping.ToUserWithTokenResp(user)

		token, _, err := s.tokenMaker.CreateToken(shrd_token.PayloadParams{
			UserId: user.ID,
			Email:  user.Email,
			Status: user.Status,
		}, s.config.AccessTokenDuration)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when creating token", 422)
		}
		userWithTokenResp.Token = token
		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()

	return userWithTokenResp
}

func (s *UserSvcImpl) ResendOtp(ctx context.Context, input request.ResendOtpReq) {
	err := shrd_utils.ExecTx(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)
		user, err := uTx.FindUserByEmail(ctx, input.Email)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
		}

		if user.Status == active {
			return shrd_utils.CustomError("invalid request", 400)
		}

		if user.AttemptLeft == 0 {
			return shrd_utils.CustomError("can't sent OTP, your attempt left is 0", 400)
		}

		otpCode := shrd_utils.RandomInt(0, 999999)

		user, err = uTx.UpdateUser(ctx, user_db.UpdateUserParams{
			ID:          user.ID,
			Username:    user.Username,
			Password:    user.Password,
			PhoneNumber: user.PhoneNumber,
			Status:      user.Status,
			AttemptLeft: user.AttemptLeft - 1,
			OtpCode:     otpCode,
		})

		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUpdatingUser, 422)
		}

		go func() {
			ctx := context.Background()
			topic, err := s.pubSubClient.CreateTopicIfNotExists(ctx, message.EMAIL_TOPIC)
			shrd_utils.LogIfError(err)

			err = s.pubSubClient.PublishTopics(ctx, []*pubsub.Topic{topic}, message.OtpPayload{
				Email:   user.Email,
				OtpCode: int(user.OtpCode),
			}, message.SEND_OTP_KEY)
			shrd_utils.LogIfError(err)
		}()

		return nil
	})

	shrd_utils.PanicIfError(err)
}

func uploadImagesHelper(
	ctx context.Context,
	mu *sync.Mutex,
	fileSvc shrd_service.FileSvc,
	uTx user_db.Querier,
	file multipart.File,
	userId uuid.UUID,
	filename string,
) (user_db.UserImage, error) {
	defer file.Close()
	ext := filepath.Ext(filename)
	newFilename := fmt.Sprintf("%s.%s", uuid.New(), ext)
	filepath := fmt.Sprintf("users/%s/%s", userId, newFilename)

	url, err := fileSvc.UploadPrivateFile(ctx, file, filepath)
	if err != nil {
		return user_db.UserImage{}, err
	}

	params := user_db.CreateUserImageParams{
		ID:        uuid.New(),
		ImageUrl:  url,
		ImagePath: filepath,
		UserID:    userId,
	}

	// FOR AVOID ERROR ROWS NOT CLOSE (Concurrency issue)
	mu.Lock()
	image, err := uTx.CreateUserImage(ctx, params)
	mu.Unlock()

	return image, err
}

func checkAndSetUserMainImage(userRepo user_db.UserRepo, userId uuid.UUID) {
	ctx := context.Background()
	ewg := errgroup.Group{}
	err := shrd_utils.ExecTx(ctx, userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := userRepo.WithTx(tx)
		user, err := uTx.FindUserWithImages(ctx, userId)
		if err != nil {
			return err
		}

		userImages := []user_db.UserImage{}

		err = json.Unmarshal(user.Images, &userImages)
		if err != nil {
			return err
		}

		hasMainImage := false
		mainImageUrl := ""
		mainImagePath := ""

		for _, ui := range userImages {
			if ui.IsMain {
				hasMainImage = true
				break
			}
		}

		if !hasMainImage {
			mainImageUrl = userImages[0].ImageUrl
			mainImagePath = userImages[0].ImagePath
			params := user_db.UpdateUserImageParams{
				ID:     userImages[0].ID,
				IsMain: true,
			}
			ewg.Go(func() error {
				_, err := uTx.UpdateUserImage(ctx, params)
				return err
			})
			ewg.Go(func() error {
				params := user_db.UpdateUserMainImageParams{
					ID:            user.ID,
					MainImageUrl:  mainImageUrl,
					MainImagePath: mainImagePath,
				}

				_, err := uTx.UpdateUserMainImage(ctx, params)
				return err
			})

		}
		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUploadingFile, 422)
		} else if mainImageUrl != "" {
			fmt.Println("success set main image", mainImageUrl)
		}
		return nil
	})
	shrd_utils.LogIfError(err)
}

func (s *UserSvcImpl) UploadImages(ctx context.Context, files []*multipart.FileHeader, userId uuid.UUID) []response.UserImageResp {
	userImagesResp := make([]response.UserImageResp, len(files))

	err := shrd_utils.ExecTx(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)
		ewg := errgroup.Group{}
		mu := sync.Mutex{}

		if len(files) > 10 {
			return shrd_utils.CustomError("can't upload more than 10 files at once", 400)
		}

		for i := range files {
			index := i
			file, err := files[index].Open()
			filename := files[index].Filename

			if err != nil {
				return shrd_utils.CustomErrorWithTrace(err, failedWhenUploadingFile, 400)
			}

			ewg.Go(func() error {
				image, err := uploadImagesHelper(
					ctx,
					&mu,
					s.fileSvc,
					uTx,
					file,
					userId,
					filename,
				)
				if err != nil {
					return err
				}

				userImagesResp[index] = mapping.ToUserImageResp(image)

				return nil
			})
		}

		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUploadingFile, 422)
		}
		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		checkAndSetUserMainImage(s.userRepo, userId)
	}()

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()

	return userImagesResp
}

func (s *UserSvcImpl) GetUserImages(ctx context.Context, userId uuid.UUID) []response.UserImageResp {
	ewg := errgroup.Group{}
	userImagesResp := []response.UserImageResp{}

	data, err := s.cacheSvc.GetOrSet(ctx, shrd_utils.BuildCacheKey(utils.USER_KEY, userId.String(), "GetUserImages"), func() any {
		userImages, err := s.userRepo.FindUserImagesByUserId(ctx, userId)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when finding user images", 400)
		}

		userImagesResp = make([]response.UserImageResp, len(userImages))
		for i := range userImages {
			index := i
			ewg.Go(func() error {
				preSignedUrl, err := s.fileSvc.GetPreSignUrl(ctx, userImages[index].ImagePath)
				if err != nil {
					return err
				}
				userImages[index].ImageUrl = preSignedUrl
				userImageResp := mapping.ToUserImageResp(userImages[index])
				userImagesResp[index] = userImageResp
				return nil
			})
		}

		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenGettingPresignUrl, 422)
		}

		return userImagesResp
	})

	shrd_utils.PanicIfError(err)
	shrd_utils.ConvertInterfaceP(data, &userImagesResp)

	return userImagesResp
}

func checkAndAssignMainImage(
	img user_db.UserImage,
	imageId uuid.UUID,
	oldMainImageId *uuid.UUID,
	newMainImageUrl *string,
	newMainImagePath *string,
) {
	if img.IsMain && img.ID != imageId {
		*oldMainImageId = img.ID
	}

	if img.ID == imageId {
		*newMainImageUrl = img.ImageUrl
		*newMainImagePath = img.ImagePath
	}
}

func setMainImageHelper(
	ctx context.Context,
	uTx user_db.Querier,
	userImageResp *response.UserImageResp,
	userId uuid.UUID,
	imageId uuid.UUID,
	newMainImageUrl string,
	newMainImagePath string,
) error {
	image, err := uTx.UpdateUserImage(ctx, user_db.UpdateUserImageParams{
		ID:     imageId,
		IsMain: true,
	})
	if err != nil {
		return err
	}

	*userImageResp = mapping.ToUserImageResp(image)

	userParams := user_db.UpdateUserMainImageParams{
		ID:            userId,
		MainImageUrl:  newMainImageUrl,
		MainImagePath: newMainImagePath,
	}

	_, err = uTx.UpdateUserMainImage(ctx, userParams)
	return err
}

func (s *UserSvcImpl) SetMainImage(ctx context.Context, userId uuid.UUID, imageId uuid.UUID) response.UserImageResp {
	userImageResp := response.UserImageResp{}

	err := shrd_utils.ExecTx(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)

		ewg := errgroup.Group{}
		user, err := uTx.FindUserWithImages(ctx, userId)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
		}

		userImages := []user_db.UserImage{}

		err = json.Unmarshal(user.Images, &userImages)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when unmarshal", 404)
		}

		var newMainImageUrl string
		var newMainImagePath string
		var oldMainImageId uuid.UUID

		for _, img := range userImages {
			if img.IsMain && img.ID == imageId {
				return shrd_utils.CustomError("you can't set the same main image", 400)
			}

			checkAndAssignMainImage(img,
				imageId,
				&oldMainImageId,
				&newMainImageUrl,
				&newMainImagePath,
			)
		}

		if newMainImageUrl == "" {
			return shrd_utils.CustomError("image not found", 404)
		}

		ewg.Go(func() error {
			return setMainImageHelper(
				ctx,
				uTx,
				&userImageResp,
				userId,
				imageId,
				newMainImageUrl,
				newMainImagePath,
			)
		})

		ewg.Go(func() error {
			_, err := uTx.UpdateUserImage(ctx, user_db.UpdateUserImageParams{
				ID:     oldMainImageId,
				IsMain: false,
			})
			return err
		})

		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when set the main image", 422)
		}
		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()

	return userImageResp
}

func (s *UserSvcImpl) DeleteImage(ctx context.Context, userId uuid.UUID, imageId uuid.UUID) {
	err := shrd_utils.ExecTx(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)
		ewg := errgroup.Group{}
		image, err := uTx.FindUserImageById(ctx, imageId)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			shrd_utils.PanicIfError(shrd_utils.CustomErrorWithTrace(err, "image not found", 404))
		}

		if image.UserID != userId {
			shrd_utils.PanicIfError(shrd_utils.CustomError("not authorize to perform this operation", 403))
		}

		if image.IsMain {
			shrd_utils.PanicIfError(shrd_utils.CustomError("you can't delete the main image", 400))
		}

		ewg.Go(func() error {
			return s.fileSvc.DeleteFile(ctx, s.config.S3PrivateBucketName, image.ImagePath)
		})

		ewg.Go(func() error {
			return uTx.DeleteUserImage(ctx, image.ID)
		})

		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when deleting image", 422)
		}
		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()
}

func (s *UserSvcImpl) GetUsers(ctx context.Context, input request.PaginationReq) response.UsersWithPaginationResp {
	ewg1 := errgroup.Group{}
	ewg2 := errgroup.Group{}
	users := []user_db.User{}
	usersPaginationResp := response.UsersWithPaginationResp{}
	var counts int64
	var err1 error
	var err2 error

	params := user_db.FindUsersParams{
		SearchValue: "%" + input.SearchValue + "%",
		SearchField: input.SearchField,
		FilterBy:    input.FilterBy,
		SortBy:      input.SortBy,
		Offset:      int32(input.Page),
		Limit:       int32(input.Limit),
	}

	data, err := s.cacheSvc.GetOrSet(ctx, shrd_utils.BuildCacheKey(utils.USERS_KEY, "|", "GetUsers", params), func() any {
		ewg1.Go(func() error {
			users, err1 = s.userRepo.FindUsers(ctx, params)
			return err1
		})

		ewg1.Go(func() error {
			counts, err2 = s.userRepo.GetUsersPaginationCount(ctx, user_db.GetUsersPaginationCountParams{
				SearchValue: "%" + input.SearchValue + "%",
				SearchField: input.SearchField,
				FilterBy:    input.FilterBy,
			})
			return err2
		})

		if err := ewg1.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when finding user", 400)
		}

		usersResp := make([]response.UserResp, len(users))
		for i := range users {
			index := i

			ewg2.Go(func() error {
				if users[index].MainImagePath != "" {
					preSignedUrl, err := s.fileSvc.GetPreSignUrl(ctx, users[index].MainImagePath)
					if err != nil {
						return err
					}
					users[index].MainImageUrl = preSignedUrl
				}
				userResp := mapping.ToUserResp(users[index])
				usersResp[index] = userResp

				return nil
			})

		}
		if err := ewg2.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenGettingPresignUrl, 422)
		}

		usersPaginationResp.Users = usersResp
		usersPaginationResp.Pagination = mapping.ToPaginationResp(input.Page, input.Limit, int(counts))

		return usersPaginationResp
	})

	shrd_utils.PanicIfError(err)
	shrd_utils.ConvertInterfaceP(data, &usersPaginationResp)

	return usersPaginationResp
}

func getUserHelper(
	ctx context.Context,
	fileSvc shrd_service.FileSvc,
	userWithImagesResp response.UserWithImagesResp,
	index int,
	path string,
) error {
	if path != "" {
		preSignedUrl, err := fileSvc.GetPreSignUrl(ctx, path)
		if err != nil {
			return err
		}
		userWithImagesResp.Images[index].ImageUrl = preSignedUrl

		if userWithImagesResp.Images[index].IsMain {
			userWithImagesResp.MainImageUrl = preSignedUrl
		}

	}

	return nil
}

func (s *UserSvcImpl) GetUser(ctx context.Context, userId uuid.UUID) response.UserWithImagesResp {
	ewg := errgroup.Group{}
	userWithImagesResp := response.UserWithImagesResp{}
	data, err := s.cacheSvc.GetOrSet(ctx, shrd_utils.BuildCacheKey(utils.USER_KEY, userId.String(), "GetUser"), func() any {
		user, err := s.userRepo.FindUserWithImages(ctx, userId)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
		}

		userWithImagesResp := mapping.ToUserWithImagesResp(user)

		for i := range userWithImagesResp.Images {
			index := i
			path := userWithImagesResp.Images[index].ImagePath

			ewg.Go(func() error {
				return getUserHelper(
					ctx,
					s.fileSvc,
					userWithImagesResp,
					index,
					path,
				)
			})
		}

		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenGettingPresignUrl, 422)
		}

		return userWithImagesResp
	})

	shrd_utils.PanicIfError(err)
	shrd_utils.ConvertInterfaceP(data, &userWithImagesResp)

	return userWithImagesResp
}
