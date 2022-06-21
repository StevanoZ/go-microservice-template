package service

import (
	"context"
	"database/sql"
	"fmt"
	"mime/multipart"
	"path/filepath"
	"strconv"
	"sync"
	"time"

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
	repoFindUserByEmail         = "repo.FindUserByEmail"
	repoUpdateUser              = "repo.UpdateUser"
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
	pubsubClient shrd_service.PubSubClient
	cacheSvc     shrd_service.CacheSvc
	tokenMaker   shrd_token.Maker
	config       *shrd_utils.BaseConfig
}

func NewUserSvc(
	userRepo user_db.UserRepo,
	fileSvc shrd_service.FileSvc,
	pubsubClient shrd_service.PubSubClient,
	cacheSvc shrd_service.CacheSvc,
	token shrd_token.Maker,
	config *shrd_utils.BaseConfig,
) UserSvc {
	return &UserSvcImpl{
		userRepo:     userRepo,
		fileSvc:      fileSvc,
		pubsubClient: pubsubClient,
		cacheSvc:     cacheSvc,
		config:       config,
		tokenMaker:   token,
	}
}

func (s *UserSvcImpl) SignUp(ctx context.Context, input request.SignUpReq) response.UserResp {
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.SignUp")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	userResp := response.UserResp{}
	var createdUser user_db.User
	err := shrd_utils.ExecTxWithRetry(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)

		fuCtx, fuTrc := shrd_utils.CreateTracer(svcCtx, repoFindUserByEmail)
		user, err := uTx.FindUserByEmail(fuCtx, input.Email)
		shrd_utils.CheckTracer(fuTrc, err)
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
		cuCtx, cuTrc := shrd_utils.CreateTracer(svcCtx, "repo.CreateUser")
		user, err = uTx.CreateUser(cuCtx, params)
		shrd_utils.CheckTracer(cuTrc, err)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when creating user", 422)
		}

		userResp = mapping.ToUserResp(user)
		createdUser = user

		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.EMAIL_TOPIC}, message.SEND_OTP_KEY, message.OtpPayload{
			Email:   createdUser.Email,
			OtpCode: int(createdUser.OtpCode),
		})
	}()

	go func() {
		ctx := context.Background()
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_TOPIC}, message.CREATED_KEY, message.CreatedUserPayload{
			ID:        createdUser.ID,
			Email:     createdUser.Email,
			Username:  createdUser.Username,
			Password:  createdUser.Password,
			OtpCode:   createdUser.OtpCode,
			CreatedAt: createdUser.CreatedAt,
			UpdatedAt: createdUser.UpdatedAt,
		})
	}()

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()

	return userResp
}

func (s *UserSvcImpl) LogIn(ctx context.Context, input request.LogInReq) response.UserWithTokenResp {
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.LogIn")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	userWithTokenResp := response.UserWithTokenResp{}
	err := shrd_utils.ExecTxWithRetry(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		ewg := errgroup.Group{}
		token := ""
		preSignedUrl := ""
		var err1 error
		var err2 error

		uTx := s.userRepo.WithTx(tx)
		fuCtx, fuTrc := shrd_utils.CreateTracer(svcCtx, repoFindUserByEmail)
		user, err := uTx.FindUserByEmail(fuCtx, input.Email)
		shrd_utils.CheckTracer(fuTrc, err)
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
			_, ctTrc := shrd_utils.CreateTracer(svcCtx, "CreateToken")
			token, _, err1 = s.tokenMaker.CreateToken(shrd_token.PayloadParams{
				UserId: user.ID,
				Email:  user.Email,
				Status: user.Status,
			}, s.config.AccessTokenDuration)
			shrd_utils.CheckTracer(ctTrc, err1)

			return err1
		})

		ewg.Go(func() error {
			if user.MainImagePath != "" {
				psCtx, psTrc := shrd_utils.CreateTracer(svcCtx, "GetPreSignUrl")
				preSignedUrl, err2 = s.fileSvc.GetPreSignUrl(psCtx, user.MainImagePath)
				shrd_utils.CheckTracer(psTrc, err)

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
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.UpdateUser")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	userResp := response.UserResp{}
	updatedUser := user_db.User{}

	err := shrd_utils.ExecTxWithRetry(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)
		fuCtx, fuTrc := shrd_utils.CreateTracer(svcCtx, "repo.FindUserById")
		user, err := uTx.FindUserById(fuCtx, userId)
		shrd_utils.CheckTracer(fuTrc, err)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
		}

		uuCtx, uuTrc := shrd_utils.CreateTracer(svcCtx, repoUpdateUser)
		user, err = uTx.UpdateUser(uuCtx, user_db.UpdateUserParams{
			ID:          user.ID,
			Username:    input.Username,
			PhoneNumber: input.PhoneNumber,
			Password:    user.Password,
			OtpCode:     user.OtpCode,
			AttemptLeft: user.AttemptLeft,
			Status:      user.Status,
		})
		shrd_utils.CheckTracer(uuTrc, err)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUpdatingUser, 422)
		}

		userResp = mapping.ToUserResp(user)
		updatedUser = user

		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_TOPIC}, message.UPDATED_KEY, message.UpdatedUserPayload{
			ID:          updatedUser.ID,
			Username:    updatedUser.Username,
			Password:    updatedUser.Password,
			OtpCode:     updatedUser.OtpCode,
			AttemptLeft: updatedUser.AttemptLeft,
			PhoneNumber: updatedUser.PhoneNumber,
			Status:      updatedUser.Status,
			UpdatedAt:   updatedUser.UpdatedAt,
		})
	}()
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
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.VerifyOtp")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	userWithTokenResp := response.UserWithTokenResp{}
	updatedUser := user_db.User{}

	err := shrd_utils.ExecTxWithRetry(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)

		fuCtx, fuTrc := shrd_utils.CreateTracer(svcCtx, repoFindUserByEmail)
		user, err := uTx.FindUserByEmail(fuCtx, input.Email)
		shrd_utils.CheckTracer(fuTrc, err)
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
			uuCtx, uuTrc := shrd_utils.CreateTracer(svcCtx, repoUpdateUser)
			updtdUser, err := s.userRepo.UpdateUser(uuCtx, params)
			shrd_utils.CheckTracer(uuTrc, err)
			if err != nil {
				return shrd_utils.CustomErrorWithTrace(err, failedWhenUpdatingUser, 422)
			}

			go func() {
				ctx := context.Background()
				s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_TOPIC}, message.UPDATED_KEY,
					message.UpdatedUserPayload{
						ID:          updtdUser.ID,
						Username:    updtdUser.Username,
						Password:    updtdUser.Password,
						PhoneNumber: updtdUser.PhoneNumber,
						OtpCode:     updtdUser.OtpCode,
						AttemptLeft: updtdUser.AttemptLeft,
						Status:      updtdUser.Status,
						UpdatedAt:   updtdUser.UpdatedAt,
					})
			}()

			return shrd_utils.CustomError("invalid otp code", 400)
		}
		params := mapping.ToUpdateUserParams(user)
		params.OtpCode = 0
		params.AttemptLeft = 0
		params.Status = active

		uuCtx, uuTrc := shrd_utils.CreateTracer(svcCtx, repoUpdateUser)
		user, err = uTx.UpdateUser(uuCtx, params)
		shrd_utils.CheckTracer(uuTrc, err)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUpdatingUser, 422)
		}

		userWithTokenResp = mapping.ToUserWithTokenResp(user)

		_, ctTrc := shrd_utils.CreateTracer(svcCtx, "CreateToken")
		token, _, err := s.tokenMaker.CreateToken(shrd_token.PayloadParams{
			UserId: user.ID,
			Email:  user.Email,
			Status: user.Status,
		}, s.config.AccessTokenDuration)
		shrd_utils.CheckTracer(ctTrc, err)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when creating token", 422)
		}
		updatedUser = user
		userWithTokenResp.Token = token
		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_TOPIC}, message.UPDATED_KEY, message.UpdatedUserPayload{
			ID:          updatedUser.ID,
			Username:    updatedUser.Username,
			Password:    updatedUser.Password,
			PhoneNumber: updatedUser.PhoneNumber,
			OtpCode:     updatedUser.OtpCode,
			AttemptLeft: updatedUser.AttemptLeft,
			Status:      updatedUser.Status,
			UpdatedAt:   updatedUser.UpdatedAt,
		})
	}()

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()

	return userWithTokenResp
}

func (s *UserSvcImpl) ResendOtp(ctx context.Context, input request.ResendOtpReq) {
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.ResendOtp")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	var updatedUser user_db.User

	err := shrd_utils.ExecTxWithRetry(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)
		fuCtx, fuTrc := shrd_utils.CreateTracer(svcCtx, repoFindUserByEmail)
		user, err := uTx.FindUserByEmail(fuCtx, input.Email)
		shrd_utils.CheckTracer(fuTrc, err)
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

		uuCtx, uuTrc := shrd_utils.CreateTracer(svcCtx, "repo.UpdateUserParams")
		user, err = uTx.UpdateUser(uuCtx, user_db.UpdateUserParams{
			ID:          user.ID,
			Username:    user.Username,
			Password:    user.Password,
			PhoneNumber: user.PhoneNumber,
			Status:      user.Status,
			AttemptLeft: user.AttemptLeft - 1,
			OtpCode:     otpCode,
		})
		shrd_utils.CheckTracer(uuTrc, err)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUpdatingUser, 422)
		}
		updatedUser = user
		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.EMAIL_TOPIC}, message.SEND_OTP_KEY, message.OtpPayload{
			Email:   updatedUser.Email,
			OtpCode: int(updatedUser.OtpCode),
		})
	}()

	go func() {
		ctx := context.Background()
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_TOPIC}, message.UPDATED_KEY, message.UpdatedUserPayload{
			ID:          updatedUser.ID,
			Username:    updatedUser.Username,
			Password:    updatedUser.Password,
			PhoneNumber: updatedUser.PhoneNumber,
			OtpCode:     updatedUser.OtpCode,
			AttemptLeft: updatedUser.AttemptLeft,
			Status:      updatedUser.Status,
			UpdatedAt:   updatedUser.UpdatedAt,
		})
	}()
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

	upfCtx, upfTrc := shrd_utils.CreateTracer(ctx, "UploadPrivateFile")
	url, err := fileSvc.UploadPrivateFile(upfCtx, file, filepath)
	shrd_utils.CheckTracer(upfTrc, err)
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
	cuiCtx, cuiTrc := shrd_utils.CreateTracer(ctx, "repo.CreateUserImage")
	image, err := uTx.CreateUserImage(cuiCtx, params)
	shrd_utils.CheckTracer(cuiTrc, err)
	mu.Unlock()

	return image, err
}

func checkAndSendCreatedUserImagesEvent(
	pubsubClient shrd_service.PubSubClient,
	images []user_db.UserImage,
	updatedUserImage user_db.UserImage,
	hasMainImage bool,
) {
	ctx := context.Background()
	createdUserImagesPayload := make([]message.CreatedUserImagePayload, len(images))

	if !hasMainImage {
		isMain := false
		for i, img := range images {
			isMain = img.ID == updatedUserImage.ID

			createdUserImagesPayload[i] = message.CreatedUserImagePayload{
				ID:        img.ID,
				UserID:    img.UserID,
				ImageUrl:  img.ImageUrl,
				ImagePath: img.ImagePath,
				IsMain:    isMain,
				CreatedAt: img.CreatedAt,
				UpdatedAt: img.UpdatedAt,
			}
		}
		pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_IMAGE_TOPIC}, message.CREATED_KEY, createdUserImagesPayload)
	} else {
		for i, img := range images {
			createdUserImagesPayload[i] = message.CreatedUserImagePayload{
				ID:        img.ID,
				UserID:    img.UserID,
				ImageUrl:  img.ImageUrl,
				ImagePath: img.ImagePath,
				IsMain:    img.IsMain,
				CreatedAt: img.CreatedAt,
				UpdatedAt: img.UpdatedAt,
			}
		}
		pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_IMAGE_TOPIC}, message.CREATED_KEY, createdUserImagesPayload)
	}
}

func checkAndSendUpdatedUserMainImageEvent(pubsubClient shrd_service.PubSubClient, updatedUser user_db.User, hasMainImage bool) {
	ctx := context.Background()
	if !hasMainImage {
		pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_TOPIC}, message.UPDATED_USER_MAIN_IMAGE_KEY, message.UpdatedUserMainImagePayload{
			ID:            updatedUser.ID,
			MainImageUrl:  updatedUser.MainImageUrl,
			MainImagePath: updatedUser.MainImagePath,
			UpdatedAt:     updatedUser.UpdatedAt,
		})
	}
}

func checkAndSetUserMainImage(userRepo user_db.UserRepo, pubsubClient shrd_service.PubSubClient, images []user_db.UserImage, userId uuid.UUID) {
	ctx := context.Background()
	ewg := errgroup.Group{}
	var updatedUser user_db.User
	var updatedUserImage user_db.UserImage
	hasMainImage := false
	var err1 error
	var err2 error

	err := shrd_utils.ExecTxWithRetry(ctx, userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := userRepo.WithTx(tx)
		userImages, err := uTx.FindUserImagesByUserIdForUpdate(ctx, userId)
		if err != nil {
			return err
		}

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
				params := user_db.UpdateUserMainImageParams{
					ID:            userId,
					MainImageUrl:  mainImageUrl,
					MainImagePath: mainImagePath,
				}
				updatedUser, err1 = uTx.UpdateUserMainImage(ctx, params)
				return err1
			})

			ewg.Go(func() error {
				updatedUserImage, err2 = uTx.UpdateUserImage(ctx, params)
				return err2
			})
		}

		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, failedWhenUploadingFile, 422)
		} else if mainImageUrl != "" {
			shrd_utils.LogInfo(fmt.Sprintf("success set user main image: %s", mainImageUrl))
			updatedUser.MainImagePath = mainImagePath
			updatedUser.MainImageUrl = mainImageUrl
		}
		return nil
	})

	shrd_utils.LogIfError(err)

	if err == nil {
		go checkAndSendUpdatedUserMainImageEvent(pubsubClient, updatedUser, hasMainImage)
		go checkAndSendCreatedUserImagesEvent(pubsubClient, images, updatedUserImage, hasMainImage)
	}
}

func (s *UserSvcImpl) UploadImages(ctx context.Context, files []*multipart.FileHeader, userId uuid.UUID) []response.UserImageResp {
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.UploadImages")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	userImagesResp := make([]response.UserImageResp, len(files))
	images := make([]user_db.UserImage, len(files))

	err := shrd_utils.ExecTxWithRetry(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
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
					svcCtx,
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
				images[index] = image

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
		checkAndSetUserMainImage(s.userRepo, s.pubsubClient, images, userId)
	}()

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()

	return userImagesResp
}

func (s *UserSvcImpl) GetUserImages(ctx context.Context, userId uuid.UUID) []response.UserImageResp {
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.GetUserImages")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	ewg := errgroup.Group{}
	userImagesResp := []response.UserImageResp{}

	data, err := s.cacheSvc.GetOrSet(ctx, shrd_utils.BuildCacheKey(utils.USER_KEY, userId.String(), "GetUserImages"), func() any {
		fuiCtx, fuiTrc := shrd_utils.CreateTracer(svcCtx, "repo.FindUserImagesByUserId")
		userImages, err := s.userRepo.FindUserImagesByUserId(fuiCtx, userId)
		shrd_utils.CheckTracer(fuiTrc, err)
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when finding user images", 400)
		}

		userImagesResp = make([]response.UserImageResp, len(userImages))
		for i := range userImages {
			index := i
			ewg.Go(func() error {
				psCtx, psTrc := shrd_utils.CreateTracer(svcCtx, "GetPreSignUrl")
				preSignedUrl, err := s.fileSvc.GetPreSignUrl(psCtx, userImages[index].ImagePath)
				shrd_utils.CheckTracer(psTrc, err)
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
) (user_db.User, user_db.UserImage, error) {
	uuiCtx, uuiTrc := shrd_utils.CreateTracer(ctx, "repo.UpdateUserImage")
	image, err := uTx.UpdateUserImage(uuiCtx, user_db.UpdateUserImageParams{
		ID:     imageId,
		IsMain: true,
	})
	shrd_utils.CheckTracer(uuiTrc, err)
	if err != nil {
		return user_db.User{}, user_db.UserImage{}, err
	}

	*userImageResp = mapping.ToUserImageResp(image)

	userParams := user_db.UpdateUserMainImageParams{
		ID:            userId,
		MainImageUrl:  newMainImageUrl,
		MainImagePath: newMainImagePath,
	}

	uumiCtx, uumiTrc := shrd_utils.CreateTracer(ctx, "repo.UpdateUserMainImage")
	user, err := uTx.UpdateUserMainImage(uumiCtx, userParams)
	shrd_utils.CheckTracer(uumiTrc, err)

	return user, image, err
}

func (s *UserSvcImpl) SetMainImage(ctx context.Context, userId uuid.UUID, imageId uuid.UUID) response.UserImageResp {
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.SetMainImage")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	userImageResp := response.UserImageResp{}
	var updatedUser user_db.User
	var updatedUserImage user_db.UserImage
	var err1 error

	err := shrd_utils.ExecTxWithRetry(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)

		ewg := errgroup.Group{}
		fuiCtx, fuiTrc := shrd_utils.CreateTracer(svcCtx, "repo.FindUserImagesByUserIdForUpdate")
		userImages, err := uTx.FindUserImagesByUserIdForUpdate(fuiCtx, userId)
		shrd_utils.CheckTracer(fuiTrc, err)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
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
			updatedUser, updatedUserImage, err1 = setMainImageHelper(
				svcCtx,
				uTx,
				&userImageResp,
				userId,
				imageId,
				newMainImageUrl,
				newMainImagePath,
			)
			return err1
		})

		ewg.Go(func() error {
			uuiCtx, uuiTrc := shrd_utils.CreateTracer(svcCtx, "repo.UpdateUserImage")
			_, err = uTx.UpdateUserImage(uuiCtx, user_db.UpdateUserImageParams{
				ID:     oldMainImageId,
				IsMain: false,
			})
			shrd_utils.CheckTracer(uuiTrc, err)
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
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_TOPIC}, message.UPDATED_USER_MAIN_IMAGE_KEY, message.UpdatedUserMainImagePayload{
			ID:            updatedUser.ID,
			MainImageUrl:  updatedUser.MainImageUrl,
			MainImagePath: updatedUser.MainImagePath,
			UpdatedAt:     updatedUser.UpdatedAt,
		})
	}()

	go func() {
		ctx := context.Background()
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_IMAGE_TOPIC}, message.UPDATED_KEY, message.UpdatedUserImagePayload{
			ID:        updatedUserImage.ID,
			IsMain:    updatedUserImage.IsMain,
			UserID:    updatedUserImage.UserID,
			UpdatedAt: updatedUserImage.UpdatedAt,
		})
	}()

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()

	return userImageResp
}

func (s *UserSvcImpl) DeleteImage(ctx context.Context, userId uuid.UUID, imageId uuid.UUID) {
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.DeleteImage")
	defer shrd_utils.CheckTracerSvc(svcTrc)
	var imageID uuid.UUID

	err := shrd_utils.ExecTxWithRetry(ctx, s.userRepo.GetDB(), func(tx *sql.Tx) error {
		uTx := s.userRepo.WithTx(tx)
		ewg := errgroup.Group{}
		fuiCtx, fuiTrc := shrd_utils.CreateTracer(svcCtx, "repo.FindUserImageById")
		image, err := uTx.FindUserImageById(fuiCtx, imageId)
		shrd_utils.CheckTracer(fuiTrc, err)
		// possible replace --> err != nil && err == sql.ErrNoRows
		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "image not found", 404)
		}

		if image.UserID != userId {
			return shrd_utils.CustomError("not authorize to perform this operation", 403)
		}

		if image.IsMain {
			return shrd_utils.CustomError("you can't delete the main image", 400)
		}

		ewg.Go(func() error {
			dfCtx, dfTrc := shrd_utils.CreateTracer(svcCtx, "DeleteFile")
			err := s.fileSvc.DeleteFile(dfCtx, s.config.S3PrivateBucketName, image.ImagePath)
			shrd_utils.CheckTracer(dfTrc, err)
			return err
		})

		ewg.Go(func() error {
			duiCtx, duiTrc := shrd_utils.CreateTracer(svcCtx, "DeleteFile")
			err := uTx.DeleteUserImage(duiCtx, image.ID)
			shrd_utils.CheckTracer(duiTrc, err)
			return err
		})

		if err := ewg.Wait(); err != nil {
			return shrd_utils.CustomErrorWithTrace(err, "failed when deleting image", 422)
		}

		imageID = image.ID
		return nil
	})

	shrd_utils.PanicIfError(err)

	go func() {
		ctx := context.Background()
		s.pubsubClient.CheckTopicAndPublish(ctx, []string{message.USER_IMAGE_TOPIC}, message.DELETED_KEY, message.DeletedUserImagePayload{
			ID: imageID,
		})
	}()

	go func() {
		ctx := context.Background()
		s.cacheSvc.DelByPrefix(ctx, shrd_utils.BuildPrefixKey(utils.USER_KEY, userId.String()))
		s.cacheSvc.DelByPrefix(ctx, utils.USERS_KEY)
	}()
}

func (s *UserSvcImpl) GetUsers(ctx context.Context, input request.PaginationReq) response.UsersWithPaginationResp {
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.GetUsers")
	defer shrd_utils.CheckTracerSvc(svcTrc)
	cacheDuration := time.Duration(1 * time.Microsecond)

	if input.IsCache == "true" {
		cacheDuration = time.Duration(1 * time.Hour)
	}

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
			fuCtx, fuTrc := shrd_utils.CreateTracer(svcCtx, "repo.FindUsers")
			users, err1 = s.userRepo.FindUsers(fuCtx, params)
			shrd_utils.CheckTracer(fuTrc, err1)
			return err1
		})

		ewg1.Go(func() error {
			gupCtx, gupTrc := shrd_utils.CreateTracer(svcCtx, "repo.GetUsersPaginationCount")
			counts, err2 = s.userRepo.GetUsersPaginationCount(gupCtx, user_db.GetUsersPaginationCountParams{
				SearchValue: "%" + input.SearchValue + "%",
				SearchField: input.SearchField,
				FilterBy:    input.FilterBy,
			})
			shrd_utils.CheckTracer(gupTrc, err2)
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
					psCtx, psTrc := shrd_utils.CreateTracer(svcCtx, "GetPreSignUrl")
					preSignedUrl, err := s.fileSvc.GetPreSignUrl(psCtx, users[index].MainImagePath)
					shrd_utils.CheckTracer(psTrc, err)
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
	}, cacheDuration)

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
	svcCtx, svcTrc := shrd_utils.CreateTracer(ctx, "service.GetUser")
	defer shrd_utils.CheckTracerSvc(svcTrc)

	ewg := errgroup.Group{}
	userWithImagesResp := response.UserWithImagesResp{}
	data, err := s.cacheSvc.GetOrSet(ctx, shrd_utils.BuildCacheKey(utils.USER_KEY, userId.String(), "GetUser"), func() any {
		dbCtx, dbTrc := shrd_utils.CreateTracer(svcCtx, "repo.GetUser")
		user, err := s.userRepo.FindUserWithImages(dbCtx, userId)
		shrd_utils.CheckTracer(dbTrc, err)
		// possible replace --> err != nil && err == sql.ErrNoRows

		if err != nil {
			return shrd_utils.CustomErrorWithTrace(err, userNotFound, 404)
		}

		userWithImagesResp := mapping.ToUserWithImagesResp(user)

		for i := range userWithImagesResp.Images {
			index := i
			path := userWithImagesResp.Images[index].ImagePath

			ewg.Go(func() error {
				psCtx, psTrc := shrd_utils.CreateTracer(svcCtx, "GetPreSignedUrl")
				err := getUserHelper(
					psCtx,
					s.fileSvc,
					userWithImagesResp,
					index,
					path,
				)
				shrd_utils.CheckTracer(psTrc, err)
				return err
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
