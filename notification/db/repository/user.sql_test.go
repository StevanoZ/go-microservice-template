package querier

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

const (
	imageUrl  = "https//test-image.com"
	imagePath = "/images/test"
)

func SetupDB() *sql.DB {
	config := shrd_utils.LoadBaseConfig("../../app", "test")
	return shrd_utils.ConnectDB(config.DBDriver, config.DBSource)
}

func CleanupDB(DB *sql.DB) {
	DB.ExecContext(context.Background(), "DELETE FROM user_image")
	DB.ExecContext(context.Background(), "DELETE FROM public.user")
	DB.ExecContext(context.Background(), "DELETE FROM error_message")
}

func InitRepository(db *sql.DB) Repository {
	return NewRepository(db)
}

func createUserParams() CreateUserParams {
	return CreateUserParams{
		ID:        uuid.New(),
		Email:     shrd_utils.RandomEmail(),
		Username:  shrd_utils.RandomUsername(),
		OtpCode:   shrd_utils.RandomInt(0, 999999),
		Password:  shrd_utils.RandomString(12),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func createUserMock(t *testing.T, repo Repository) User {
	params := createUserParams()
	user, err := repo.CreateUser(context.Background(), params)
	assert.NoError(t, err)

	return user
}

func createUserImageParams(userID uuid.UUID, isMain ...bool) CreateUserImageParams {
	isSetMainImage := false
	if len(isMain) > 0 {
		isSetMainImage = true
	}
	return CreateUserImageParams{
		ID:        uuid.New(),
		ImageUrl:  imageUrl,
		ImagePath: imagePath,
		UserID:    userID,
		IsMain:    isSetMainImage,
		UpdatedAt: time.Now(),
		CreatedAt: time.Now(),
	}
}

func createUserImageMock(t *testing.T, repo Repository, userID uuid.UUID, isMain ...bool) UserImage {
	params := createUserImageParams(userID, isMain...)
	userImage, err := repo.CreateUserImage(context.Background(), params)
	assert.NoError(t, err)

	return userImage
}

func TestMain(m *testing.M) {
	CleanupDB(SetupDB())

	os.Exit(m.Run())
}

func TestCreateUser(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully create user", func(t *testing.T) {
		params := createUserParams()
		user, err := repo.CreateUser(ctx, params)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, params.ID, user.ID)
	})
}

func TestUpdateUser(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully update user", func(t *testing.T) {
		updatedUsername := "Updated!"
		updatedOtpCode := 723456
		updatedAttemptLeft := 3
		newupdatedAt := time.Now()

		user := createUserMock(t, repo)
		assert.NotNil(t, user)

		params := UpdateUserParams{
			ID:          user.ID,
			Username:    updatedUsername,
			OtpCode:     int64(updatedOtpCode),
			AttemptLeft: int32(updatedAttemptLeft),
			UpdatedAt:   newupdatedAt,
		}
		updatedUser, err := repo.UpdateUser(ctx, params)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, updatedUser.ID)
		assert.Equal(t, updatedUsername, updatedUser.Username)
		assert.Equal(t, int64(updatedOtpCode), updatedUser.OtpCode)
		assert.Equal(t, int32(updatedAttemptLeft), updatedUser.AttemptLeft)
		assert.Equal(t, newupdatedAt.Unix(), updatedUser.UpdatedAt.Unix())
	})
}

func TestDeleteUser(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully delete user", func(t *testing.T) {
		createdUser := createUserMock(t, repo)
		assert.NotNil(t, createdUser)

		user, err := repo.FindUserByIdForUpdate(ctx, createdUser.ID)
		assert.NoError(t, err)
		assert.NotNil(t, user)

		err = repo.DeleteUser(ctx, createdUser.ID)
		assert.NoError(t, err)

		_, err = repo.FindUserByIdForUpdate(ctx, createdUser.ID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, sql.ErrNoRows)
	})
}

func TestFindUserByIdForUpdate(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully find user by ID", func(t *testing.T) {
		createdUser := createUserMock(t, repo)
		assert.NotNil(t, createdUser)

		user, err := repo.FindUserByIdForUpdate(ctx, createdUser.ID)
		assert.NoError(t, err)
		assert.Equal(t, createdUser.ID, user.ID)
	})
}

func TestCreateUserImage(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully find user image by ID", func(t *testing.T) {
		user := createUserMock(t, repo)
		assert.NotNil(t, user)

		params := createUserImageParams(user.ID, true)

		createdImage, err := repo.CreateUserImage(ctx, params)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, createdImage.UserID)
		assert.Equal(t, true, createdImage.IsMain)
	})
}

func TestFindUserImageByIdForUpdate(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully find user image by ID", func(t *testing.T) {
		user := createUserMock(t, repo)
		assert.NotNil(t, user)

		createdImage := createUserImageMock(t, repo, user.ID)
		assert.NotNil(t, createdImage)

		image, err := repo.FindUserImageByIdForUpdate(ctx, createdImage.ID)
		assert.NoError(t, err)
		assert.Equal(t, createdImage.ID, image.ID)
		assert.Equal(t, false, image.IsMain)
	})
}

func TestFindUserMainImageByUserIdForUpdate(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully find user image by ID", func(t *testing.T) {
		user := createUserMock(t, repo)
		assert.NotNil(t, user)

		createdImage := createUserImageMock(t, repo, user.ID, true)
		assert.NotNil(t, createdImage)

		image, err := repo.FindUserMainImageByUserIdForUpdate(ctx, createdImage.UserID)
		assert.NoError(t, err)
		assert.Equal(t, createdImage.ID, image.ID)
		assert.Equal(t, true, image.IsMain)
	})
}

func TestUpdateUserImage(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully update user image", func(t *testing.T) {
		user := createUserMock(t, repo)
		createdImage := createUserImageMock(t, repo, user.ID)
		assert.Equal(t, false, createdImage.IsMain)

		updatedImage, err := repo.UpdateUserImage(ctx, UpdateUserImageParams{
			IsMain: true,
			ID:     createdImage.ID,
		})
		assert.NoError(t, err)
		assert.Equal(t, createdImage.ID, updatedImage.ID)
		assert.Equal(t, true, updatedImage.IsMain)
	})
}

func TestUpdateUserMainImage(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully update user main image", func(t *testing.T) {
		user := createUserMock(t, repo)
		assert.Empty(t, user.MainImageUrl)
		assert.Empty(t, user.MainImagePath)

		updatedUser, err := repo.UpdateUserMainImage(ctx, UpdateUserMainImageParams{
			MainImageUrl:  imageUrl,
			MainImagePath: imagePath,
			ID:            user.ID,
		})
		assert.NoError(t, err)
		assert.Equal(t, user.ID, updatedUser.ID)
		assert.Equal(t, imageUrl, updatedUser.MainImageUrl)
		assert.Equal(t, imagePath, updatedUser.MainImagePath)
	})
}

func TestDeleteUserImage(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully delete user image", func(t *testing.T) {
		user := createUserMock(t, repo)
		createdImage := createUserImageMock(t, repo, user.ID)

		image, err := repo.FindUserImageByIdForUpdate(ctx, createdImage.ID)
		assert.NoError(t, err)
		assert.Equal(t, createdImage.ID, image.ID)

		err = repo.DeleteUserImage(ctx, createdImage.ID)
		assert.NoError(t, err)

		_, err = repo.FindUserImageByIdForUpdate(ctx, createdImage.ID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, sql.ErrNoRows)
	})
}
