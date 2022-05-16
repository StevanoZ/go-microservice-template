package user_db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func SetUpDB() *sql.DB {
	config := shrd_utils.LoadBaseConfig("../../../app", "test")
	return shrd_utils.ConnectDB(config.DBDriver, config.DBSource)
}

func CleanUpDB(DB *sql.DB) {
	DB.ExecContext(context.Background(), "DELETE FROM user_image")
	DB.ExecContext(context.Background(), "DELETE FROM public.user")
	//	DB.Exec(schema.UserDBSchema)
}

func InitUserRepo(DB *sql.DB) UserRepo {
	CleanUpDB(DB)
	return NewUserRepo(DB)
}

func buildCreateUserParams() CreateUserParams {
	return CreateUserParams{
		ID:       uuid.New(),
		Username: shrd_utils.RandomUsername(),
		Email:    shrd_utils.RandomEmail(),
		OtpCode:  shrd_utils.RandomInt(0, 999999),
		Password: shrd_utils.RandomString(12),
	}
}

func createUserMock(userRepo UserRepo) User {
	ctx := context.Background()
	user, _ := userRepo.CreateUser(ctx, buildCreateUserParams())
	return user
}

func createUsersMock(userRepo UserRepo) {
	wg := sync.WaitGroup{}
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			ctx := context.Background()
			createUserParams := buildCreateUserParams()
			user, _ := userRepo.CreateUser(ctx, createUserParams)
			if index < 4 {
				updateUserParams := UpdateUserParams{
					ID:          user.ID,
					Username:    "Test-0" + strconv.Itoa(index+1),
					Password:    user.Password,
					PhoneNumber: user.PhoneNumber,
					OtpCode:     0,
					AttemptLeft: 0,
					Status:      "active",
				}
				userRepo.UpdateUser(ctx, updateUserParams)
			}
		}(i)

	}
	wg.Wait()

}

func createkUserWithImagesMock(userRepo UserRepo) User {
	wg := sync.WaitGroup{}
	ctx := context.Background()
	user, _ := userRepo.CreateUser(ctx, buildCreateUserParams())

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			isMain := false
			if index == 4 {
				isMain = true
			}
			userRepo.CreateUserImage(ctx, CreateUserImageParams{
				ID:        uuid.New(),
				IsMain:    isMain,
				UserID:    user.ID,
				ImageUrl:  fmt.Sprintf("http://test/image-url/image-%s", strconv.Itoa(index+1)),
				ImagePath: "http://test/image-path",
			})
		}(i)
	}
	wg.Wait()
	return user
}

func createMockUserImage(userRepo UserRepo, userId uuid.UUID) []UserImage {
	wg := sync.WaitGroup{}
	ctx := context.Background()
	userImages := make([]UserImage, 4)

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			isMain := false
			if index == 3 {
				isMain = true
			}
			userImage, _ := userRepo.CreateUserImage(ctx, CreateUserImageParams{
				ID:        uuid.New(),
				IsMain:    isMain,
				UserID:    userId,
				ImageUrl:  fmt.Sprintf("http://test/image-url/image-%s", strconv.Itoa(index+1)),
				ImagePath: "http://test/image-path",
			})
			userImages[index] = userImage
		}(i)
	}
	wg.Wait()
	return userImages
}
func TestCreateUser(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)
	params := buildCreateUserParams()
	user, err := userRepo.CreateUser(context.Background(), params)

	assert.NoError(t, err)
	assert.Equal(t, params.ID, user.ID)
	assert.Equal(t, params.Email, user.Email)
	assert.Equal(t, params.OtpCode, user.OtpCode)
	assert.Equal(t, 5, int(user.AttemptLeft))
	assert.Equal(t, "not-active", user.Status)
}

func TestUpdateUser(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)

	createParam := buildCreateUserParams()
	user, err := userRepo.CreateUser(context.Background(), createParam)
	assert.NoError(t, err)
	updateParams := UpdateUserParams{
		ID:          user.ID,
		Username:    "TESTING",
		PhoneNumber: "082111112233",
		Password:    user.Password,
		OtpCode:     user.OtpCode,
		AttemptLeft: user.AttemptLeft,
		Status:      "active",
	}

	user, err = userRepo.UpdateUser(context.Background(), updateParams)

	assert.NoError(t, err)
	assert.Equal(t, updateParams.Username, user.Username)
	assert.Equal(t, updateParams.PhoneNumber, user.PhoneNumber)
	assert.Equal(t, updateParams.Status, user.Status)
}

func TestGetUsersAndPagination(t *testing.T) {
	DB := SetUpDB()

	userRepo := InitUserRepo(DB)
	createUsersMock(userRepo)

	// should filter by default by status = 'active'
	users, err := userRepo.FindUsers(context.Background(), FindUsersParams{
		Offset: 0,
		Limit:  15,
	})
	assert.NoError(t, err)
	assert.Equal(t, 4, len(users))

	// should filter by status = 'active'
	users, err = userRepo.FindUsers(context.Background(), FindUsersParams{
		Offset:   0,
		Limit:    15,
		FilterBy: "not-active",
	})
	assert.NoError(t, err)
	assert.Equal(t, 11, len(users))

	// should filter by username = 'TesT'
	users, err = userRepo.FindUsers(context.Background(), FindUsersParams{
		Offset:      0,
		Limit:       15,
		FilterBy:    "active",
		SearchField: "username",
		SearchValue: "%" + "TesT" + "%",
	})
	assert.NoError(t, err)
	assert.Equal(t, 4, len(users))

	// should return page 2
	users, err = userRepo.FindUsers(context.Background(), FindUsersParams{
		Offset:   10,
		Limit:    10,
		FilterBy: "not-active",
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(users))

	// should sort by username DESC
	users, err = userRepo.FindUsers(context.Background(), FindUsersParams{
		Offset:   0,
		Limit:    10,
		FilterBy: "active",
		SortBy:   "-username",
	})
	assert.NoError(t, err)
	assert.Equal(t, 4, len(users))
	assert.Equal(t, "Test-04", users[0].Username)

	counts, err := userRepo.GetUsersPaginationCount(context.Background(), GetUsersPaginationCountParams{
		FilterBy: "not-active",
	})
	assert.NoError(t, err)
	assert.Equal(t, 11, int(counts))

	counts, err = userRepo.GetUsersPaginationCount(context.Background(), GetUsersPaginationCountParams{
		SearchField: "username",
		SearchValue: "%" + "TesT" + "%",
		FilterBy:    "active",
	})
	assert.NoError(t, err)
	assert.Equal(t, 4, int(counts))

	// BAD CASE
	DB.Close()
	users, err = userRepo.FindUsers(context.Background(), FindUsersParams{
		Offset: 0,
		Limit:  10,
	})
	assert.Error(t, err)
	assert.Nil(t, users)
}

func TestCreateUserImage(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)
	user := createUserMock(userRepo)

	imageUrl := "http://test/image-url"
	userImage, err := userRepo.CreateUserImage(context.Background(), CreateUserImageParams{
		ID:        uuid.New(),
		UserID:    user.ID,
		ImageUrl:  imageUrl,
		ImagePath: "http://test/image-path",
	})

	assert.NoError(t, err)
	assert.Equal(t, user.ID, userImage.UserID)
	assert.Equal(t, imageUrl, userImage.ImageUrl)
	assert.Equal(t, false, userImage.IsMain)
}

func TestUpdateUserImage(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)
	user := createUserMock(userRepo)

	imageUrl := "http://test/image-url"
	userImage, err := userRepo.CreateUserImage(context.Background(), CreateUserImageParams{
		ID:        uuid.New(),
		UserID:    user.ID,
		ImageUrl:  imageUrl,
		ImagePath: "http://test/image-path",
	})

	assert.NoError(t, err)

	userImage, err = userRepo.UpdateUserImage(context.Background(), UpdateUserImageParams{
		ID:     userImage.ID,
		IsMain: true,
	})
	assert.NoError(t, err)
	assert.Equal(t, true, userImage.IsMain)

}

func TestUpdateUserMainImage(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)
	user := createUserMock(userRepo)

	imageUrl := "http://test/image-url"
	imagePath := "http://test/image-path"

	updatedUser, err := userRepo.UpdateUserMainImage(context.Background(), UpdateUserMainImageParams{
		ID:            user.ID,
		MainImageUrl:  imageUrl,
		MainImagePath: imagePath,
	})
	assert.NoError(t, err)
	assert.Equal(t, imageUrl, updatedUser.MainImageUrl)
	assert.Equal(t, imagePath, updatedUser.MainImagePath)
}

func TestFindUserById(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)

	user1 := createUserMock(userRepo)

	user2, err := userRepo.FindUserById(context.Background(), user1.ID)
	assert.NoError(t, err)
	assert.Equal(t, user1.ID, user2.ID)
	assert.Equal(t, user1.Email, user2.Email)
}

func TestFindUserEmail(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)

	user1 := createUserMock(userRepo)

	user2, err := userRepo.FindUserByEmail(context.Background(), user1.Email)
	assert.NoError(t, err)
	assert.Equal(t, user1.ID, user2.ID)
	assert.Equal(t, user1.Email, user2.Email)
}

func TestFindUserWithImages(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)
	user := createkUserWithImagesMock(userRepo)

	userWithImages, err := userRepo.FindUserWithImages(context.Background(), user.ID)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, userWithImages.ID)

	images := []UserImage{}
	err = json.Unmarshal(userWithImages.Images, &images)
	assert.NoError(t, err)
	assert.Equal(t, 5, len(images))
}
func TestDeleteUser(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)

	user1 := createUserMock(userRepo)

	user2, err := userRepo.FindUserById(context.Background(), user1.ID)
	assert.NoError(t, err)

	assert.NotNil(t, user2)

	err = userRepo.DeleteUser(context.Background(), user1.ID)
	assert.NoError(t, err)

	_, err = userRepo.FindUserById(context.Background(), user1.ID)

	assert.Equal(t, sql.ErrNoRows, err)

}

func TestFindUserImageById(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)

	user := createUserMock(userRepo)
	images := createMockUserImage(userRepo, user.ID)

	userImage, err := userRepo.FindUserImageById(context.Background(), images[0].ID)
	assert.NoError(t, err)
	assert.Equal(t, images[0].ID, userImage.ID)
	assert.Equal(t, images[0].ImageUrl, userImage.ImageUrl)
	assert.Equal(t, images[0].IsMain, userImage.IsMain)
}

func TestFindImagesByUserId(t *testing.T) {
	DB := SetUpDB()

	userRepo := InitUserRepo(DB)

	user := createUserMock(userRepo)
	createMockUserImage(userRepo, user.ID)

	userImage, err := userRepo.FindUserImagesByUserId(context.Background(), user.ID)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(userImage))

	// NOT FOUND
	userImage, err = userRepo.FindUserImagesByUserId(context.Background(), uuid.New())
	assert.NoError(t, err)
	assert.Equal(t, 0, len(userImage))

	// BAD CASE
	DB.Close()
	userImage, err = userRepo.FindUserImagesByUserId(context.Background(), user.ID)
	assert.Error(t, err)
	assert.Nil(t, userImage)
}

func TestDeleteUserImage(t *testing.T) {
	DB := SetUpDB()
	defer DB.Close()

	userRepo := InitUserRepo(DB)

	user := createUserMock(userRepo)
	images := createMockUserImage(userRepo, user.ID)

	err := userRepo.DeleteUserImage(context.Background(), images[0].ID)
	assert.NoError(t, err)

	_, err = userRepo.FindUserImageById(context.Background(), images[0].ID)
	assert.Equal(t, sql.ErrNoRows, err)
}
