package mapping

import (
	"encoding/json"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	user_db "github.com/StevanoZ/dv-user/db/user/sqlc"
	"github.com/StevanoZ/dv-user/dtos/request"
	"github.com/StevanoZ/dv-user/dtos/response"
)

// RESPONSES
func ToUserResp(user user_db.User) response.UserResp {
	return response.UserResp{
		ID:           user.ID,
		Email:        user.Email,
		Username:     user.Username,
		Status:       user.Status,
		PhoneNumber:  user.PhoneNumber,
		MainImageUrl: user.MainImageUrl,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}

func ToUserWithTokenResp(user user_db.User) response.UserWithTokenResp {
	return response.UserWithTokenResp{
		ID:           user.ID,
		Email:        user.Email,
		Username:     user.Username,
		Status:       user.Status,
		PhoneNumber:  user.PhoneNumber,
		MainImageUrl: user.MainImageUrl,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}

func ToUserImageResp(image user_db.UserImage) response.UserImageResp {
	return response.UserImageResp{
		ID:        image.ID,
		ImageUrl:  image.ImageUrl,
		ImagePath: image.ImagePath,
		UserId:    image.UserID,
		IsMain:    image.IsMain,
		CreatedAt: image.CreatedAt,
		UpdatedAt: image.UpdatedAt,
	}
}

func ToUserWithImagesResp(user user_db.FindUserWithImagesRow) response.UserWithImagesResp {
	images := []user_db.UserImage{}
	imagesResp := []response.UserImageResp{}
	json.Unmarshal(user.Images, &images)

	for _, img := range images {
		if img.ID != shrd_utils.DEFAULT_UUID {
			imageResp := ToUserImageResp(img)
			imagesResp = append(imagesResp, imageResp)
		}
	}

	return response.UserWithImagesResp{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Username,
		PhoneNumber:   user.PhoneNumber,
		Status:        user.Status,
		MainImageUrl:  user.MainImageUrl,
		MainImagePath: user.MainImagePath,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		Images:        imagesResp,
	}
}

func ToPaginationResp(page int, limit int, total int) response.PaginationResp {
	var nextPage response.Next
	var prevPage response.Prev
	isLoadMore := false

	if (page * limit) < total {
		nextPage.Page = page + 1
		isLoadMore = true
	} else {
		nextPage.Page = -1
		isLoadMore = false
	}

	if page > 1 {
		prevPage.Page = page - 1
	} else {
		prevPage.Page = -1
	}

	return response.PaginationResp{
		Next:       nextPage,
		Prev:       prevPage,
		Total:      total,
		IsLoadMore: isLoadMore,
	}
}

// PARAMS
func ToCreateUserParams(r request.SignUpReq) user_db.CreateUserParams {
	return user_db.CreateUserParams{
		ID:       r.ID,
		Email:    r.Email,
		Username: r.Username,
		Password: r.Password,
	}
}

func ToUpdateUserParams(user user_db.User) user_db.UpdateUserParams {
	return user_db.UpdateUserParams{
		ID:          user.ID,
		Username:    user.Username,
		OtpCode:     user.OtpCode,
		AttemptLeft: user.AttemptLeft,
		Password:    user.Password,
		Status:      user.Status,
		PhoneNumber: user.PhoneNumber,
	}
}
