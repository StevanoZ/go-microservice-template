package response

import (
	"time"

	"github.com/google/uuid"
)

type Next struct {
	Page int `json:"page"`
}

type Prev struct {
	Page int `json:"page"`
}

type PaginationResp struct {
	Total      int  `json:"total"`
	IsLoadMore bool `json:"isLoadMore"`
	Next       Next `json:"next"`
	Prev       Prev `json:"prev"`
}

type UserResp struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
	PhoneNumber  string    `json:"phoneNumber"`
	Status       string    `json:"status"`
	MainImageUrl string    `json:"mainImageUrl"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type UserImageResp struct {
	ID        uuid.UUID `json:"id"`
	ImageUrl  string    `json:"imageUrl"`
	ImagePath string    `json:"imagePath"`
	IsMain    bool      `json:"isMain"`
	UserId    uuid.UUID `json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type UserWithTokenResp struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
	PhoneNumber  string    `json:"phoneNumber"`
	Status       string    `json:"status"`
	MainImageUrl string    `json:"mainImageUrl"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Token        string    `json:"token"`
}

type UserWithImagesResp struct {
	ID            uuid.UUID       `json:"id"`
	Email         string          `json:"email"`
	Username      string          `json:"username"`
	PhoneNumber   string          `json:"phoneNumber"`
	Status        string          `json:"status"`
	MainImageUrl  string          `json:"mainImageUrl"`
	MainImagePath string          `json:"mainImagepath"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
	Images        []UserImageResp `json:"images"`
}

type UsersWithPaginationResp struct {
	Users      []UserResp     `json:"users"`
	Pagination PaginationResp `json:"pagination"`
}
