package request

import (
	"github.com/google/uuid"
)

type SignUpReq struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email" validate:"required,email"`
	Username string    `json:"username" validate:"required,min=3,max=10"`
	Password string    `json:"password" validate:"required,min=6,max=15"`
}

type LogInReq struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6,max=15"`
}

type VerifyOtpReq struct {
	OtpCode string `json:"otpCode" validate:"required,len=6"`
	Email   string `json:"email" validate:"required,email"`
}

type ResendOtpReq struct {
	Email string `json:"email" validate:"required,email"`
}

type UpdateUserReq struct {
	Username    string `json:"username" validate:"required,min=3,max=10"`
	PhoneNumber string `json:"phoneNumber" validate:"required,min=12,max=14"`
}
