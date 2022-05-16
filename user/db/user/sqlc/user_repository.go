package user_db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

type UserRepo interface {
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	CreateUserImage(ctx context.Context, arg CreateUserImageParams) (UserImage, error)
	DeleteUser(ctx context.Context, id uuid.UUID) error
	DeleteUserImage(ctx context.Context, id uuid.UUID) error
	FindUserByEmail(ctx context.Context, email string) (User, error)
	FindUserById(ctx context.Context, id uuid.UUID) (User, error)
	FindUserImageById(ctx context.Context, id uuid.UUID) (UserImage, error)
	FindUserImagesByUserId(ctx context.Context, userID uuid.UUID) ([]UserImage, error)
	FindUserWithImages(ctx context.Context, id uuid.UUID) (FindUserWithImagesRow, error)
	FindUsers(ctx context.Context, arg FindUsersParams) ([]User, error)
	GetUsersPaginationCount(ctx context.Context, arg GetUsersPaginationCountParams) (int64, error)
	UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error)
	UpdateUserImage(ctx context.Context, arg UpdateUserImageParams) (UserImage, error)
	UpdateUserMainImage(ctx context.Context, arg UpdateUserMainImageParams) (User, error)

	WithTx(tx *sql.Tx) Querier
	GetDB() *sql.DB
}

type UserRepoImpl struct {
	db *sql.DB
	*Queries
}

func NewUserRepo(db *sql.DB) UserRepo {
	return &UserRepoImpl{
		db:      db,
		Queries: New(db),
	}
}

func (r *UserRepoImpl) WithTx(tx *sql.Tx) Querier {
	return &Queries{
		db: tx,
	}
}

func (r *UserRepoImpl) GetDB() *sql.DB {
	return r.db
}
