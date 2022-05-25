package user_db

import (
	"database/sql"
)

type UserRepo interface {
	Querier

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
