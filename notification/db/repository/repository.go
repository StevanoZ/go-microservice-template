package querier

import "database/sql"

type Repository interface {
	Querier

	WithTx(tx *sql.Tx) Querier
	GetDB() *sql.DB
}

type RepositoryImpl struct {
	db *sql.DB
	*Queries
}

func NewRepository(db *sql.DB) Repository {
	return &RepositoryImpl{db: db, Queries: New(db)}
}

func (r *RepositoryImpl) WithTx(tx *sql.Tx) Querier {
	return &Queries{
		db: tx,
	}
}

func (r *RepositoryImpl) GetDB() *sql.DB {
	return r.db
}
