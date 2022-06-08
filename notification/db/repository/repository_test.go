package querier

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRepository(t *testing.T) {
	DB := SetupDB()
	repo := NewRepository(DB)
	assert.IsType(t, &RepositoryImpl{}, repo)
}

func TestRepoWithTx(t *testing.T) {
	DB := SetupDB()
	tx, err := DB.BeginTx(context.Background(), nil)
	assert.NoError(t, err)

	repo := NewRepository(DB)
	querierTx := repo.WithTx(tx)
	assert.NotNil(t, querierTx)
}

func TestGetDB(t *testing.T) {
	DB := SetupDB()

	repo := NewRepository(DB)
	assert.IsType(t, &sql.DB{}, repo.GetDB())
}
