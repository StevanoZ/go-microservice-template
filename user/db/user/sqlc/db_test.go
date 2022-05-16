package user_db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDB(t *testing.T) {
	DB := SetUpDB()
	queries := New(DB)
	tx, err := DB.BeginTx(context.Background(), nil)
	assert.NoError(t, err)
	q := queries.WithTx(tx)
	assert.NotNil(t, q)
}
