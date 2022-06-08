package querier

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	queries := New(SetupDB())
	assert.NotNil(t, queries)
	assert.IsType(t, &Queries{}, queries)
}

func TestWithTx(t *testing.T) {
	DB := SetupDB()
	tx, err := DB.BeginTx(context.Background(), nil)
	assert.NoError(t, err)
	queries := New(DB)
	queriesTx := queries.WithTx(tx)
	assert.IsType(t, &Queries{}, queriesTx)
}
