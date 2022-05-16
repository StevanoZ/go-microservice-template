package user_db

import (
	"context"
	"testing"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/stretchr/testify/assert"
)

func TestUserRepo(t *testing.T) {
	config := shrd_utils.LoadBaseConfig("../../../app", "test")
	DB := shrd_utils.ConnectDB(config.DBDriver, config.DBSource)

	userRepo := NewUserRepo(DB)

	assert.NotNil(t, userRepo.GetDB())

	tx, err := DB.BeginTx(context.Background(), nil)
	assert.NoError(t, err)
	assert.NotNil(t, userRepo.WithTx(tx))
}
