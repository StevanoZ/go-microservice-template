package querier

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

const serviceName = "testing-project"
const payloadName = "message-payload-name"
const topic = "TEST_TOPIC"
const orderingKey = "message-ordering-key"
const messageId = "123"
const msgDescription = "failed when consumming message payload"
const concurrencyNum = 50

type messagePayload struct {
	ID        uuid.UUID
	Email     string
	Username  string
	CreatedAt time.Time
}

func createMsgPayload() messagePayload {
	return messagePayload{
		ID:        uuid.New(),
		Email:     shrd_utils.RandomEmail(),
		Username:  shrd_utils.RandomUsername(),
		CreatedAt: time.Now(),
	}
}

func createErrorMsgParams(t *testing.T, msg messagePayload) CreateErrorMessageParams {
	payload, err := json.Marshal(msg)
	assert.NoError(t, err)

	return CreateErrorMessageParams{
		ServiceName: serviceName,
		OrderingKey: orderingKey,
		Topic:       topic,
		PayloadName: payloadName,
		PayloadData: string(payload),
		MessageID:   messageId,
		Description: msgDescription,
	}
}

// func createErrorMsgMock(t *testing.T, repo Repository) ErrorMessage {
// 	msg := createMsgPayload()
// 	params := createErrorMsgParams(t, msg)
// 	message, err := repo.CreateErrorMessage(context.Background(), params)
// 	assert.NoError(t, err)

// 	return message
// }

func TestCreateErrorMessage(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully create error message", func(t *testing.T) {
		params := createErrorMsgParams(t, createMsgPayload())
		createdMsg, err := repo.CreateErrorMessage(ctx, params)
		assert.NoError(t, err)
		assert.Equal(t, serviceName, createdMsg.ServiceName)
		assert.Equal(t, orderingKey, createdMsg.OrderingKey)
		assert.Equal(t, messageId, createdMsg.MessageID)
		assert.Equal(t, topic, createdMsg.Topic)
	})
}

func TestErrorMessage(t *testing.T) {
	DB := SetupDB()
	defer DB.Close()

	// CONCURRENCY ISSUES, NEEED TO RE-CLEAN DB
	CleanupDB(DB)
	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Successfully create, find, and delete error message", func(t *testing.T) {
		data := createMsgPayload()
		params := createErrorMsgParams(t, data)
		createdMsg, err := repo.CreateErrorMessage(ctx, params)
		assert.NoError(t, err)

		messages, err := repo.FindErrorMessage(ctx, FindErrorMessageParams{
			Topic:       createdMsg.Topic,
			OrderingKey: createdMsg.OrderingKey,
		})
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		var payload messagePayload

		// MAKE SURE DATA PAYLOAD
		err = json.Unmarshal([]byte(messages[0].PayloadData), &payload)
		assert.NoError(t, err)
		assert.Equal(t, data.ID, payload.ID)
		assert.Equal(t, data.Email, payload.Email)
		assert.Equal(t, data.Username, payload.Username)
		assert.Equal(t, data.CreatedAt.UTC(), payload.CreatedAt.UTC())

		err = repo.DeleteErrorMessage(ctx, createdMsg.ID)
		assert.NoError(t, err)

		messages, err = repo.FindErrorMessage(ctx, FindErrorMessageParams{
			Topic:       createdMsg.Topic,
			OrderingKey: createdMsg.OrderingKey,
		})
		assert.NoError(t, err)
		assert.Equal(t, 0, len(messages))
	})
}

func TestDeleteErrorMessage(t *testing.T) {
	DB := SetupDB()

	// CONCURRENCY ISSUES, NEEED TO RE-CLEAN DB
	CleanupDB(DB)
	ctx := context.Background()
	repo := InitRepository(DB)

	t.Run("Bad case", func(t *testing.T) {
		data := createMsgPayload()
		params := createErrorMsgParams(t, data)
		createdMsg, err := repo.CreateErrorMessage(ctx, params)
		assert.NoError(t, err)

		tx, err := DB.BeginTx(ctx, nil)
		assert.NoError(t, err)
		repoTx := repo.WithTx(tx)
		ewg := errgroup.Group{}

		for i := 0; i < concurrencyNum; i++ {
			ewg.Go(func() error {
				_, err := repoTx.FindErrorMessage(ctx, FindErrorMessageParams{
					Topic:       createdMsg.Topic,
					OrderingKey: createdMsg.OrderingKey,
				})
				return err
			})

		}
		err = ewg.Wait()
		assert.Error(t, err)

		DB.Close()
		messages, err := repo.FindErrorMessage(ctx, FindErrorMessageParams{
			Topic:       createdMsg.Topic,
			OrderingKey: createdMsg.OrderingKey,
		})
		assert.Error(t, err)
		assert.Equal(t, 0, len(messages))
	})
}
