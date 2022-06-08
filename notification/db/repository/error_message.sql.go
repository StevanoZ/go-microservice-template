// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.13.0
// source: error_message.sql

package querier

import (
	"context"
)

const createErrorMessage = `-- name: CreateErrorMessage :one

INSERT INTO
    "error_message"(
        service_name,
        payload_name,
        payload_data,
        message_id,
        topic,
        ordering_key,
        description
    )
VALUES
    ($1, $2, $3, $4, $5, $6, $7) RETURNING id, service_name, payload_name, payload_data, message_id, topic, ordering_key, description, created_at, updated_at
`

type CreateErrorMessageParams struct {
	ServiceName string `json:"service_name"`
	PayloadName string `json:"payload_name"`
	PayloadData string `json:"payload_data"`
	MessageID   string `json:"message_id"`
	Topic       string `json:"topic"`
	OrderingKey string `json:"ordering_key"`
	Description string `json:"description"`
}

func (q *Queries) CreateErrorMessage(ctx context.Context, arg CreateErrorMessageParams) (ErrorMessage, error) {
	row := q.db.QueryRowContext(ctx, createErrorMessage,
		arg.ServiceName,
		arg.PayloadName,
		arg.PayloadData,
		arg.MessageID,
		arg.Topic,
		arg.OrderingKey,
		arg.Description,
	)
	var i ErrorMessage
	err := row.Scan(
		&i.ID,
		&i.ServiceName,
		&i.PayloadName,
		&i.PayloadData,
		&i.MessageID,
		&i.Topic,
		&i.OrderingKey,
		&i.Description,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteErrorMessage = `-- name: DeleteErrorMessage :exec
DELETE FROM "error_message" WHERE id = $1
`

func (q *Queries) DeleteErrorMessage(ctx context.Context, id int64) error {
	_, err := q.db.ExecContext(ctx, deleteErrorMessage, id)
	return err
}

const findErrorMessage = `-- name: FindErrorMessage :many
SELECT id, service_name, payload_name, payload_data, message_id, topic, ordering_key, description, created_at, updated_at FROM "error_message" WHERE topic = $1 AND ordering_key = $2
ORDER BY created_at DESC
`

type FindErrorMessageParams struct {
	Topic       string `json:"topic"`
	OrderingKey string `json:"ordering_key"`
}

func (q *Queries) FindErrorMessage(ctx context.Context, arg FindErrorMessageParams) ([]ErrorMessage, error) {
	rows, err := q.db.QueryContext(ctx, findErrorMessage, arg.Topic, arg.OrderingKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ErrorMessage{}
	for rows.Next() {
		var i ErrorMessage
		if err := rows.Scan(
			&i.ID,
			&i.ServiceName,
			&i.PayloadName,
			&i.PayloadData,
			&i.MessageID,
			&i.Topic,
			&i.OrderingKey,
			&i.Description,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
