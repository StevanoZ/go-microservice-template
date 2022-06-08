-- name: CreateErrorMessage :one

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
    ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: FindErrorMessage :many
SELECT * FROM "error_message" WHERE topic = $1 AND ordering_key = $2
ORDER BY created_at DESC;

-- name: DeleteErrorMessage :exec
DELETE FROM "error_message" WHERE id = $1;