-- name: CreateUser :one
INSERT INTO
    "user"(id, email, username, password, otp_code, created_at, updated_at)
VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: UpdateUser :one
UPDATE
    "user"
SET
    username = $1,
    password = $2,
    phone_number = $3,
    attempt_left = $4,
    otp_code = $5,
    status = $6,
    updated_at = $8
WHERE
    id = $7 RETURNING *;

-- name: UpdateUserMainImage :one
UPDATE
    "user"
SET
    main_image_url = $1,
    main_image_path = $2,
    updated_at = $4
WHERE
    id = $3 RETURNING *;

-- name: DeleteUser :exec
DELETE from "user" WHERE id = $1;

-- name: FindUserByIdForUpdate :one
SELECT * from "user" WHERE id = $1 FOR NO KEY UPDATE;

-- name: CreateUserImage :one
INSERT INTO
    "user_image" (id, image_url, image_path, is_main, user_id, created_at, updated_at)
VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: UpdateUserImage :one
UPDATE
    "user_image"
SET
    is_main = $1,
    updated_at = $3
WHERE
    id = $2 RETURNING *;

-- name: DeleteUserImage :exec
DELETE from "user_image" WHERE id = $1;

-- name: FindUserImageByIdForUpdate :one
SELECT * from "user_image" WHERE id = $1 FOR NO KEY UPDATE;

-- name: FindUserMainImageByUserIdForUpdate :one
SELECT * from "user_image" where user_id = $1 AND is_main = true
FOR NO KEY UPDATE;