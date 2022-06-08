
-- name: CreateUser :one
INSERT INTO "user"(id, email, username, password, otp_code)
VALUES($1, $2, $3, $4, $5) RETURNING *;

-- name: UpdateUser :one
UPDATE "user" SET username = $1, password = $2, phone_number = $3, 
attempt_left = $4, otp_code = $5, status = $6, 
updated_at = now() WHERE id = $7 RETURNING *;

-- name: UpdateUserMainImage :one
UPDATE "user" SET main_image_url = $1, main_image_path = $2, updated_at = now()
WHERE id = $3 RETURNING *;

-- name: DeleteUser :exec
DELETE FROM "user" WHERE id = $1;

-- name: FindUserById :one
SELECT * FROM "user" WHERE id = $1 LIMIT 1;

-- name: FindUserByEmail :one
SELECT * FROM "user" WHERE email = $1 LIMIT 1;

-- name: FindUsers :many
SELECT * FROM "user" WHERE 
CASE 
WHEN @search_field::text = 'username' THEN username 
WHEN @search_field::text = 'email' THEN email
ELSE username END ILIKE
CASE
WHEN @search_field::text = '' THEN '%%'
ELSE @search_value END
AND status = CASE 
WHEN @filter_by::text = '' THEN 'active'
ELSE @filter_by END 
ORDER BY 
CASE WHEN @sort_by::text = 'email' THEN email END ASC,
CASE WHEN @sort_by::text = '-email' THEN email END DESC,
CASE WHEN @sort_by::text = 'username' THEN username END ASC,
CASE WHEN @sort_by::text = '-username' THEN username END DESC,
CASE WHEN @sort_by::text = 'createdAt' THEN created_at END ASC,
CASE WHEN @sort_by::text = '-createdAt' THEN created_at END DESC, 
CASE WHEN @sort_by::text = '' THEN username END ASC
LIMIT $1 OFFSET $2;

-- name: GetUsersPaginationCount :one
SELECT COUNT(*) FROM "user" WHERE
CASE 
WHEN @search_field::text = 'username' THEN username 
WHEN @search_field::text = 'email' THEN email
ELSE username END ILIKE
CASE
WHEN @search_field::text = '' THEN '%%'
ELSE @search_value END
AND status = CASE 
WHEN @filter_by::text = '' THEN 'active'
ELSE @filter_by END;

-- name: CreateUserImage :one
INSERT INTO "user_image"(id, image_url, image_path, user_id, is_main) 
VALUES($1, $2, $3, $4, $5) 
RETURNING *;

-- name: UpdateUserImage :one
UPDATE "user_image" SET is_main = $1, updated_at = now() WHERE id = $2 RETURNING *;

-- name: DeleteUserImage :exec
DELETE FROM "user_image" WHERE id = $1;

-- name: FindUserImageById :one
SELECT * FROM "user_image" WHERE id = $1;

-- name: FindUserImagesByUserId :many
SELECT * FROM "user_image" WHERE user_id = $1;

-- name: FindUserWithImages :one
SELECT u.*, array_to_json(array_agg(row_to_json(ui.*))) as images FROM "user" as u LEFT JOIN "user_image" as ui 
ON ui.user_id = u.id WHERE u.id = $1
GROUP BY u.id; 

-- name: FindUserImagesByUserIdForUpdate :many
SELECT * FROM "user_image" WHERE user_id = $1 FOR NO KEY UPDATE;