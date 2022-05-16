CREATE TABLE IF NOT EXISTS "user" (
  "id" uuid PRIMARY KEY,
  "email" varchar UNIQUE NOT NULL,
  "username" varchar(10) NOT NULL,
  "password" varchar NOT NULL,
  "attempt_left" int NOT NULL DEFAULT 5,
  "otp_code" bigint NOT NULL DEFAULT 0,
  "phone_number" varchar NOT NULL DEFAULT '',
  "status" varchar NOT NULL DEFAULT 'not-active',
  "main_image_url" varchar NOT NULL DEFAULT '',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE INDEX ON "user" ("email");
