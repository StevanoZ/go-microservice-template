package schema

var UserDBSchema = `
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
  CREATE TABLE IF NOT EXISTS "user_image" (
	"id" uuid PRIMARY KEY,
	"image_url" varchar NOT NULL,
	"is_main" boolean NOT NULL DEFAULT false,
	"user_id" uuid NOT NULL,
	"created_at" timestamptz NOT NULL DEFAULT (now()),
	"updated_at" timestamptz NOT NULL DEFAULT (now())
  );
  ALTER TABLE
	"user_image"
  ADD
	FOREIGN KEY ("user_id") REFERENCES "user" ("id") ON DELETE CASCADE;
  
  CREATE INDEX ON "user" ("email");
  CREATE INDEX ON "user_image" ("user_id");
  ALTER TABLE
  "user_image"
  ADD
  "image_path" varchar NOT NULL;
  ALTER TABLE "user"
  ADD "main_image_path" varchar NOT NULL DEFAULT '';
`
