CREATE TABLE IF NOT EXISTS "user_image" (
    "id" uuid PRIMARY KEY,
    "image_url" varchar NOT NULL,
    "image_path" varchar NOT NULL,
    "is_main" boolean NOT NULL DEFAULT false,
    "user_id" uuid NOT NULL,
    "created_at" timestamptz NOT NULL DEFAULT (now()),
    "updated_at" timestamptz NOT NULL DEFAULT (now())
);

ALTER TABLE
    "user_image"
ADD
    FOREIGN KEY ("user_id") REFERENCES "user" ("id") ON DELETE CASCADE;

CREATE INDEX ON "user_image" ("user_id");