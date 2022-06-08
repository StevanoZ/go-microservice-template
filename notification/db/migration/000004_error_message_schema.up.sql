CREATE TABLE IF NOT EXISTS "error_message" (
    "id" bigserial PRIMARY KEY,
    "service_name" varchar NOT NULL,
    "payload_name" varchar NOT NULL,
    "payload_data" varchar NOT NULL,
    "message_id" varchar NOT NULL,
    "topic" varchar NOT NULL,
    "ordering_key" varchar NOT NULL,
    "description" varchar NOT NULL,
    "created_at" timestamptz NOT NULL DEFAULT (now()),
    "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE INDEX ON "error_message" ("service_name");

CREATE INDEX ON "error_message" ("ordering_key");