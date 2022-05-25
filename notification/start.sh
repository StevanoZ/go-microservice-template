#!/bin/sh

set -e

echo "run db migration"

source /app/app/app.env
export GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"

/app/migrate -path /app/db/migration -database "postgresql://${DB_SOURCE}" -verbose up

echo "start the app"
exec "$@"
