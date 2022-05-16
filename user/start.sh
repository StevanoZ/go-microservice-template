#!/bin/bash

set -e

echo "run db migration"

source /app/app/app.env

/app/migrate -path /app/db/migration -database "postgresql://${DB_SOURCE}" -verbose up

echo "start the app"
exec "$@"