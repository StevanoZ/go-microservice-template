#!/bin/sh

set -e

echo "run db migration"

source /app/app/app.env
export GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"

exec "$@"
