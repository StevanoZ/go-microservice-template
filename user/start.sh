#!/bin/sh

set -e

source /app/app/app.env
export GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"

exec "$@"
