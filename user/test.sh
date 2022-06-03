#!/bin/bash

gcloud beta emulators pubsub start --project=test

echo "start the emulator"
exec "$@"