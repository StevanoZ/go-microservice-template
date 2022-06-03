FROM google/cloud-sdk:alpine

WORKDIR /app
RUN apk update
RUN apk add openjdk12
RUN gcloud components --quiet install pubsub-emulator
RUN gcloud components --quiet update

CMD [ "/bin/sh" ]