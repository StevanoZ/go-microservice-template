package main

import (
	"context"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	config := shrd_utils.CheckAndSetConfig("./app", "app")

	ctx := context.Background()

	app, err := InitializedApp(r, config)
	shrd_utils.LogAndPanicIfError(err, "failed when starting app")

	app.ListenEvent(ctx)
	app.Start()
}
