package main

import (
	"context"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	config := shrd_utils.LoadBaseConfig("./app", "app")
	ctx := context.Background()

	app, err := InitializedApp(r, config)
	shrd_utils.LogIfError(err)

	app.ListenEvent(ctx)
	app.Start()
}
