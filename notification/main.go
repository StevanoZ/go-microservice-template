package main

import (
	"context"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"

	"github.com/go-chi/chi"
)

func main() {
	r := chi.NewRouter()
	config := shrd_utils.CheckAndSetConfig("./app", "app")
	DB := shrd_utils.ConnectDB(config.DBDriver, config.DBSource)
	shrd_utils.RunMigration(DB, config)

	ctx := context.Background()

	app, err := InitializedApp(r, DB, config)
	shrd_utils.LogAndPanicIfError(err, "failed when starting app")

	app.ListenEvent(ctx)
	app.Start()
}
