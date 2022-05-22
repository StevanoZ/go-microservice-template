package main

import (
	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	config := shrd_utils.LoadBaseConfig("./app", "app")
	DB := shrd_utils.ConnectDB(config.DBDriver, config.DBSource)

	app, err := InitializedApp(r, DB, config)
	shrd_utils.LogIfError(err)

	app.Start()
}
