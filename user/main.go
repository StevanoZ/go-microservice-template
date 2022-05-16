package main

import (
	"log"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"
	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	config := shrd_utils.LoadBaseConfig("./app", "app")
	DB := shrd_utils.ConnectDB(config.DBDriver, config.DBSource)

	app, err := InitializedApp(r, DB, config)

	if err != nil {
		log.Fatal("failed when initialized app")
	}

	app.Start()
}
