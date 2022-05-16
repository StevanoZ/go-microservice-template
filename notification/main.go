package main

import (
	"context"
	"fmt"
	"net/http"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	config := shrd_utils.LoadBaseConfig("./app", "app")
	r.Mount("/api/notification", r)
	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("PONG!"))
	})

	notificationSvc, err := InitializedApp(config)

	if err != nil {
		fmt.Println("failed when initialize app")
	}

	go func() {
		ctx := context.Background()
		notificationSvc.ListenAndSendEmail(ctx, true)
	}()

	http.ListenAndServe(fmt.Sprintf(":%s", config.ServerPort), r)
}