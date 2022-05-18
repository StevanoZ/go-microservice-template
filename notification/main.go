package main

import (
	"context"
	"fmt"
	"net/http"

	shrd_utils "github.com/StevanoZ/dv-shared/utils"

	"github.com/go-chi/chi/v5"
	"github.com/go-openapi/runtime/middleware"
)

func main() {
	r := chi.NewRouter()
	config := shrd_utils.LoadBaseConfig("./app", "app")
	shrd_utils.EnableCORS(r)

	r.Mount("/api/notification", r)

	opts := middleware.SwaggerUIOpts{SpecURL: "/api/notification/swagger.json", Path: "/doc"}
	sh := middleware.SwaggerUI(opts, nil)
	r.Handle("/doc/*", sh)
	r.Handle("/swagger.json", http.FileServer(http.Dir("./docs")))

	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		shrd_utils.GenerateSuccessResp(w, "PONG!", 200)
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
