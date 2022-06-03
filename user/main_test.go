package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {
	t.Run("Not Panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			os.Setenv("ENVIRONMENT", "test")
			go main()

			time.Sleep(2 * time.Second)
			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		})
	})
}
