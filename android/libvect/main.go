package main

import (
	"embed"
	"log"
	"net/http"

	"github.com/yu-929/Vect-IP/internal/server"
)

//go:embed web
var webFS embed.FS

func main() {
	srv := server.SetupServer(8080, webFS, "http://127.0.0.1:8091")
	log.Printf("starting vect server on 127.0.0.1:8080")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}