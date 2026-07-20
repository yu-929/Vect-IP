package main

import (
	"log"
	"net/http"
	"os"

	"github.com/yu-929/Vect-IP/internal/server"
	"github.com/yu-929/Vect-IP/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(os.Stdout)

	log.Println("=== VECT SERVER STARTING ===")
	log.Println("GOOS=android GOARCH=arm64")
	log.Println("Creating server...")

	srv := server.SetupServer(8080, web.FS)

	log.Printf("Server configured, listening on %s", srv.Addr)
	log.Println("Calling ListenAndServe...")
	os.Stdout.Sync()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("server error: %v", err)
		os.Stdout.Sync()
		os.Exit(1)
	}
}