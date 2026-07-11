package main

import (
	"C"
	"embed"
	"log"
	"net/http"

	"github.com/yu-929/Vect-IP/internal/server"
)

//go:embed web
var webFS embed.FS

//export StartVectServer
func StartVectServer(port C.int) C.int {
	srv := server.SetupServer(int(port), webFS, "http://127.0.0.1:8091")
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()
	return C.int(0)
}

func main() {}