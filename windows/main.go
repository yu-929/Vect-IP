package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"

	"github.com/yu-929/Vect-IP/internal/server"
	"github.com/yu-929/Vect-IP/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(os.Stdout)

	fmt.Println("=== VECT IP Selector ===")
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("Starting server on http://127.0.0.1:8080")
	fmt.Println()

	srv := server.SetupServer(8080, web.FS)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	url := "http://127.0.0.1:8080"
	fmt.Printf("Opening browser: %s\n", url)
	openBrowser(url)

	fmt.Println("Press Ctrl+C or Enter to exit...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	done := make(chan struct{})
	go func() {
		fmt.Scanln()
		close(done)
	}()

	select {
	case <-sigCh:
		fmt.Println("\nShutting down...")
	case <-done:
		fmt.Println("\nShutting down...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if cmd != nil {
		cmd.Run()
	}
}
