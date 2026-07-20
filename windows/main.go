package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/yu-929/Vect-IP/internal/server"
	"github.com/yu-929/Vect-IP/web"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("PANIC: %v\n", r)
			log.Print(msg)
			os.WriteFile("C:\\Users\\Public\\vect_debug.log", []byte(msg), 0644)
		}
	}()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(os.Stdout)

	fmt.Println("=== VECT IP Selector ===")
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("Starting server on http://127.0.0.1:8080")
	fmt.Println()

	srv := server.SetupServer(8080, web.FS)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				msg := fmt.Sprintf("server goroutine PANIC: %v\n", r)
				log.Print(msg)
				os.WriteFile("C:\\Users\\Public\\vect_debug.log", []byte(msg), 0644)
			}
		}()
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	url := "http://127.0.0.1:8080"
	fmt.Printf("Opening browser: %s\n", url)
	openBrowser(url)

	fmt.Println("Running... Press Ctrl+C or close the console to exit.")
	select {}
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