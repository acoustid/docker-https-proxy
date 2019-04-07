package main

import (
	"flag"
	"log"
	"os"
	"strings"
)

// App is an interface for generic application
type App interface {
	Run() error
}

func main() {
	runLetsEncryptServer := flag.Bool("letsencrypt", false, "run letsencrypt master server")
	flag.Parse()

	runLetsEncryptServerEnvStr := os.Getenv("RUN_LETSENCRYPT_SERVER")
	if runLetsEncryptServerEnvStr == "1" || strings.ToLower(runLetsEncryptServerEnvStr) == "on" {
		*runLetsEncryptServer = true
	}

	var app App
	if *runLetsEncryptServer {
		app = NewLetsEncryptServer()
	} else {
		app = NewProxyServer()
	}

	err := app.Run()
	if err != nil {
		log.Fatal(err)
	}
	log.Print("bye")
}
