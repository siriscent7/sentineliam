package main

import (
	"log"
	"net/http"
	"time"

	"github.com/anushka/sentineliam/internal/client"
	"github.com/anushka/sentineliam/internal/server"
	"github.com/anushka/sentineliam/internal/token"
)

func main() {
	// Set up signing keys + issuer.
	keys, err := token.GenerateKeyPair()
	if err != nil {
		log.Fatalf("key generation failed: %v", err)
	}
	issuer := token.NewIssuer(keys, "sentineliam", 15*time.Minute)

	// Seed a demo client.
	clients := client.NewRegistry()
	if err := clients.Register(
		"service-a", "s3cr3t",
		[]string{"read", "write"},
		[]string{"service"},
	); err != nil {
		log.Fatalf("client registration failed: %v", err)
	}

	oauth := server.NewOAuthServer(clients, issuer)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", oauth.HandleToken)

	addr := ":8080"
	log.Printf("SentinelIAM listening on %s", addr)
	log.Printf("Try: curl -s -u service-a:s3cr3t -d 'grant_type=client_credentials&scope=read write' http://localhost%s/token", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
