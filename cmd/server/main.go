package main

import (
	"log"
	"net/http"
	"time"

	"github.com/anushka/sentineliam/internal/authcode"
	"github.com/anushka/sentineliam/internal/client"
	"github.com/anushka/sentineliam/internal/server"
	"github.com/anushka/sentineliam/internal/token"
)

func main() {
	keys, err := token.GenerateKeyPair()
	if err != nil {
		log.Fatalf("key generation failed: %v", err)
	}
	issuer := token.NewIssuer(keys, "sentineliam", 15*time.Minute)

	clients := client.NewRegistry()
	// A confidential service client (client-credentials).
	clients.Register("service-a", "s3cr3t", []string{"read", "write"}, []string{"service"})
	// A public app client (authorization-code + PKCE) — no usable secret needed.
	clients.Register("web-app", "unused", []string{"read", "profile"}, []string{"user"})

	codes := authcode.NewStore(60 * time.Second)
	oauth := server.NewOAuthServer(clients, issuer, codes)

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", oauth.HandleAuthorize)
	mux.HandleFunc("/token", oauth.HandleToken)

	addr := ":8080"
	log.Printf("SentinelIAM listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
