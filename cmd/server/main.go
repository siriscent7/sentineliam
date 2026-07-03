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
	clients.Register("service-a", "s3cr3t", []string{"read", "write"}, []string{"service", "admin"})
	clients.Register("web-app", "unused", []string{"read", "profile"}, []string{"user"})

	codes := authcode.NewStore(60 * time.Second)
	oauth := server.NewOAuthServer(clients, issuer, codes)
	mw := server.NewMiddleware(issuer)

	mux := http.NewServeMux()

	// OAuth endpoints (public)
	mux.HandleFunc("/authorize", oauth.HandleAuthorize)
	mux.HandleFunc("/token", oauth.HandleToken)

	// Protected: requires a valid token
	mux.Handle("/profile", mw.Authenticate(http.HandlerFunc(server.ProfileHandler)))

	// Protected: requires a valid token AND the "write" scope
	mux.Handle("/data", mw.Authenticate(
		mw.RequireScope("write", http.HandlerFunc(server.ProfileHandler))))

	// Protected: requires a valid token AND the "admin" role
	mux.Handle("/admin", mw.Authenticate(
		mw.RequireRole("admin", http.HandlerFunc(server.AdminHandler))))

	addr := ":8080"
	log.Printf("SentinelIAM listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
