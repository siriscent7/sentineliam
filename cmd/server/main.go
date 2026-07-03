package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/anushka/sentineliam/internal/authcode"
	"github.com/anushka/sentineliam/internal/client"
	appcrypto "github.com/anushka/sentineliam/internal/crypto"
	"github.com/anushka/sentineliam/internal/server"
	"github.com/anushka/sentineliam/internal/token"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "demo-crypto" {
		runCryptoDemo()
		return
	}
	runServer()
}

func runCryptoDemo() {
	kek := make([]byte, 32)
	io.ReadFull(rand.Reader, kek)

	km, err := appcrypto.NewKeyManager(kek)
	if err != nil {
		log.Fatalf("key manager: %v", err)
	}

	secret := []byte("super-secret-client-credential")
	fmt.Printf("Plaintext:  %s\n", secret)

	env, err := km.Encrypt(secret)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}
	fmt.Printf("\nEnvelope (stored at rest):\n  ciphertext:    %s...\n  encrypted DEK: %s...\n",
		env.Ciphertext[:24], env.EncryptedDEK[:24])

	decrypted, err := km.Decrypt(env)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}
	fmt.Printf("\nDecrypted:  %s\n", decrypted)

	env.Ciphertext = "AAAA" + env.Ciphertext[4:]
	if _, err := km.Decrypt(env); err != nil {
		fmt.Printf("\nTampered ciphertext correctly rejected: %v\n", err)
	}
}

func runServer() {
	keys, err := token.GenerateKeyPair()
	if err != nil {
		log.Fatalf("key generation failed: %v", err)
	}

	denylist := token.NewDenylist()
	issuer := token.NewIssuer(keys, "sentineliam", 15*time.Minute).WithDenylist(denylist)

	clients := client.NewRegistry()
	clients.Register("service-a", "s3cr3t", []string{"read", "write"}, []string{"service", "admin"})
	clients.Register("web-app", "unused", []string{"read", "profile"}, []string{"user"})

	codes := authcode.NewStore(60 * time.Second)
	oauth := server.NewOAuthServer(clients, issuer, codes)
	oauth.SetDenylist(denylist)
	mw := server.NewMiddleware(issuer)

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", oauth.HandleAuthorize)
	mux.HandleFunc("/token", oauth.HandleToken)
	mux.HandleFunc("/introspect", oauth.HandleIntrospect)
	mux.HandleFunc("/revoke", oauth.HandleRevoke)
	mux.Handle("/profile", mw.Authenticate(http.HandlerFunc(server.ProfileHandler)))
	mux.Handle("/data", mw.Authenticate(mw.RequireScope("write", http.HandlerFunc(server.ProfileHandler))))
	mux.Handle("/admin", mw.Authenticate(mw.RequireRole("admin", http.HandlerFunc(server.AdminHandler))))

	addr := ":8080"
	log.Printf("SentinelIAM listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
