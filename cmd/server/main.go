package main

import (
	"fmt"
	"log"
	"time"

	"github.com/anushka/sentineliam/internal/token"
)

func main() {
	keys, err := token.GenerateKeyPair()
	if err != nil {
		log.Fatalf("key generation failed: %v", err)
	}

	issuer := token.NewIssuer(keys, "sentineliam", 15*time.Minute)

	// Issue a token
	jwtStr, err := issuer.Issue("user-123", "read write", []string{"admin"})
	if err != nil {
		log.Fatalf("issue failed: %v", err)
	}
	fmt.Println("Issued JWT:")
	fmt.Println(jwtStr)

	// Validate it
	claims, err := issuer.Validate(jwtStr)
	if err != nil {
		log.Fatalf("validation failed: %v", err)
	}
	fmt.Printf("\nValidated. Subject=%s Scope=%q Roles=%v Expires=%s\n",
		claims.Subject, claims.Scope, claims.Roles, claims.ExpiresAt)

	// Try validating garbage
	if _, err := issuer.Validate("not.a.real.token"); err != nil {
		fmt.Printf("\nCorrectly rejected invalid token: %v\n", err)
	}
}
