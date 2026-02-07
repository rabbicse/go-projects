package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/rabbicse/auth-service/internal/infrastructure/security/keys"
)

func main() {

	// Use timestamp as kid
	kid := time.Now().UTC().Format("2006-01-02T15-04-05")

	privatePath := fmt.Sprintf(
		"secrets/keys/%s.pem",
		kid,
	)

	// Ensure directory exists
	err := os.MkdirAll("secrets/keys", 0700)
	if err != nil {
		log.Fatal(err)
	}

	if fileExists(privatePath) {
		log.Fatal("key already exists — refusing overwrite")
	}

	fmt.Println("Generating RSA-4096 key...")
	fmt.Println("KID:", kid)

	err = keys.GenerateRSA4096(
		privatePath,
		"", // no need to store public key
	)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("✅ Key generated successfully.")
	fmt.Println("Location:", privatePath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
