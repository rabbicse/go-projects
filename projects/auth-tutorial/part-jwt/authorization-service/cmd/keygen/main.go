package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rabbicse/auth-service/internal/infrastructure/security/keys"
)

func main() {

	privatePath := "secrets/private.pem"
	publicPath := "secrets/public.pem"

	// Prevent overwrite
	if fileExists(privatePath) {
		log.Fatal("private.pem already exists — refusing to overwrite")
	}

	fmt.Println("Generating RSA-4096 keys...")

	err := os.MkdirAll("secrets", 0700)
	if err != nil {
		log.Fatal(err)
	}

	err = keys.GenerateRSA4096(
		privatePath,
		publicPath,
	)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("✅ Keys generated successfully.")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
