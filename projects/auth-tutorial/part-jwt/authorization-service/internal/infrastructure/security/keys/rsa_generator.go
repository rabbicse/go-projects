package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// func GenerateRSA4096(privatePath, publicPath string) error {

// 	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
// 	if err != nil {
// 		return err
// 	}

// 	// PRIVATE KEY
// 	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)

// 	privFile, err := os.Create(privatePath)
// 	if err != nil {
// 		return err
// 	}

// 	pem.Encode(privFile, &pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: privBytes,
// 	})

// 	// PUBLIC KEY
// 	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
// 	if err != nil {
// 		return err
// 	}

// 	pubFile, err := os.Create(publicPath)
// 	if err != nil {
// 		return err
// 	}

// 	pem.Encode(pubFile, &pem.Block{
// 		Type:  "PUBLIC KEY",
// 		Bytes: pubBytes,
// 	})

// 	return nil
// }

func GenerateRSA4096(privatePath, publicPath string) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// ---------- PRIVATE KEY ----------
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privFile, err := os.OpenFile(
		privatePath,
		os.O_CREATE|os.O_WRONLY,
		0600, // owner read/write only
	)
	if err != nil {
		return err
	}
	defer privFile.Close()

	err = pem.Encode(privFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	if err != nil {
		return err
	}

	// ---------- PUBLIC KEY (OPTIONAL) ----------
	if publicPath != "" {

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return err
		}

		pubFile, err := os.OpenFile(
			publicPath,
			os.O_CREATE|os.O_WRONLY,
			0644,
		)
		if err != nil {
			return err
		}
		defer pubFile.Close()

		err = pem.Encode(pubFile, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})
		if err != nil {
			return err
		}
	}

	return nil
}
