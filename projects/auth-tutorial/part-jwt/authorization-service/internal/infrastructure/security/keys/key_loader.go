package keys

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func LoadKeyPair(privatePath string, kid string) (*KeyPair, error) {

	data, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Kid:        kid,
	}, nil
}

func LoadKeyRing(dir string) (*KeyRing, error) {

	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, errors.New("no pem files found")
	}

	var pairs []*KeyPair

	for _, file := range files {

		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid pem file: " + file)
		}

		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		kid := strings.TrimSuffix(filepath.Base(file), ".pem")

		pairs = append(pairs, &KeyPair{
			Kid:        kid,
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		})
	}

	return NewKeyRing(pairs)
}
