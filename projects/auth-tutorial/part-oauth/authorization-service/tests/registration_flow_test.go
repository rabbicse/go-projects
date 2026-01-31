package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/rabbicse/auth-service/pkg/helpers"
)

const BaseURLMfa = "http://localhost:8080"

func Test_Registration_Flow(t *testing.T) {
	username := "alice"
	password := "password123"
	email := "alice@example.com"

	// --------------------------------
	// 0. Client Registration
	// --------------------------------
	salt := make([]byte, 16)
	rand.Read(salt)
	verifier := helpers.DeriveVerifier(password, salt)

	regBody := map[string]string{
		"username": username,
		"email":    email,
		"salt":     base64.RawURLEncoding.EncodeToString(salt),
		"verifier": base64.RawURLEncoding.EncodeToString(verifier),
	}

	callJSON(t, "POST", "/users/register", regBody, nil)
}

func callJSON(t *testing.T, method, path string, body any, out any) {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}

	req, err := http.NewRequest(method, BaseURLMfa+path, &buf)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		t.Fatalf("request %s %s failed: %d", method, path, resp.StatusCode)
	}

	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
}
