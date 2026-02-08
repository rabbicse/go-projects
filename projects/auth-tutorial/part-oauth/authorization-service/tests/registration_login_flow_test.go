package tests

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"golang.org/x/crypto/argon2"
)

// const (
// 	BaseURL = "http://localhost:8080"
// )

func Test_Login_Flow(t *testing.T) {
	username := "alice"
	password := "password123"
	email := "alice@example.com"

	t.Log("================================")
	t.Log("0. Client-side Registration")
	t.Log("================================")

	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	// Derive verifier (Argon2id)
	verifier := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	regBody := map[string]string{
		"username": username,
		"email":    email,
		"salt":     base64.RawURLEncoding.EncodeToString(salt),
		"verifier": base64.RawURLEncoding.EncodeToString(verifier),
	}

	callApi(t, "POST", "/users/register", regBody, nil)
	t.Log("User registered")

	// -------------------------------------------------------

	t.Log("================================")
	t.Log("1. Request Login Challenge")
	t.Log("================================")

	var chal struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Salt        string `json:"salt"`
	}

	callApi(t, "POST", "/login/challenge",
		map[string]string{"username": username},
		&chal,
	)

	if chal.ChallengeID == "" || chal.Challenge == "" || chal.Salt == "" {
		t.Fatal("Invalid challenge response from server")
	}

	t.Logf("Challenge ID: %s", chal.ChallengeID)

	// -------------------------------------------------------

	t.Log("================================")
	t.Log("2. Decode Base64URL")
	t.Log("================================")

	saltSrv, err := base64.RawURLEncoding.DecodeString(chal.Salt)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(chal.Challenge)
	if err != nil {
		t.Fatal(err)
	}

	// -------------------------------------------------------

	t.Log("================================")
	t.Log("3. Re-Derive Verifier")
	t.Log("================================")

	verifier2 := argon2.IDKey([]byte(password), saltSrv, 1, 64*1024, 4, 32)

	// -------------------------------------------------------

	t.Log("================================")
	t.Log("4. Compute Proof = HMAC(verifier, challenge)")
	t.Log("================================")

	mac := hmac.New(sha256.New, verifier2)
	mac.Write(challenge)
	proof := mac.Sum(nil)

	proofB64 := base64.RawURLEncoding.EncodeToString(proof)
	t.Logf("Proof: %s", proofB64)

	// -------------------------------------------------------

	t.Log("================================")
	t.Log("5. Verify Login")
	t.Log("================================")

	verifyBody := map[string]string{
		"username":     username,
		"challenge_id": chal.ChallengeID,
		"proof":        proofB64,
	}

	var verifyResp map[string]any
	callApi(t, "POST", "/login/verify", verifyBody, &verifyResp)

	t.Log("Server response:", verifyResp)
}

func callApi(t *testing.T, method, path string, body any, out any) {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}

	req, err := http.NewRequest(method, BaseURL+path, &buf)
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
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("request %s %s failed: %d\n%s", method, path, resp.StatusCode, string(b))
	}

	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
}
