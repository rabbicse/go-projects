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

func Test_Full_Login_MFA_Flow(t *testing.T) {
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

	callJSON(t, "POST", "/users/register", "", regBody, nil)

	// --------------------------------
	// 1. Request Login Challenge
	// --------------------------------
	var chalResp struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Salt        string `json:"salt"`
	}

	callJSON(t, "POST", "/login/challenge", "", map[string]string{
		"username": username,
	}, &chalResp)

	challenge, _ := base64.RawURLEncoding.DecodeString(chalResp.Challenge)
	salt, _ = base64.RawURLEncoding.DecodeString(chalResp.Salt)

	// --------------------------------
	// 2. Compute Proof
	// --------------------------------
	verifier = helpers.DeriveVerifier(password, salt)
	proof := helpers.ComputeProof(verifier, challenge)

	verifyResp := struct {
		LoginToken string `json:"login_token"`
	}{}

	callJSON(t, "POST", "/login/verify", "", map[string]string{
		"username":     username,
		"challenge_id": chalResp.ChallengeID,
		"proof":        base64.RawURLEncoding.EncodeToString(proof),
	}, &verifyResp)

	if verifyResp.LoginToken == "" {
		t.Fatal("login_token not returned")
	}

	loginToken := verifyResp.LoginToken

	// --------------------------------
	// 3. MFA Enrollment Start
	// --------------------------------
	var mfaStart struct {
		Secret string `json:"secret"`
		QRURL  string `json:"qr_url"`
	}

	callJSON(t, "POST", "/mfa/enroll/start", loginToken, nil, &mfaStart)

	if mfaStart.Secret == "" {
		t.Fatal("MFA secret not returned")
	}

	// --------------------------------
	// 4. MFA Enrollment Verify
	// --------------------------------
	code, err := helpers.GenerateTOTP(mfaStart.Secret)
	if err != nil {
		t.Fatal(err)
	}

	callJSON(t, "POST", "/mfa/enroll/verify", loginToken, map[string]string{
		"code": code,
	}, nil)

	// --------------------------------
	// 5. MFA Login Verify
	// --------------------------------
	code, err = helpers.GenerateTOTP(mfaStart.Secret)
	if err != nil {
		t.Fatal(err)
	}

	callJSON(t, "POST", "/mfa/verify", loginToken, map[string]string{
		"code": code,
	}, nil)

	t.Log("FULL LOGIN + MFA FLOW SUCCESS")
}

func callJSON(t *testing.T, method, path, token string, body any, out any) {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}

	req, err := http.NewRequest(method, BaseURLMfa+path, &buf)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Login "+token)
	}

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
