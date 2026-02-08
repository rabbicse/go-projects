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
	"net/url"
	"testing"

	"golang.org/x/crypto/argon2"
)

func Test_Full_Identity_Flow(t *testing.T) {

	client := newHttpClient()

	username := randomString("user")
	password := "password123"
	email := username + "@example.com"

	t.Log("===================================")
	t.Log("STARTING FULL IDENTITY FLOW")
	t.Log("USERNAME:", username)
	t.Log("EMAIL:", email)
	t.Log("===================================")

	//--------------------------------------
	// 1. REGISTER
	//--------------------------------------

	t.Log("STEP 1 → REGISTER USER")

	salt := make([]byte, 16)
	rand.Read(salt)

	verifier := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	regBody := map[string]string{
		"username": username,
		"email":    email,
		"salt":     base64.RawURLEncoding.EncodeToString(salt),
		"verifier": base64.RawURLEncoding.EncodeToString(verifier),
	}

	callApiWithClient(t, client, "POST", "/users/register", regBody, nil)

	t.Log("✅ USER REGISTERED")

	//--------------------------------------
	// 2. LOGIN CHALLENGE
	//--------------------------------------

	t.Log("STEP 2 → REQUEST LOGIN CHALLENGE")

	var chal struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Salt        string `json:"salt"`
	}

	callApiWithClient(t, client,
		"POST",
		"/login/challenge",
		map[string]string{"username": username},
		&chal,
	)

	saltSrv, _ := base64.RawURLEncoding.DecodeString(chal.Salt)
	challenge, _ := base64.RawURLEncoding.DecodeString(chal.Challenge)

	verifier2 := argon2.IDKey([]byte(password), saltSrv, 1, 64*1024, 4, 32)

	mac := hmac.New(sha256.New, verifier2)
	mac.Write(challenge)

	proof := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	//--------------------------------------
	// 3. LOGIN VERIFY → GET LOGIN TOKEN
	//--------------------------------------

	t.Log("STEP 3 → VERIFY LOGIN")

	var loginResp struct {
		LoginToken string `json:"login_token"`
	}

	callApiWithClient(t, client, "POST", "/login/verify",
		map[string]string{
			"username":     username,
			"challenge_id": chal.ChallengeID,
			"proof":        proof,
		},
		&loginResp,
	)

	if loginResp.LoginToken == "" {
		t.Fatal("login_token missing")
	}

	loginToken := loginResp.LoginToken

	t.Log("✅ LOGIN TOKEN ISSUED")

	//--------------------------------------
	// 4. AUTHORIZE (Bearer login token)
	//--------------------------------------

	t.Log("STEP 4 → OAUTH AUTHORIZE")

	authURL := OauthBaseURL + "/authorize?" +
		"response_type=code" +
		"&client_id=" + url.QueryEscape(ClientID) +
		"&redirect_uri=" + url.QueryEscape(RedirectURI) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + State

	req, _ := http.NewRequest("GET", authURL, nil)
	req.Header.Set("Authorization", "Bearer "+loginToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected redirect, got %d: %s",
			resp.StatusCode,
			string(bodyBytes))
	}

	location := resp.Header.Get("Location")

	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")

	if code == "" {
		t.Fatal("authorization code missing")
	}

	t.Log("✅ AUTHORIZATION CODE RECEIVED")

	//--------------------------------------
	// 5. TOKEN EXCHANGE
	//--------------------------------------

	t.Log("STEP 5 → TOKEN EXCHANGE")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", RedirectURI)
	form.Set("client_id", ClientID)
	form.Set("client_secret", ClientSecret)

	req, err = http.NewRequest(
		"POST",
		OauthBaseURL+"/token",
		bytes.NewBufferString(form.Encode()),
	)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	t.Log("Token Status:", resp.StatusCode)
	t.Log("Token Body:", string(body))

	if resp.StatusCode != 200 {
		t.Fatalf("TOKEN EXCHANGE FAILED → %s", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}

	// json.NewDecoder(resp.Body).Decode(&tokenResp)

	json.Unmarshal(body, &tokenResp)

	if tokenResp.AccessToken == "" {
		t.Fatal("access_token missing")
	}

	if tokenResp.IDToken == "" {
		t.Fatal("id_token missing — OIDC not working")
	}

	t.Log("✅ TOKENS ISSUED")

	//--------------------------------------
	// 6. ACCESS RESOURCE (JWT validation)
	//--------------------------------------

	t.Log("STEP 6 → ACCESS PROTECTED RESOURCE")

	req, _ = http.NewRequest("GET",
		ResourceBaseURL+"/protected",
		nil)

	req.Header.Set("Authorization",
		"Bearer "+tokenResp.AccessToken)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("resource failed: %s", string(body))
	}

	t.Log("✅ RESOURCE ACCESS GRANTED")

	t.Log("===================================")
	t.Log("🎉 FULL IDENTITY FLOW SUCCESS")
	t.Log("===================================")
}
