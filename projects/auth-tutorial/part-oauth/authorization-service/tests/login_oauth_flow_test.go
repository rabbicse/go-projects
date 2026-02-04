package tests

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
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
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

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

	t.Log("ChallengeID:", chal.ChallengeID)
	t.Log("Salt:", chal.Salt)
	t.Log("Challenge:", chal.Challenge)

	saltSrv, err := base64.RawURLEncoding.DecodeString(chal.Salt)
	if err != nil {
		t.Fatal("failed to decode salt:", err)
	}

	challenge, err := base64.RawURLEncoding.DecodeString(chal.Challenge)
	if err != nil {
		t.Fatal("failed to decode challenge:", err)
	}

	verifier2 := argon2.IDKey([]byte(password), saltSrv, 1, 64*1024, 4, 32)

	mac := hmac.New(sha256.New, verifier2)
	mac.Write(challenge)

	proof := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	t.Log("Computed Proof:", proof)

	//--------------------------------------
	// 3. LOGIN VERIFY (SESSION CREATED)
	//--------------------------------------

	t.Log("STEP 3 → VERIFY LOGIN")

	callApiWithClient(t, client, "POST", "/login/verify",
		map[string]string{
			"username":     username,
			"challenge_id": chal.ChallengeID,
			"proof":        proof,
		},
		nil,
	)

	t.Log("✅ LOGIN SUCCESSFUL (SESSION SHOULD EXIST)")

	//--------------------------------------
	// 4. OAUTH AUTHORIZE
	//--------------------------------------

	t.Log("STEP 4 → OAUTH AUTHORIZE")

	authURL := OauthBaseURL + "/authorize?" +
		"response_type=code" +
		"&client_id=" + url.QueryEscape(ClientID) +
		"&redirect_uri=" + url.QueryEscape(RedirectURI) +
		"&scope=" + url.QueryEscape(Scope) +
		"&state=" + State

	t.Log("Authorize URL:", authURL)

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	t.Log("Authorize Status:", resp.StatusCode)
	t.Log("Authorize Body:", string(bodyBytes))

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected redirect, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	location := resp.Header.Get("Location")
	t.Log("Redirect Location:", location)

	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	code := redirectURL.Query().Get("code")

	if code == "" {
		t.Fatal("Authorization code missing")
	}

	t.Log("✅ AUTHORIZATION CODE:", code)

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

	req, err := http.NewRequest("POST", OauthBaseURL+"/token",
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	tokenBody, _ := io.ReadAll(resp.Body)

	t.Log("Token Status:", resp.StatusCode)
	t.Log("Token Response:", string(tokenBody))

	var tokenResp map[string]any
	if err := json.Unmarshal(tokenBody, &tokenResp); err != nil {
		t.Fatal("failed to decode token response:", err)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("access_token missing in response: %+v", tokenResp)
	}

	t.Log("✅ ACCESS TOKEN RECEIVED")

	//--------------------------------------
	// 6. ACCESS RESOURCE
	//--------------------------------------

	t.Log("STEP 6 → ACCESS PROTECTED RESOURCE")

	req, err = http.NewRequest("GET", ResourceBaseURL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	resourceBody, _ := io.ReadAll(resp.Body)

	t.Log("Resource Status:", resp.StatusCode)
	t.Log("Resource Body:", string(resourceBody))

	if resp.StatusCode != 200 {
		t.Fatal("protected resource failed")
	}

	t.Log("===================================")
	t.Log("✅ FULL FLOW SUCCESS")
	t.Log("===================================")
}

func callApiWithClient(t *testing.T,
	client *http.Client,
	method, path string,
	body any,
	out any,
) {

	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}

	req, _ := http.NewRequest(method, BaseURL+path, &buf)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s failed: %d %s",
			method, path, resp.StatusCode, string(b))
	}

	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
}

func randomString(prefix string) string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%s_%x", prefix, b)
}

func newHttpClient() *http.Client {
	jar, _ := cookiejar.New(nil)

	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
