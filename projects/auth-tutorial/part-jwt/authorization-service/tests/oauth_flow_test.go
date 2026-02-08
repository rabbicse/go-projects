package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// const (
// 	OauthBaseURL    = "http://localhost:8080"
// 	ResourceBaseURL = "http://localhost:9090"
// 	ClientID        = "client-123"
// 	ClientSecret    = "secret"
// 	RedirectURI     = "http://localhost:3000/callback"
// 	Scope           = "profile email"
// 	State           = "xyz123"
// )

func Test_OAuth2_Authorization_Code_Flow(t *testing.T) {

	// --------------------------------
	// 1. Start Authorization Request
	// --------------------------------
	t.Log("1. Starting OAuth Authorization")

	authURL := OauthBaseURL + "/authorize?" +
		"response_type=code" +
		"&client_id=" + url.QueryEscape(ClientID) +
		"&redirect_uri=" + url.QueryEscape(RedirectURI) +
		"&scope=" + url.QueryEscape(Scope) +
		"&state=" + State
	t.Logf("Authorization URL: %v", authURL)

	// We don't follow redirects because we want to capture the code
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected redirect, got %d: %s", resp.StatusCode, string(b))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("No redirect location returned")
	}

	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	code := redirectURL.Query().Get("code")
	if code == "" {
		t.Fatal("Authorization code not found in redirect")
	}

	t.Log("✔ Authorization code:", code)

	// --------------------------------
	// 2. Exchange Code for Token
	// --------------------------------
	t.Log("2. Exchanging authorization code for token")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", RedirectURI)
	form.Set("client_id", ClientID)
	form.Set("client_secret", ClientSecret)

	req, err := http.NewRequest("POST", OauthBaseURL+"/token", bytes.NewBufferString(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("Token exchange failed: %d %s", resp.StatusCode, string(b))
	}

	var tokenResp map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResp)
	t.Logf("Token response: %v", tokenResp)

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("Access token not returned")
	}

	t.Log("✔ Access token issued")

	// --------------------------------
	// 3. Use Access Token
	// --------------------------------
	t.Log("3. Accessing protected resource")

	req, err = http.NewRequest("GET", ResourceBaseURL+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("Protected resource access failed: %d %s", resp.StatusCode, string(b))
	}

	t.Log("✔ Protected resource accessed")

	// --------------------------------
	// 4. Replay Attack Test (MUST FAIL)
	// --------------------------------
	t.Log("4. Testing replay attack (must fail)")

	req, err = http.NewRequest("POST", OauthBaseURL+"/token", bytes.NewBufferString(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Fatal("Replay attack succeeded, this is a security bug")
	}

	t.Log("✔ Replay attack correctly blocked")
}
