package tests

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/crypto/argon2"
)

func Test_OAuth_OIDC_EndToEnd(t *testing.T) {

	client := newHttpClient()

	username := randomString("user")
	password := "password123"
	email := username + "@example.com"

	t.Log("========== START OAUTH + OIDC FLOW ==========")

	//--------------------------------------
	// 1. REGISTER
	//--------------------------------------

	salt := make([]byte, 16)
	rand.Read(salt)

	verifier := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	regBody := map[string]string{
		"username": username,
		"email":    email,
		"salt":     base64.RawURLEncoding.EncodeToString(salt),
		"verifier": base64.RawURLEncoding.EncodeToString(verifier),
	}

	callAPI(t, client, "POST", "/users/register", regBody, nil)

	t.Log("✅ USER REGISTERED")

	//--------------------------------------
	// 2. LOGIN CHALLENGE
	//--------------------------------------

	var chal struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Salt        string `json:"salt"`
	}

	callAPI(t, client, "POST", "/login/challenge",
		map[string]string{"username": username},
		&chal,
	)

	saltSrv, _ := base64.RawURLEncoding.DecodeString(chal.Salt)
	challenge, _ := base64.RawURLEncoding.DecodeString(chal.Challenge)

	verifier2 := argon2.IDKey([]byte(password), saltSrv, 1, 64*1024, 4, 32)

	mac := hmac.New(sha256.New, verifier2)
	mac.Write(challenge)

	proof := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	callAPI(t, client, "POST", "/login/verify",
		map[string]string{
			"username":     username,
			"challenge_id": chal.ChallengeID,
			"proof":        proof,
		},
		nil,
	)

	t.Log("✅ LOGIN SUCCESS")

	//--------------------------------------
	// 3. AUTHORIZE
	//--------------------------------------

	authURL := OauthBaseURL + "/authorize?" +
		"response_type=code" +
		"&client_id=" + url.QueryEscape(ClientID) +
		"&redirect_uri=" + url.QueryEscape(RedirectURI) +
		"&scope=" + url.QueryEscape(Scope) +
		"&state=" + State

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize failed: %s", string(body))
	}

	location := resp.Header.Get("Location")

	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")

	if code == "" {
		t.Fatal("authorization code missing")
	}

	t.Log("✅ AUTH CODE RECEIVED")

	//--------------------------------------
	// 4. TOKEN EXCHANGE
	//--------------------------------------

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", RedirectURI)
	form.Set("client_id", ClientID)
	form.Set("client_secret", ClientSecret)

	tokenResp := exchangeToken(t, client, form)

	accessToken := tokenResp["access_token"].(string)
	idToken := tokenResp["id_token"].(string)
	refreshToken := tokenResp["refresh_token"].(string)

	t.Log("✅ TOKENS RECEIVED")

	//--------------------------------------
	// 5. VALIDATE ID TOKEN (OIDC)
	//--------------------------------------

	validateJWT(t, idToken, ClientID)

	t.Log("✅ ID TOKEN VALIDATED")

	//--------------------------------------
	// 6. ACCESS RESOURCE
	//--------------------------------------

	req, _ := http.NewRequest("GET",
		ResourceBaseURL+"/protected",
		nil,
	)

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("resource access failed: %s", string(body))
	}

	t.Log("✅ RESOURCE ACCESS SUCCESS")

	//--------------------------------------
	// 7. REFRESH FLOW
	//--------------------------------------

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", refreshToken)
	refreshForm.Set("client_id", ClientID)
	refreshForm.Set("client_secret", ClientSecret)

	refreshResp := exchangeToken(t, client, refreshForm)

	newAccess := refreshResp["access_token"].(string)

	if newAccess == accessToken {
		t.Fatal("access token not rotated")
	}

	t.Log("✅ TOKEN REFRESH SUCCESS")

	//--------------------------------------
	// 8. REFRESH REPLAY (SECURITY TEST)
	//--------------------------------------

	reqReplay, _ := http.NewRequest(
		"POST",
		OauthBaseURL+"/token",
		bytes.NewBufferString(refreshForm.Encode()),
	)

	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, _ = client.Do(reqReplay)

	if resp.StatusCode == 200 {
		t.Fatal("refresh replay allowed — SECURITY BUG")
	}

	t.Log("✅ REFRESH REPLAY BLOCKED")

	t.Log("========== FLOW COMPLETE ==========")
}

////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////

func validateJWT(t *testing.T, tokenString, audience string) {

	cache := jwk.NewCache(context.Background())

	jwksURL := OauthBaseURL + "/.well-known/jwks.json"

	cache.Register(jwksURL, jwk.WithMinRefreshInterval(5*time.Minute))

	set, err := cache.Get(context.Background(), jwksURL)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer(OauthBaseURL),
		jwt.WithAudience(audience),
	)

	if err != nil {
		t.Fatal("invalid jwt:", err)
	}

	sub, _ := token.Get("sub")
	t.Log("JWT subject:", sub)
}

func exchangeToken(t *testing.T, client *http.Client, form url.Values) map[string]any {

	req, _ := http.NewRequest(
		"POST",
		OauthBaseURL+"/token",
		bytes.NewBufferString(form.Encode()),
	)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		t.Fatalf("token exchange failed: %s", string(body))
	}

	var result map[string]any
	json.Unmarshal(body, &result)

	return result
}

func callAPI(t *testing.T, client *http.Client,
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
		t.Fatalf("%s %s failed: %s",
			method, path, string(b))
	}

	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
}
