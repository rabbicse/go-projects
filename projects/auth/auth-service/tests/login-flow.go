// package main

// import (
// 	"bytes"
// 	"crypto/hmac"
// 	"crypto/sha256"
// 	"encoding/base64"
// 	"encoding/hex"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"net/http"

// 	"golang.org/x/crypto/argon2"
// )

// const (
// 	BaseURL  = "http://localhost:8080"
// 	Username = "alice"
// 	Password = "password123"
// )

// func hexDump(label string, b []byte) {
// 	fmt.Printf("%s (hex): %s\n", label, hex.EncodeToString(b))
// }

// func b64url(label string, b []byte) {
// 	fmt.Printf("%s (base64url): %s\n", label, base64.RawURLEncoding.EncodeToString(b))
// }

// func main() {
// 	fmt.Println("================================")
// 	fmt.Println("1. Request Login Challenge")
// 	fmt.Println("================================")

// 	resp, err := http.Post(
// 		BaseURL+"/login/challenge",
// 		"application/json",
// 		bytes.NewBuffer([]byte(`{"username":"`+Username+`"}`)),
// 	)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer resp.Body.Close()

// 	var chal struct {
// 		ChallengeID string `json:"challenge_id"`
// 		Challenge   string `json:"challenge"`
// 		Salt        string `json:"salt"`
// 	}

// 	json.NewDecoder(resp.Body).Decode(&chal)

// 	fmt.Println("Challenge ID:", chal.ChallengeID)
// 	fmt.Println("Challenge (raw):", chal.Challenge)
// 	fmt.Println("Salt (raw):     ", chal.Salt)
// 	fmt.Println()

// 	fmt.Println("================================")
// 	fmt.Println("2. Decode Base64URL")
// 	fmt.Println("================================")

// 	salt, err := base64.RawURLEncoding.DecodeString(chal.Salt)
// 	if err != nil {
// 		panic("Salt decode failed: " + err.Error())
// 	}
// 	challenge, err := base64.RawURLEncoding.DecodeString(chal.Challenge)
// 	if err != nil {
// 		panic("Challenge decode failed: " + err.Error())
// 	}

// 	hexDump("Salt", salt)
// 	hexDump("Challenge", challenge)
// 	fmt.Println()

// 	fmt.Println("================================")
// 	fmt.Println("3. Derive Verifier (Argon2id)")
// 	fmt.Println("================================")

// 	verifier := argon2.IDKey([]byte(Password), salt, 1, 64*1024, 4, 32)

// 	hexDump("Verifier", verifier)
// 	b64url("Verifier", verifier)
// 	fmt.Println()

// 	fmt.Println("================================")
// 	fmt.Println("4. Compute Proof = HMAC(verifier, challenge)")
// 	fmt.Println("================================")

// 	mac := hmac.New(sha256.New, verifier)
// 	mac.Write(challenge)
// 	proof := mac.Sum(nil)

// 	hexDump("Proof", proof)
// 	b64url("Proof", proof)
// 	fmt.Println()

// 	fmt.Println("================================")
// 	fmt.Println("5. Verify Login")
// 	fmt.Println("================================")

// 	body := fmt.Sprintf(`{
// 		"username":"%s",
// 		"challenge_id":"%s",
// 		"proof":"%s"
// 	}`, Username, chal.ChallengeID, base64.RawURLEncoding.EncodeToString(proof))

// 	fmt.Println("Verify payload:")
// 	fmt.Println(body)
// 	fmt.Println()

// 	resp, err = http.Post(
// 		BaseURL+"/login/verify",
// 		"application/json",
// 		bytes.NewBuffer([]byte(body)),
// 	)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer resp.Body.Close()

// 	out, _ := io.ReadAll(resp.Body)
// 	fmt.Println("Server response:")
// 	fmt.Println(string(out))
// }

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/argon2"
)

const (
	BaseURL  = "http://localhost:8080"
	Username = "alice"
	Password = "password123"
	Email    = "alice@example.com"
)

func hexDump(label string, b []byte) {
	fmt.Printf("%s (hex): %s\n", label, hex.EncodeToString(b))
}

func b64url(label string, b []byte) {
	fmt.Printf("%s (base64url): %s\n", label, base64.RawURLEncoding.EncodeToString(b))
}

func main() {
	fmt.Println("================================")
	fmt.Println("0. Client-side Registration")
	fmt.Println("================================")

	// Generate salt
	salt := make([]byte, 16)
	rand.Read(salt)

	// Derive verifier (Argon2id)
	verifier := argon2.IDKey([]byte(Password), salt, 1, 64*1024, 4, 32)

	hexDump("Salt", salt)
	hexDump("Verifier", verifier)
	fmt.Println()

	// Register user
	regBody := fmt.Sprintf(`{
		"username": "%s",
		"email": "%s",
		"salt": "%s",
		"verifier": "%s"
	}`,
		Username,
		Email,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(verifier),
	)

	fmt.Println("Registration payload:")
	fmt.Println(regBody)
	fmt.Println()

	regResp, err := http.Post(
		BaseURL+"/users/register",
		"application/json",
		bytes.NewBuffer([]byte(regBody)),
	)
	if err != nil {
		panic(err)
	}
	defer regResp.Body.Close()

	regOut, _ := io.ReadAll(regResp.Body)
	fmt.Println("Registration response:")
	fmt.Println(string(regOut))
	fmt.Println()

	// -------------------------------------------------------

	fmt.Println("================================")
	fmt.Println("1. Request Login Challenge")
	fmt.Println("================================")

	resp, err := http.Post(
		BaseURL+"/login/challenge",
		"application/json",
		bytes.NewBuffer([]byte(`{"username":"`+Username+`"}`)),
	)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	var chal struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
		Salt        string `json:"salt"`
	}
	json.NewDecoder(resp.Body).Decode(&chal)

	fmt.Println("Challenge ID:", chal.ChallengeID)
	fmt.Println("Challenge (raw):", chal.Challenge)
	fmt.Println("Salt (raw):     ", chal.Salt)
	fmt.Println()

	fmt.Println("================================")
	fmt.Println("2. Decode Base64URL")
	fmt.Println("================================")

	saltSrv, _ := base64.RawURLEncoding.DecodeString(chal.Salt)
	challenge, _ := base64.RawURLEncoding.DecodeString(chal.Challenge)

	hexDump("Salt (server)", saltSrv)
	hexDump("Challenge", challenge)
	fmt.Println()

	fmt.Println("================================")
	fmt.Println("3. Re-Derive Verifier")
	fmt.Println("================================")

	verifier2 := argon2.IDKey([]byte(Password), saltSrv, 1, 64*1024, 4, 32)

	hexDump("Verifier (derived again)", verifier2)
	fmt.Println()

	fmt.Println("================================")
	fmt.Println("4. Compute Proof = HMAC(verifier, challenge)")
	fmt.Println("================================")

	mac := hmac.New(sha256.New, verifier2)
	mac.Write(challenge)
	proof := mac.Sum(nil)

	hexDump("Proof", proof)
	b64url("Proof", proof)
	fmt.Println()

	fmt.Println("================================")
	fmt.Println("5. Verify Login")
	fmt.Println("================================")

	body := fmt.Sprintf(`{
		"username":"%s",
		"challenge_id":"%s",
		"proof":"%s"
	}`,
		Username,
		chal.ChallengeID,
		base64.RawURLEncoding.EncodeToString(proof),
	)

	fmt.Println("Verify payload:")
	fmt.Println(body)
	fmt.Println()

	resp, err = http.Post(
		BaseURL+"/login/verify",
		"application/json",
		bytes.NewBuffer([]byte(body)),
	)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	out, _ := io.ReadAll(resp.Body)
	fmt.Println("Server response:")
	fmt.Println(string(out))
}
