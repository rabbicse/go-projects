package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

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
