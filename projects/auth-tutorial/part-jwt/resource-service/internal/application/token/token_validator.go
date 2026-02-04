package token

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/rabbicse/resource-service/internal/application/dtos"
)

type TokenValidator struct {
	IntrospectionURL string
	ClientID         string
	ClientSecret     string
}

func (v *TokenValidator) Validate(token string) (*dtos.IntrospectionResponse, error) {
	body := map[string]string{
		"token": token,
	}

	b, _ := json.Marshal(body)

	req, err := http.NewRequest(
		"POST",
		v.IntrospectionURL,
		bytes.NewBuffer(b),
	)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(v.ClientID, v.ClientSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res dtos.IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	if !res.Active {
		return nil, http.ErrNoCookie
	}

	return &res, nil
}
