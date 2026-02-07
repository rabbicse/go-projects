package token

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JWTTokenValidator struct {
	keySet *jwk.Cache
	issuer string
}

func NewJWTValidator(jwksURL string, issuer string) *JWTTokenValidator {

	cache := jwk.NewCache(context.Background())

	cache.Register(
		jwksURL,
		jwk.WithMinRefreshInterval(15*time.Minute),
	)

	return &JWTTokenValidator{
		keySet: cache,
		issuer: issuer,
	}
}

func (v *JWTTokenValidator) Validate(tokenString string) (jwt.Token, error) {

	set, err := v.keySet.Get(context.Background(), v.issuer+"/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
	)

	if err != nil {
		return nil, err
	}

	return token, nil
}
