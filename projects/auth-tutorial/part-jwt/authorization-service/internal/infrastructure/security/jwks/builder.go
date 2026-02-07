package jwks

import (
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Builder struct {
	keys []jwk.Key
}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) AddRSAKey(pub *rsa.PublicKey, kid string) error {

	key, err := jwk.FromRaw(pub)
	if err != nil {
		return err
	}

	key.Set(jwk.KeyIDKey, kid)
	key.Set(jwk.AlgorithmKey, "RS256")
	key.Set(jwk.KeyUsageKey, "sig")

	b.keys = append(b.keys, key)

	return nil
}

func (b *Builder) Build() (jwk.Set, error) {

	set := jwk.NewSet()

	for _, k := range b.keys {
		set.AddKey(k)
	}

	return set, nil
}
