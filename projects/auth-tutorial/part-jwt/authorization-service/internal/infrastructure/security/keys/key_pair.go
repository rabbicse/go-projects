package keys

import "crypto/rsa"

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
}
