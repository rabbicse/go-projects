# JWT & JWK

## 🔐 RSA Key Generation for JWT Signing

## Infrastructure Security Specification

---

## 📌 Purpose

The Authorization Server must sign tokens in a way that:

* Clients **cannot forge**
* Resource servers can **verify without calling auth server**
* Private keys remain **secret**
* Public keys are **safely distributed**

To achieve this — we use **asymmetric cryptography**.

👉 **RSA + RS256**

---

# 🧠 Why Asymmetric Cryptography?

Two-key model:

```
Private Key  → used ONLY by Authorization Server
Public Key   → shared via JWKS
```

### Signing Flow

```
Authorization Server
       │
       │ signs JWT
       ▼
   Private Key
       │
       ▼
      JWT
       │
       │ verify
       ▼
Resource Server → uses Public Key
```

✅ No shared secret
✅ No network calls needed
✅ Scales massively

This is why **all serious identity providers use asymmetric signing**.

(Auth0, Okta, Azure AD, Cognito)

---

# 🔬 RSA Algorithm — Conceptual Overview

RSA relies on a mathematical property:

> Factoring extremely large prime numbers is computationally infeasible.

### Key Generation Steps (Simplified)

```
1. Generate two large primes:
      p, q

2. Compute:
      n = p × q

3. Compute totient:
      φ(n) = (p−1)(q−1)

4. Choose public exponent:
      e = 65537   (industry standard)

5. Compute private exponent:
      d = modular inverse of e
```

---

## Result

### Public Key

```
(n, e)
```

### Private Key

```
(n, d)
```

Even if attackers know:

```
n and e
```

They **cannot compute `d`** in any realistic timeframe.

For **4096-bit RSA**, brute force would take longer than the age of the universe.

---

# 🔐 Why RS256?

RS256 = **RSA Signature with SHA-256**

### Signing:

```
signature = RSA(
    SHA256(header + payload),
    privateKey
)
```

### Verification:

```
valid = RSA_VERIFY(
    signature,
    SHA256(header + payload),
    publicKey
)
```

---

## Why SHA-256?

✔ Collision resistant
✔ NIST approved
✔ Industry default
✔ Supported everywhere

Avoid SHA-1 completely.

---

# 📏 Why 4096-bit Instead of 2048?

| Key Size | Security         | Performance     | Recommendation              |
| -------- | ---------------- | --------------- | --------------------------- |
| 2048     | Secure today     | Faster          | Acceptable                  |
| 3072     | Very secure      | Slightly slower | Excellent                   |
| **4096** | Extreme security | Slower          | ⭐ Best for Identity Servers |

### Important Insight:

JWT signing is **not high-frequency crypto**.

You are NOT encrypting traffic — just signing tokens.

The tiny performance cost is worth the security.

👉 Identity servers often choose **4096**.

---

# 🏗️ Infrastructure Placement

```
internal/
   infrastructure/
        security/
             keys/
                 rsa_generator.go
                 key_loader.go
```

Key generation should **NOT** happen inside handlers.

Run it:

✅ via CLI tool
✅ secure init job
✅ provisioning script

Never generate keys dynamically in production.

---

# Domain Layer
Add token signer interface at `/internal/domain/aggregates/token/token_signer.go`
```golang
package token

import "crypto/rsa"

type TokenSigner interface {
	Sign(claims any) (string, error)
	PublicKey() *rsa.PublicKey
	Kid() string
}
```

Add Token Issuer at `/internal/domain/aggregates/token/token_issuer.go`
```golang
package token

import "time"

type TokenIssuer interface {
	GenerateAccessToken(
		userID string,
		clientID string,
		scopes []string,
	) (string, time.Time, error)

	GenerateRefreshToken(
		userID string,
		clientID string,
	) (string, error)
}
```

At `/internal/domain/valueobjects/access_claims.go`
```golang
package valueobjects

import "github.com/golang-jwt/jwt/v5"

type AccessClaims struct {
	Sub      string   `json:"sub"`             // user ID or client_id
	Scope    string   `json:"scope"`           // space-separated or comma
	Roles    []string `json:"roles,omitempty"` // if you have them
	ClientID string   `json:"client_id,omitempty"`
	Jti      string   `json:"jti,omitempty"` // optional unique id
	jwt.RegisteredClaims
}
```

At `/internal/domain/valueobjects/refresh_claims.go`
```golang
package valueobjects

import "github.com/golang-jwt/jwt/v5"

type RefreshClaims struct {
	UserID string `json:"sub,omitempty"`
	jwt.RegisteredClaims
}
```

Add Refresh Store at `/internal/domain/aggregates/token/refresh_store.go`
```golang
package token

import "time"

type RefreshStore interface {
	Save(token, userID string, ttl time.Duration) error
	Get(token string) (string, error)
	Delete(token string) error
}
```

# 🔑 RSA Key Generation — Implementation

## Generator (One-Time Operation)

At `/internal/infrastructure/security/keys/rsa_generator.go`

```go
package keys

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "os"
)

func GenerateRSA4096(privatePath, publicPath string) error {

    privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return err
    }

    // PRIVATE KEY
    privBytes := x509.MarshalPKCS1PrivateKey(privateKey)

    privFile, err := os.Create(privatePath)
    if err != nil {
        return err
    }

    pem.Encode(privFile, &pem.Block{
        Type: "RSA PRIVATE KEY",
        Bytes: privBytes,
    })

    // PUBLIC KEY
    pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    if err != nil {
        return err
    }

    pubFile, err := os.Create(publicPath)
    if err != nil {
        return err
    }

    pem.Encode(pubFile, &pem.Block{
        Type: "PUBLIC KEY",
        Bytes: pubBytes,
    })

    return nil
}
```

Then at `/internal/infrastructure/security/keys/key_loader.go`
```golang
package keys

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "os"
    "fmt"
)

type KeyPair struct {
    PrivateKey *rsa.PrivateKey
    PublicKey  *rsa.PublicKey
    Kid        string
}

func LoadKeyPair(privatePath string, kid string) (*KeyPair, error) {

    data, err := os.ReadFile(privatePath)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(data)
    if block == nil {
        return nil, fmt.Errorf("invalid private key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return &KeyPair{
        PrivateKey: priv,
        PublicKey:  &priv.PublicKey,
        Kid:        kid,
    }, nil
}
```

At `/internal/infrastructure/persistence/memory/refresh_store.go`
```golang
package memory

import (
	"errors"
	"sync"
	"time"
)

type InMemoryRefreshStore struct {
	data sync.Map
}

func (s *InMemoryRefreshStore) Save(token, userID string, ttl time.Duration) error {

	s.data.Store(token, userID)

	time.AfterFunc(ttl, func() {
		s.data.Delete(token)
	})

	return nil
}

func (s *InMemoryRefreshStore) Get(token string) (string, error) {

	val, ok := s.data.Load(token)
	if !ok {
		return "", errors.New("invalid refresh token")
	}

	return val.(string), nil
}

func (s *InMemoryRefreshStore) Delete(token string) error {
	s.data.Delete(token)
	return nil
}
```

### Then install the following `jwt` package
```bash
go get github.com/golang-jwt/jwt/v5
```

At `/internal/infrastructure/security/jwt/token_generator.go`

---

# 🔄 Key Lifecycle (VERY Important)

Most tutorials skip this.

Production systems MUST define lifecycle.

---

## Recommended Strategy

### Rotation Every:

```
6 — 12 months
```

---

## Rotation Model

```
kid-2025-01  → ACTIVE
kid-2024-01  → still in JWKS
```

Never remove old keys immediately.

Why?

Because issued tokens may still be valid.

---

### Safe Rotation Flow

```
1. Generate new key
2. Add to JWKS
3. Start signing with new key
4. Wait for old tokens to expire
5. Remove old key
```

Zero downtime.

---

# 🚨 Security Threat Model

## If Private Key Leaks:

Attackers can:

✔ forge tokens
✔ impersonate users
✔ bypass auth

👉 This is a **total compromise**.

---

## Therefore:

### NEVER:

❌ Commit keys to Git
❌ Send via Slack
❌ Store in Docker image
❌ Put inside config maps

---

## ALWAYS Prefer:

* Vault
* AWS Secrets Manager
* Azure Key Vault
* GCP Secret Manager

Even for mid-scale systems.

---

# ⚠️ Common Beginner Mistakes

## ❌ Using HS256

Symmetric key = shared secret.

Meaning:

Every service that verifies tokens can also create them.

Catastrophic architecture flaw.

👉 Avoid for auth servers.

---

## ❌ Generating Keys On Startup

If container restarts:

💥 All tokens instantly invalid.

Production outage.

---

## ❌ Missing `kid`

Without it — rotation becomes painful.

Always include:

```
token.Header["kid"]
```

---

# 🧭 Future Compatibility (OIDC)

By implementing RSA correctly now — you automatically unlock:

✅ JWKS
✅ OpenID Discovery
✅ ID Tokens
✅ Federation
✅ Multi-region verification

You are laying the **cryptographic foundation** of your identity platform.

This is not just auth anymore — it's security engineering.

---

# ⭐ Recommended Next Step

After RSA generation, immediately implement:

## 👉 JWKS endpoint

```
GET /.well-known/jwks.json
```

Then:

## 👉 Discovery endpoint

```
GET /.well-known/openid-configuration
```

At that point…

Your server starts looking like a real OIDC provider.

---

If you want — next I can build you an even more advanced doc:

👉 **"JWT Signing Architecture for Authorization Servers"**

It covers:

* Access vs ID token signing
* Multi-tenant keys
* HSM usage
* ECDSA vs RSA
* Offline signing
* Token hierarchy

Just say:

> next doc

and we’ll level your auth server up to **enterprise-grade design** 🚀
