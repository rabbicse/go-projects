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

## Installation
Install the following `jwt` package
```bash
go get github.com/golang-jwt/jwt/v5
```

Install the following `jwk` package
```bash
go get github.com/lestrrat-go/jwx/v2/jwk
```

# Domain Layer
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

Add Refresh Session at `/internal/domain/aggregates/token/refresh_session.go`
```golang
package token

import "time"

type RefreshSession struct {
	Token     string
	UserID    string
	ClientID  string
	ExpiresAt time.Time
}
```

At JWT Config at `/internal/domain/aggregates/token/jwt_config.go`
```golang
package token

import "time"

type JWTConfig struct {
	AccessSecret  []byte
	RefreshSecret []byte        // different secret is strongly recommended
	AccessTTL     time.Duration // 5–60 min
	RefreshTTL    time.Duration // 1–14 days
	Issuer        string        // "https://api.yourdomain.com"
}
```

At `/internal/domain/aggregates/token/token_issuer.go` add the following interface.
```golang
package token

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

type TokenIssuer interface {
	GenerateAccessToken(
		userID string,
		clientID string,
		scopes []string,
	) (string, time.Time, error)

	GenerateRefreshToken(
		userID string,
		clientID string,
	) (string, time.Time, error)

	ValidateAccessToken(tokenStr string) (*valueobjects.AccessClaims, error)
}
```

At `/internal/domain/aggregates/token/token_signer.go` add the following interface.
```golang
package token

import "crypto/rsa"

type TokenSigner interface {
	Sign(claims any) (string, error)
	PublicKey() *rsa.PublicKey
	Kid() string
}
```

## Application Layer
At `/internal/application/token/token_issuer.go` write the implementation at application layer.
```golang
package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

type TokenIssuerService struct {
	signer token.TokenSigner
	store  token.RefreshStore
	issuer string
}

func NewTokenIssuerService(signer token.TokenSigner, store token.RefreshStore, issuer string) *TokenIssuerService {
	return &TokenIssuerService{
		signer: signer,
		store:  store,
		issuer: issuer,
	}
}

func (s *TokenIssuerService) GenerateAccessToken(
	userID string,
	clientID string,
	scopes []string,
) (string, time.Time, error) {

	now := time.Now()
	exp := now.Add(15 * time.Minute)

	claims := valueobjects.AccessClaims{
		Scope:    strings.Join(scopes, " "),
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   userID,
			Audience:  []string{clientID},
			Issuer:    s.issuer,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	tokenStr, err := s.signer.Sign(claims)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenStr, exp, nil
}

func (s *TokenIssuerService) GenerateRefreshToken(
	userID string,
	clientID string,
) (string, time.Time, error) {

	tokenStr, err := generateSecureToken(64)
	if err != nil {
		return "", time.Time{}, err
	}

	exp := time.Now().Add(30 * 24 * time.Hour)

	err = s.store.Save(
		tokenStr,
		userID,
		clientID,
		exp,
	)

	if err != nil {
		return "", time.Time{}, err
	}

	return tokenStr, exp, nil
}

func (s *TokenIssuerService) ValidateAccessToken(tokenStr string) (*valueobjects.AccessClaims, error) {

	token, err := jwt.ParseWithClaims(
		tokenStr,
		&valueobjects.AccessClaims{},
		func(t *jwt.Token) (interface{}, error) {

			if t.Method != jwt.SigningMethodRS256 {
				return nil, fmt.Errorf("unexpected signing method")
			}

			return s.signer.PublicKey(), nil
		},
	)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*valueobjects.AccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func generateSecureToken(bytes int) (string, error) {
	b := make([]byte, bytes)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
```

## Infrastructure Layer
At `/internal/infrastructure/security/crypto/rsa_signer.go`
```golang
package crypto

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

type RSASigner struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

func NewRSASigner(
	priv *rsa.PrivateKey,
	pub *rsa.PublicKey,
	kid string,
) *RSASigner {
	return &RSASigner{
		privateKey: priv,
		publicKey:  pub,
		kid:        kid,
	}
}

func (s *RSASigner) Sign(claims any) (string, error) {

	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		claims.(jwt.Claims),
	)

	token.Header["kid"] = s.kid

	return token.SignedString(s.privateKey)
}

func (s *RSASigner) PublicKey() *rsa.PublicKey {
	return s.publicKey
}

func (s *RSASigner) Kid() string {
	return s.kid
}
```

At `/internal/infrastructure/persistence/memory/refresh_store.go`
```golang
package memory

import (
	"errors"
	"sync"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
)

type InMemoryRefreshStore struct {
	data sync.Map
}

func NewInMemoryRefreshStore() *InMemoryRefreshStore {
	return &InMemoryRefreshStore{}
}

func (s *InMemoryRefreshStore) Save(
	t string,
	userID string,
	clientID string,
	exp time.Time,
) error {
	s.data.Store(t, &token.RefreshSession{
		Token:     t,
		UserID:    userID,
		ClientID:  clientID,
		ExpiresAt: exp,
	})

	return nil
}

func (s *InMemoryRefreshStore) Get(
	t string,
) (*token.RefreshSession, error) {

	val, ok := s.data.Load(t)
	if !ok {
		return nil, errors.New("invalid refresh token")
	}

	session := val.(*token.RefreshSession)

	if time.Now().After(session.ExpiresAt) {
		s.data.Delete(t)
		return nil, errors.New("expired refresh token")
	}

	return session, nil
}

func (s *InMemoryRefreshStore) Delete(t string) error {
	s.data.Delete(t)
	return nil
}
```

## 🔑 RSA Key Generation — Implementation

### Generator (One-Time Operation)

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

At `/internal/infrastructure/security/keys/key_pair.go`
```golang
type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
}
```

Then at `/internal/infrastructure/security/keys/key_loader.go`
```golang
package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

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

1.2. Create a KeyRing to Manage Multiple Keys

The KeyRing will hold all your keys and determine the active one for signing:
```golang
package keys

import (
    "errors"
    "sort"
)

type KeyRing struct {
    keys   map[string]*KeyPair
    active *KeyPair
}

func NewKeyRing(pairs []*KeyPair) (*KeyRing, error) {
    if len(pairs) == 0 {
        return nil, errors.New("no signing keys found")
    }

    keyMap := make(map[string]*KeyPair)
    for _, kp := range pairs {
        keyMap[kp.Kid] = kp
    }

    // Sort keys to determine the active one (e.g., latest by Kid)
    sort.Slice(pairs, func(i, j int) bool {
        return pairs[i].Kid > pairs[j].Kid
    })

    return &KeyRing{
        keys:   keyMap,
        active: pairs[0],
    }, nil
}

func (k *KeyRing) Active() *KeyPair {
    return k.active
}

func (k *KeyRing) All() []*KeyPair {
    list := make([]*KeyPair, 0, len(k.keys))
    for _, v := range k.keys {
        list = append(list, v)
    }
    return list
}

func (k *KeyRing) Get(kid string) (*KeyPair, bool) {
    kp, ok := k.keys[kid]
    return kp, ok
}
```

### JWKS Builder

Separate package — do NOT mix with keys.

Serialization ≠ key lifecycle.

At `internal/infrastructure/security/jwks/builder.go` write the following code.
```golang
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
```

At `main.go` add the following code.
```golang
	cwd, _ := os.Getwd()
	log.Println("WORKING DIR:", cwd)
	// load all keys from the directory and create a key ring
	keyRing, err := keys.LoadKeyRing("secrets/keys")
	if err != nil {
		log.Fatal("FATAL: no signing keys found")
	}
	active := keyRing.Active()

	signer := crypto.NewRSASigner(
		active.PrivateKey,
		active.PublicKey,
		active.Kid,
	)
	builder := jwks.NewBuilder()

	for _, kp := range keyRing.All() {

		err := builder.AddRSAKey(
			kp.PublicKey,
			kp.Kid,
		)

		if err != nil {
			log.Fatal(err)
		}
	}

	jwksSet, err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}
	jwksHandler := handlers.NewJWKSHandler(jwksSet)

	refreshStore := memory.NewInMemoryRefreshStore()
	tokenIssuer := tokenApp.NewTokenIssuerService(
		signer,
		refreshStore,
		"http://localhost:8080", // issuer - temporarily set to localhost/my personal domain, should be the actual domain in production
	)
```

# Resource Service
Create JWT Token Validator at `/internal/application/jwt_token_validator.go`
```golang
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
```

Add JWT middleware at `/internal/middleware/jwt_middleware.go`
```golang
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/resource-service/internal/application/token"
)

func JWTAuthorizationMiddleware(
	validator *token.JWTTokenValidator,
) gin.HandlerFunc {

	return func(c *gin.Context) {

		auth := c.GetHeader("Authorization")

		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{"error": "missing token"},
			)
			return
		}

		tokenString := strings.TrimPrefix(auth, "Bearer ")

		token, err := validator.Validate(tokenString)
		if err != nil {

			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{"error": "invalid token"},
			)
			return
		}

		// Extract claims safely
		sub, _ := token.Get("sub")
		scope, _ := token.Get("scope")

		// Attach to context
		c.Set("sub", sub)
		c.Set("scope", scope)

		c.Next()
	}
}
```

And final `main.go` of resource server will be:
```golang
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/rabbicse/resource-service/internal/application/token"
	"github.com/rabbicse/resource-service/internal/handlers"
	"github.com/rabbicse/resource-service/internal/middleware"
)

func main() {
	r := gin.Default()

	validator := token.NewJWTValidator("http://localhost:8080/.well-known/jwks.json",
		"http://localhost:8080")

	r.GET(
		"/protected",
		middleware.JWTAuthorizationMiddleware(validator),
		handlers.ProtectedResource,
	)

	r.Run(":9090")
}
```


# OIDC
OAuth only answers:

“Can this client access a resource?”

OpenID answers:

“Who is the user?”

That identity proof is the ID Token.

🔥 First — Understand ID Token (Very Important)

An Access Token is for:
```
resource server
```

An ID Token is for:
```
client application
```

NEVER confuse them. Many developers do.

Example Flow:
```bash
User logs in
    ↓
Auth Server returns:

access_token → API
id_token     → Client
refresh      → Auth server
```

The client reads the ID token to know:

✅ user id
✅ email
✅ login time
✅ authentication method

It should NOT call /userinfo just to know who logged in.

That is why ID tokens exist.

## 🔥 Next Step: OpenID Discovery Endpoint
This is the endpoint:
```bash
GET /.well-known/openid-configuration
```

When clients hit this, they automatically learn:
	•	who issued the tokens
	•	where JWKS lives
	•	where to authorize
	•	where to get tokens

No manual config.

This is how SDKs auto-wire themselves.

For example:

👉 mobile apps
👉 SPA frameworks
👉 backend OAuth clients
👉 API gateways

All depend on this.

At infra layer add oidc discovery provider `/internal/infrastructure/security/oidc/provider.go`
```golang
package oidc

type OidcProvider struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported"`
	SubjectTypes          []string `json:"subject_types_supported"`
	IDTokenAlgs           []string `json:"id_token_signing_alg_values_supported"`
	Scopes                []string `json:"scopes_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

func NewOidcProvider(issuer string) *OidcProvider {

	return &OidcProvider{
		Issuer: issuer,

		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		JWKSUri:               issuer + "/.well-known/jwks.json",

		ResponseTypes: []string{
			"code",
		},

		SubjectTypes: []string{
			"public",
		},

		IDTokenAlgs: []string{
			"RS256",
		},

		Scopes: []string{
			"openid",
			"profile",
			"email",
		},

		TokenAuthMethods: []string{
			"client_secret_basic",
		},
	}
}
```

Then add discovery handler at `/internal/interfaces/http/handlers/discovery_handler.go`
```golang
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/infrastructure/security/oidc"
)

type DiscoveryHandler struct {
	provider *oidc.OidcProvider
}

func NewDiscoveryHandler(p *oidc.OidcProvider) *DiscoveryHandler {
	return &DiscoveryHandler{provider: p}
}

func (h *DiscoveryHandler) Handle(c *gin.Context) {

	c.Header(
		"Cache-Control",
		"public, max-age=3600",
	)

	c.JSON(http.StatusOK, h.provider)
}
```

Wire It in main.go

Right after JWKS:
```golang
provider := discovery.NewProvider(
	"http://localhost:8080",
)

discoveryHandler := handlers.NewDiscoveryHandler(provider)
```

Update Router Signature. Add handler:
```golang
func NewRouter(
	registerHandler *handlers.RegisterHandler,
	loginHandler *handlers.LoginHandler,
	oauthHandler *handlers.AuthorizeHandler,
	tokenHandler *handlers.TokenHandler,
	introspectionHandler *handlers.IntrospectionHandler,
	jwksHandler *handlers.JWKSHandler,
	discoveryHandler *handlers.DiscoveryHandler,
) *gin.Engine
```

Register Route. Inside router:
```golang
r.GET(
	"/.well-known/openid-configuration",
	discoveryHandler.Handle,
)
```

Test It. Open browser:
```bash
http://localhost:8080/.well-known/openid-configuration
```

You should see a clean JSON metadata document. When you see this — your brain should go:

“Wow… this looks like a real provider.”

Because it is 🙂

## Domain Layer
### Create ID Claims
Create `/internal/domain/valueobjects/id_claims.go`
```golang
package valueobjects

import "github.com/golang-jwt/jwt/v5"

type IDClaims struct {
	Email          string `json:"email,omitempty"`
	EmailVerified  bool   `json:"email_verified,omitempty"`
	Name           string `json:"name,omitempty"`

	jwt.RegisteredClaims
}
```

Extend TokenIssuer Interface at `/internal/domain/aggregates/token/token_issuer.go`
```golang
	GenerateIDToken(
		userID string,
		clientID string,
		email string,
	) (string, error)
```

Implement ID Token Generator. Go to your issuer service. At `/internal/application/token/token_issuer.go`
```golang
func (s *TokenIssuerService) GenerateIDToken(
	userID string,
	clientID string,
	email string,
) (string, error) {

	now := time.Now()

	claims := valueobjects.IDClaims{
		Email:         email,
		EmailVerified: true,

		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  []string{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	return s.signer.Sign(claims)
}
```

Return ID Token from /token
Now modify your OAuth token service. `/internal/application/oauth/token_service.go`
Find where tokens are issued.
```golang
idToken, err := s.tokenIssuer.GenerateIDToken(
	authCode.UserID,
	c.ID,
	user.Email, // load from repo
)

if err != nil {
	return nil, err
}
```

Update DTO at `/internal/application/dtos/token_response.go`
```golang
IDToken string `json:"id_token,omitempty"`
```

Update Authorization Code repository by adding the following method 
at `/internal/domain/aggregates/oauth/authorization_code_repository.go`.
```golang
	// 🔥 Atomic operation
	Consume(code string) (*AuthorizationCode, error)
```

At `/internal/infrastructure/persistence/memory/authorization_code_repository.go`
```golang
func (r *AuthCodeRepository) Consume(code string) (*oauth.AuthorizationCode, error) {

	r.mu.Lock()
	defer r.mu.Unlock()

	authCode, ok := r.codes[code]
	if !ok {
		return nil, errors.New("invalid authorization code")
	}

	// 🔥 delete immediately (atomic)
	delete(r.codes, code)

	return authCode, nil
}
```

Add the following method at `/internal/domain/aggregates/client.go`
```golang
func (c *Client) SupportsGrant(grant GrantType) bool {

	for _, g := range c.GrantTypes {
		if g == grant {
			return true
		}
	}

	return false
}
```