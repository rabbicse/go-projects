## Architecture Diagrams & Flow Mapping

This section explains how requests flow through the system and which parts of the codebase are responsible for each OAuth 2.0 and OpenID Connect flow. The diagrams are ASCII-based and render correctly on GitHub.

---

## High-Level Architecture

```
Client / Browser
      |
      v
interfaces/http (Gin)
      |
      v
application (oauth / oidc)
      |
      v
domain (client, user, authcode, token)
      |
      v
infrastructure (jwt, persistence)
```

Responsibilities:

* **interfaces/http**: HTTP routing, request parsing, response formatting
* **application**: OAuth 2.0 and OIDC use cases
* **domain**: Pure business models and rules
* **infrastructure**: JWT signing, JWKS, persistence implementations

---

## OAuth 2.0 Authorization Code Flow

### Flow Diagram

```
Browser
  |
  | GET /authorize
  |
  v
AuthorizeHandler
  |
  v
OAuthService.Authorize()
  |
  |-- validate client
  |-- validate redirect_uri
  |-- validate scopes
  |
  v
AuthCodeRepository.Save()
  |
  v
302 Redirect with ?code=XXXX
```

### Code Mapping

| Responsibility             | Package                    | File             |
| -------------------------- | -------------------------- | ---------------- |
| HTTP handler               | interfaces/http/handlers   | authorize.go     |
| Routing                    | interfaces/http/routes     | routes.go        |
| OAuth logic                | application/oauth          | authorize.go     |
| Client validation          | domain/client              | client.go        |
| Authorization code storage | infrastructure/persistence | authcode_repo.go |

---

## OAuth 2.0 Token Exchange Flow

### Flow Diagram

```
Client
  |
  | POST /token
  |
  v
TokenHandler
  |
  v
TokenService.Token()
  |
  |-- authenticate client
  |-- consume authorization code
  |-- issue access token
  |-- issue refresh token
  |
  v
TokenRepository.Save()
```

### Code Mapping

| Responsibility        | Package                    | File          |
| --------------------- | -------------------------- | ------------- |
| HTTP handler          | interfaces/http/handlers   | token.go      |
| Token logic           | application/oauth          | token.go      |
| Auth code consumption | domain/authcode            | repository.go |
| Token storage         | infrastructure/persistence | token_repo.go |

---

## OpenID Connect (OIDC) ID Token Flow

### Flow Diagram

```
TokenService
  |
  |-- scope contains "openid"
  |
  v
OIDCService.GenerateIDToken()
  |
  |-- build IDTokenClaims
  |
  v
JWT Signer (RS256)
  |
  v
Signed ID Token
```

### Code Mapping

| Responsibility      | Package            | File            |
| ------------------- | ------------------ | --------------- |
| OIDC interface      | application/oidc   | service.go      |
| OIDC implementation | application/oidc   | oidc_service.go |
| ID Token claims     | application/oidc   | claims.go       |
| JWT signing         | infrastructure/jwt | signer.go       |

---

## OIDC Discovery Flow

### Flow Diagram

```
Client
  |
  | GET /.well-known/openid-configuration
  |
  v
OIDCHandler
  |
  v
Discovery JSON Response
```

### Code Mapping

| Responsibility    | Package                  | File      |
| ----------------- | ------------------------ | --------- |
| Discovery handler | interfaces/http/handlers | oidc.go   |
| Routing           | interfaces/http/routes   | routes.go |

---

## JWKS (JSON Web Key Set) Flow

### Flow Diagram

```
OIDC Client / Resource Server
  |
  | GET /jwks.json
  |
  v
JWKSHandler
  |
  v
Public RSA Key (JWK)
```

### Code Mapping

| Responsibility | Package                  | File      |
| -------------- | ------------------------ | --------- |
| JWK creation   | infrastructure/jwt       | jwks.go   |
| JWKS handler   | interfaces/http/handlers | jwks.go   |
| Routing        | interfaces/http/routes   | routes.go |

---

## Dependency Direction (DDD Rule)

```
interfaces/http
      ↓
application
      ↓
domain
      ↑
infrastructure
```

Rules enforced:

* Domain depends on nothing
* Application depends on domain
* Infrastructure depends on domain
* HTTP depends on application only

---

## Why This Design Works

* OAuth and OIDC logic are testable without HTTP
* Infrastructure can be swapped without touching business logic
* No framework leakage into domain or application layers
* Mirrors real-world identity systems architecture
