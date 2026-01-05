# Auth Service – OAuth 2.0 & OpenID Connect (Go + Gin + DDD)

A from-scratch implementation of OAuth 2.0 Authorization Code Flow with OpenID Connect (OIDC), built in Go, following Domain-Driven Design (DDD) principles and clean architecture.

This project intentionally avoids existing OAuth/OIDC servers (Keycloak, Ory, Auth0) to demonstrate protocol-level understanding and backend system design.

---

## Features

- OAuth 2.0 Authorization Code Grant
- OpenID Connect (OIDC) Provider
- RSA-signed ID Tokens (RS256)
- JWKS endpoint for public key discovery
- OIDC Discovery (.well-known/openid-configuration)
- One-time authorization code (replay protection)
- In-memory persistence (pluggable)
- Clean DDD layering
- Automated shell-based test flow

---

## Architecture Overview
```bash
cmd/
└── server/                Application entrypoint (composition root)

internal/
├── domain/                Pure business models
│   ├── client/
│   ├── user/
│   ├── authcode/
│   └── token/
│
├── application/           Use cases & protocol logic
│   ├── oauth/
│   └── oidc/
│
├── infrastructure/        Technical implementations
│   ├── jwt/
│   └── persistence/
│
└── interfaces/http/       HTTP layer (Gin)
    ├── handlers/
    ├── routes/
    └── router.go
```

Design rules:
- Domain layer is framework-free
- Application layer contains OAuth/OIDC logic
- Infrastructure layer handles crypto, JWT, persistence
- HTTP layer is thin (no business logic)
- Dependencies flow inward only

---

## OAuth 2.0 Flow

Authorization Code Grant:

1. Client redirects user to /authorize
2. Server validates client_id, redirect_uri, scope
3. Authorization Code is issued (short-lived, one-time)
4. Client exchanges code at /token
5. Server issues access_token, refresh_token, id_token (if openid scope is present)

---

## OpenID Connect (OIDC)

Supported endpoints:

- /authorize
- /token
- /.well-known/openid-configuration
- /jwks.json

ID Token:
- Signed using RS256
- Claims:
  - iss (issuer)
  - sub (user identifier)
  - aud (client identifier)
  - iat, exp
  - email (if requested)

---

## RFCs & Specifications

- RFC 6749 – OAuth 2.0 Authorization Framework
  https://datatracker.ietf.org/doc/html/rfc6749

- RFC 6750 – Bearer Token Usage
  https://datatracker.ietf.org/doc/html/rfc6750

- OpenID Connect Core 1.0
  https://openid.net/specs/openid-connect-core-1_0.html

- RFC 7519 – JSON Web Token (JWT)
  https://datatracker.ietf.org/doc/html/rfc7519

- RFC 7517 – JSON Web Key (JWK)
  https://datatracker.ietf.org/doc/html/rfc7517

---

## Running the Server

go run cmd/server/main.go

Base URL:
http://localhost:8080

---

## Automated Testing

A shell-based automated test is included.

Run:
bash tests/test-flow.sh

The test verifies:
- OIDC discovery endpoint
- JWKS endpoint
- Authorization Code issuance
- Token exchange
- ID Token issuance
- Authorization code replay protection

---

## Example Authorization Request
```bash
http://localhost:8080/authorize?
response_type=code&
client_id=client-123&
redirect_uri=http://localhost:3000/callback&
scope=openid email profile&
state=xyz
```

---

## Example Token Request
```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=client-123" \
  -d "client_secret=secret"
```
---

## Current Limitations

- In-memory persistence only
- No PKCE yet
- No OIDC nonce enforcement yet
- No refresh token rotation
- No token introspection endpoint

These are intentionally excluded to keep the core protocol implementation clear.

---

## Roadmap

- PKCE (RFC 7636)
- OIDC nonce enforcement
- JWT kid header and key rotation
- Refresh token rotation
- Token introspection
- PostgreSQL / Redis persistence
- Swagger / OpenAPI documentation

---

## Project Goal

This project demonstrates:
- Deep understanding of OAuth 2.0 and OIDC
- Clean backend architecture
- Domain-Driven Design in practice
- Security-conscious implementation
- Building identity systems without frameworks

---

## Author

Mehedi Hasan Rabbi  
Backend Engineer | Distributed Systems | Identity & Security  

GitHub: https://github.com/rabbicse
