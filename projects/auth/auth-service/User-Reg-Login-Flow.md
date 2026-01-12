# 🔐 Authentication & Authorization Architecture

This system is built in layered form. Each layer has a single responsibility.

Identity Creation  →  Identity Proof  →  Strong Authentication  →  Authorization  →  Identity Federation
Registration       →  Login           →  MFA                    →  OAuth 2.0       →  OpenID Connect

Tokens by responsibility:

| Token | Purpose |
|------|--------|
| `login_token` | Authentication session |
| `authorization_code` | OAuth handshake |
| `access_token` | API authorization |
| `id_token` | User identity |
| `refresh_token` | Session continuation |

---

## 1️⃣ Registration Flow (Zero-Knowledge)

Password never leaves the client.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Auth Server

    C->>C: Generate salt
    C->>C: Derive verifier = Argon2id(password, salt)
    C->>S: POST /users/register {username, email, salt, verifier}
    S->>S: Store user(salt, verifier)
    S->>C: 201 Created

Algorithm:

salt ← random(16 bytes)
verifier ← Argon2id(password, salt)

Stored:

User {
  username,
  salt,
  password_verifier
}


⸻

2️⃣ Login Flow (Challenge–Response)

sequenceDiagram
    participant C as Client
    participant S as Auth Server

    C->>S: POST /login/challenge {username}
    S->>S: Generate challenge + challenge_id
    S->>C: {challenge, challenge_id, salt}

    C->>C: verifier = Argon2id(password, salt)
    C->>C: proof = HMAC(verifier, challenge)

    C->>S: POST /login/verify {username, challenge_id, proof}
    S->>S: expected = HMAC(stored_verifier, stored_challenge)
    S->>C: login_token

Security:
	•	Password never transmitted
	•	Proof valid once
	•	Replay resistant
	•	MITM safe

⸻

3️⃣ MFA Flow (Authenticator App / TOTP)

sequenceDiagram
    participant C as Client
    participant S as Auth Server
    participant A as Authenticator App

    C->>S: POST /mfa/enroll/start
    S->>C: QR Code + secret
    C->>A: Scan QR

    A->>C: OTP code
    C->>S: POST /mfa/enroll/verify {code}
    S->>S: Enable MFA
    S->>C: MFA Enabled

During login:

sequenceDiagram
    C->>S: POST /login/verify
    S->>C: login_token(auth_level=PASSWORD)

    C->>S: POST /mfa/verify {code}
    S->>C: login_token(auth_level=MFA_VERIFIED)


⸻

4️⃣ OAuth 2.0 Authorization Code Flow

OAuth begins only after login_token is valid and MFA passed.

sequenceDiagram
    participant C as Client
    participant AS as Authorization Server

    C->>AS: GET /authorize (Authorization: Login <login_token>)
    AS->>AS: Validate login_token & MFA
    AS->>C: Redirect with authorization_code

    C->>AS: POST /token {authorization_code}
    AS->>C: access_token + refresh_token + id_token


⸻

5️⃣ PKCE (Public Clients)

sequenceDiagram
    participant C as Client
    participant AS as Authorization Server

    C->>C: code_verifier = random()
    C->>C: code_challenge = SHA256(code_verifier)

    C->>AS: /authorize?code_challenge
    AS->>C: authorization_code

    C->>AS: /token {authorization_code, code_verifier}
    AS->>C: access_token

Prevents:
	•	Code interception
	•	Mobile/SPA attacks

⸻

6️⃣ OpenID Connect (OIDC)

OIDC adds identity on top of OAuth.

sequenceDiagram
    participant C as Client
    participant AS as Auth Server

    C->>AS: /authorize scope=openid
    AS->>C: authorization_code

    C->>AS: /token
    AS->>C: id_token + access_token

id_token is a JWT:

{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "client-123",
  "iat": 1700000000,
  "exp": 1700003600,
  "email": "user@example.com"
}


⸻

🧱 Layered Architecture Diagram

graph TD
    A[Registration] --> B[Login]
    B --> C[MFA]
    C --> D[login_token]
    D --> E[OAuth 2.0]
    E --> F[JWT access_token]
    E --> G[OIDC id_token]


⸻

🔑 Token Responsibility

Token	Used For
login_token	Authentication state
access_token	API authorization
id_token	User identity
refresh_token	Token renewal


⸻

🏁 Summary

You have implemented:
	•	Zero-knowledge registration
	•	Cryptographic login proof
	•	MFA authentication layer
	•	OAuth 2.0 authorization
	•	PKCE security for public clients
	•	OIDC identity federation
	•	JWT infrastructure

This architecture is equivalent to enterprise identity providers like:

Auth0 · Okta · Google Identity · Azure AD

but built from first principles, cleanly and correctly.