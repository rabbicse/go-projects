# 🔐 Login Flow – Challenge–Response Authentication

This authentication system is a **password-based but passwordless-on-the-wire** protocol.  
The user’s password is never transmitted to the server. Instead, cryptographic proofs are exchanged.

It forms the **root security primitive** for the entire system:
- OAuth 2.0
- PKCE
- OpenID Connect (OIDC)

Everything depends on this login flow.

---

## 🎯 Goals

- Never transmit the password
- Prevent replay attacks
- Protect against MITM
- Make offline brute force expensive
- Avoid storing passwords
- Be API-only (no cookies required)

---

## 🧠 Cryptography Used

| Purpose                | Algorithm       |
|-----------------------|-----------------|
| Password derivation   | Argon2id        |
| Proof generation      | HMAC-SHA256     |
| Randomness            | crypto/rand     |
| Transport encoding    | Base64URL       |
| Compare safety        | Constant-time   |

Argon2id parameters:

Iterations   = 1
Memory       = 64 MB (2^16 KB)
Parallelism  = 4
Output size  = 32 bytes (256 bits)

---

## 🗃 User Registration (One-Time Setup)

When a user is created:

1. Generate salt:

salt ← random(16 bytes)

2. Derive password verifier:

verifier = Argon2id(password, salt)

3. Store:

User {
id,
username,
salt,
password_verifier
}

> Password is never stored.  
> Only the verifier and salt exist on the server.

---

## 🔄 Login Flow Overview

Client ──(1)──> POST /login/challenge
Client <─(2)─── challenge + salt
Client ──(3)──> POST /login/verify (proof)
Client <─(4)─── login_token

---

## 1️⃣ Request Login Challenge

**Request**

POST /login/challenge
{
“username”: “alice”
}

**Server Steps**
1. Find user by username
2. Generate random challenge:

challenge ← random(32 bytes)
challenge_id ← random token

3. Save challenge:

Challenge {
id,
user_id,
value,
expires_at = now + 2 minutes,
used = false
}

4. Return:

{
challenge_id,
challenge: base64url(challenge),
salt: base64url(user.salt)
}

---

## 2️⃣ Client Computes Password Verifier

Client reconstructs the same verifier as server:

verifier = Argon2id(password, salt)

This equals the server’s stored `password_verifier`.

---

## 3️⃣ Client Computes Proof

proof = HMAC-SHA256(
key = verifier,
message = challenge
)

Encode:

proof_b64url = base64url(proof)

---

## 4️⃣ Verify Login

**Request**

POST /login/verify
{
“username”: “alice”,
“challenge_id”: “…”,
“proof”: “…”
}

**Server Steps**
1. Find user
2. Find challenge
3. Validate:

challenge.used == false
challenge.expires_at > now

4. Recompute expected proof:

expected = HMAC-SHA256(
key = user.password_verifier,
message = challenge.value
)

5. Compare safely:

hmac.Equal(expected, proof)

6. Mark challenge used
7. Issue login token:

login_token ← random(32 bytes)

Store:

LoginToken {
value,
user_id,
expires_at
}

Return:

{
login_token
}

---

## 🔑 Login Token

The `login_token` represents an authenticated session.

It is later used in OAuth:

Authorization: Login <login_token>

No cookies, no sessions, fully stateless and API-driven.

---

## 🛡 Security Properties

| Threat                    | Protection |
|---------------------------|-----------|
Password interception       | ❌ Impossible |
Replay attack               | ❌ Impossible |
MITM attack                 | ❌ Blocked |
Database breach             | ❌ No passwords stored |
Offline brute force         | ❌ Argon2id is memory hard |
Timing attack               | ❌ Constant-time compare |

---

## 🧱 Architectural Role

This login flow is the **base layer**:

[ Challenge–Response Login ]
↓
[ Login Token ]
↓
[ OAuth 2.0 ]
↓
[ PKCE ]
↓
[ OIDC ]

Without this layer, OAuth and OIDC are meaningless.

---

## 🏁 Summary

You implemented a production-grade authentication system:

- Cryptographically sound
- Zero-password exposure
- Replay-safe
- Stateless
- API-first
- OAuth-ready
- OIDC-ready

This is not a demo login.  
This is real identity infrastructure.