# API Reference — OAuth2 Example

This document summarizes the HTTP endpoints, request/response shapes, and
key types used by the example authorization server and resource server.

Overview
--------

- Authorization server base URL: `http://localhost:8080`
- Client callback example: `http://localhost:8090/callback`

Endpoints
---------

- `GET /authorize`
  - Query parameters: `response_type=code`, `client_id`, `redirect_uri`,
    `scope`, `state`.
  - Validates the request against configured clients and redirects the
    user to `/login` to obtain user consent.

- `GET /login`
  - Rendered HTML form that POSTs to `/consent` with the same parameters.

- `POST /consent`
  - Expects form fields: `client_id`, `redirect_uri`, `scope`, `state`,
    `action=allow`.
  - If consent is given, the server issues an authorization code and
    redirects to the client's `redirect_uri` with `?code=<code>&state=<state>`.

- `POST /token`
  - Form fields: `grant_type=authorization_code`, `code`, `redirect_uri`.
  - Client must provide HTTP Basic Auth (`client_id` / `client_secret`).
  - On success returns JSON: `{"access_token":"...","token_type":"..."}`.

- `GET /access`
  - Query parameter: `access_token`.
  - Returns the protected resource associated with the token if valid.

Key types & packages
--------------------

- `auth.App` — client registration record with `ClientId`, `ClientSecret`,
  `RedirectUri`, and allowed `Scope`.
- `auth.AccessCombination` — demo structure holding `State`, `Code`, and
  `AccessToken` values stored in-memory to tie an authorization request to
  an issued token.

Important implementation notes
------------------------------

- Tokens and codes are generated using `rand.Int()` and stored in memory.
- The example uses plain HTTP and does not perform cryptographic signing of
  tokens or secure client validation — this is acceptable for a learning
  example but not for production use.

Suggested next steps to harden (if you plan to extend this project):

- Use cryptographically secure token generation (`crypto/rand`).
- Persist client data and tokens in a database rather than in-memory maps.
- Use TLS (HTTPS) and validate redirect URIs strictly.
- Add unit tests for each handler and error path.
