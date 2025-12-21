# OAuth2 Example (auth-server + client)

This repository contains a small educational OAuth2-style example implemented
in Go. It includes:

- `auth-server/` — a combined authorization server and resource server that
  demonstrates the authorization code flow (endpoints: `/authorize`,
  `/login`, `/consent`, `/token`, `/access`).
- `client/` — a simple client application that drives the flow and displays
  the protected resource.

Ports used by the example:

- Authorization & Resource server: `:8080`
- Client: `:8090`

Quick run (developer/demo machine):

```bash
# from repository root
go run ./auth-server
# in a separate terminal
go run ./client
```

Open the client in your browser: http://localhost:8090

Flow summary:

1. Client redirects the user to `http://localhost:8080/authorize` with
   `response_type=code`, `client_id`, `redirect_uri`, `scope`, and `state`.
2. Authorization server validates request and redirects the user to
   `/login` where the user can consent (`/consent`).
3. On consent, the server issues an authorization code and redirects back
   to the client's callback (e.g. `http://localhost:8090/callback?code=...`).
4. Client exchanges the code for an access token by POSTing to `/token`
   with HTTP Basic auth (client_id:client_secret).
5. Client requests the protected resource from `/access?access_token=...`.

Notes & caveats:

- This code is an educational demo only — token generation, storage, and
  authentication are insecure (random ints, in-memory maps, no TLS).
- Do not use this code in production.

See `docs/API.md` for endpoint and type details.
