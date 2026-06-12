---
name: Bug Report
about: Something is broken or behaves incorrectly
labels: bug
---

## Bug Description

A clear description of what the bug is.

## Steps to Reproduce

1. Start the backend and frontend (see `docs/RUNNING_THE_APPLICATION.md`)
2. ...
3. Observe the error

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include any error messages or unexpected responses.

## Environment

- OS:
- Go version (`go version`):
- Node version (`node --version`):
- Backend config (from startup log, redact credentials):
  ```
  {"level":"INFO","msg":"config loaded","server_port":...}
  ```

## Reproduction Case

If possible, include a `curl` command that reproduces the issue:

```bash
curl -X POST http://localhost:8080/api/v1/... \
  -H "Content-Type: application/json" \
  -d '...'
```

## Additional Context

Any other context, screenshots, or log output.
