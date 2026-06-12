# Contributing

Thank you for your interest in contributing to the Cinema Booking System.

---

## Getting Started

1. Fork the repository and clone your fork
2. Follow [docs/RUNNING_THE_APPLICATION.md](docs/RUNNING_THE_APPLICATION.md) to set up your environment
3. Create a branch: `git checkout -b feat/your-feature-name`
4. Make your changes
5. Run tests and lint before submitting
6. Open a pull request against `main`

---

## Development Setup

```bash
# Backend
cd backend
cp .env.example .env     # configure your local databases
make run                 # starts the backend

# Frontend
cd frontend
cp .env.local.example .env.local
npm install
npm run dev

# Databases (Docker required)
make dev-up              # Redis + MongoDB
```

---

## Before Submitting

### Backend

```bash
cd backend
make test-unit           # must pass
make lint                # must pass (requires golangci-lint)
make tidy                # go.sum must be clean
```

### Frontend

```bash
cd frontend
npm run type-check       # must pass with 0 errors
npm run build            # must succeed
```

---

## Commit Style

Use conventional commits:

```
feat: add JWT authentication middleware
fix: translate validator messages to user-friendly strings
perf: replace seat polling with Server-Sent Events
docs: add ADR for Redis Lua script choice
test: add integration test for concurrent hold
```

---

## Pull Request Guidelines

- Keep PRs focused: one feature or fix per PR
- Add tests for new functionality
- Update `CLAUDE.md` if you change commands, architecture, or config
- Update the relevant docs in `docs/` if behavior changes
- Do not modify `docs/RUNNING_THE_APPLICATION.md` unless you are changing the setup procedure

---

## Architecture Conventions

The project follows Clean Architecture with strict layer boundaries:

```
domain/        — Zero external dependencies. No new external imports.
application/   — Depends only on domain interfaces.
infrastructure/ — Implements domain interfaces.
interfaces/    — HTTP handlers only. No business logic.
```

Domain errors must be declared as typed sentinels in the domain layer. HTTP status mapping belongs in `interfaces/http/apierr/errors.go`. Business logic belongs in the application layer, not handlers.

---

## Reporting Security Issues

Do **not** open a public GitHub issue for security vulnerabilities. Email the maintainer directly with `[SECURITY]` in the subject line. Include steps to reproduce and potential impact.
