# Recruiter Overview

## Cinema Booking System — Quick Reference

---

## What Is This Project?

A full-stack online cinema ticket booking platform. Users browse movies, select showtimes, choose seats in real time, hold them for 10 minutes, and confirm their booking. Multiple users can compete for the same seats simultaneously — the system guarantees no seat is ever double-booked.

---

## Why It's Technically Impressive

Most booking systems have a race condition: two users select the same seat at the same time, and the system allows both holds. This project solves that problem correctly using atomic Redis operations that either lock all requested seats or lock none — in a single database round trip.

This is the same engineering challenge faced by Ticketmaster, United Airlines seat selection, and concert ticket platforms.

---

## Quick Facts

| Item | Detail |
|---|---|
| Language | Go (backend), TypeScript/Next.js (frontend) |
| Architecture | Clean Architecture + Domain-Driven Design |
| Databases | Redis (seat locking), MongoDB (booking records) |
| Deployment | Docker Compose (full stack), Prometheus + Grafana monitoring |
| Lines of Go code | ~3,500 (backend) |
| Lines of TypeScript | ~1,200 (frontend) |
| Test coverage | Unit + integration + load tests (k6) |
| Build time | < 5 seconds |
| Startup time | < 1 second |

---

## Skills Demonstrated

**Go / Backend Engineering**
- Goroutine-safe concurrent request handling
- Redis Lua scripting for atomic distributed locks
- MongoDB aggregation and index optimization
- Graceful HTTP server shutdown
- Structured logging (`log/slog`)
- Prometheus metrics instrumentation

**Software Architecture**
- Clean Architecture (4-layer, strict dependency inversion)
- Domain-Driven Design (aggregates, value objects, domain events, bounded contexts)
- CQRS (implicit command/query separation)
- Compensating transactions for distributed consistency

**Frontend / Full Stack**
- Next.js 15 App Router (server components + client components)
- TypeScript with strict type checking
- Real-time UI with 2-second polling
- Error handling with typed `ApiError` class

**DevOps / Infrastructure**
- Docker multi-stage builds
- Docker Compose with health-checked service dependencies
- Prometheus + Grafana observability stack
- Non-root container security
- testcontainers-go for integration tests

---

## Position Fit

| Role | Relevance |
|---|---|
| **Backend Engineer (Go)** | Primary fit — idiomatic Go, clean architecture, Redis/MongoDB |
| **Senior Software Engineer** | Full stack, architecture decisions, DDD patterns |
| **Platform / Infra Engineer** | Docker, Compose, Prometheus, observability |
| **Staff Engineer** | Architecture review docs, scalability analysis, engineering tradeoffs |
| **Solutions Architect** | System design documentation, C4 diagrams, ADRs |

---

## Links

- Source code: this repository
- API documentation: `http://localhost:8080/api/v1/docs` (when running)
- Architecture walkthrough: [docs/SYSTEM_DESIGN_WALKTHROUGH.md](SYSTEM_DESIGN_WALKTHROUGH.md)
- Staff Engineer review: [docs/STAFF_ENGINEER_REVIEW.md](STAFF_ENGINEER_REVIEW.md)
- Interview guide: [docs/INTERVIEW_GUIDE.md](INTERVIEW_GUIDE.md)
