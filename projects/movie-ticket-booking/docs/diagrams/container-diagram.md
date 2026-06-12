# Container Diagram (C4 Level 2)

```mermaid
C4Container
    title Cinema Booking System — Container Diagram

    Person(user, "Moviegoer")
    Person(admin, "Cinema Admin")

    Container_Boundary(frontend_bound, "Frontend") {
        Container(nextjs, "Next.js 15", "TypeScript, App Router", "Serves SSR pages. Proxies /api/v1/* to backend. Polls seat map every 2s.")
    }

    Container_Boundary(backend_bound, "Backend") {
        Container(gin, "Go / Gin", "Go 1.24", "REST API. Enforces booking invariants. Dispatches domain events.")
    }

    Container_Boundary(data_bound, "Data") {
        ContainerDb(redis, "Redis 7", "In-memory key-value", "Atomic seat locks via Lua NX scripts. TTL-based hold expiry.")
        ContainerDb(mongodb, "MongoDB 7", "Document database", "Persists bookings, movies, showtimes. Partial TTL index for auto-expiry.")
    }

    Container_Boundary(obs_bound, "Observability") {
        Container(prometheus, "Prometheus", "Time-series DB", "Scrapes /metrics from backend.")
        Container(grafana, "Grafana", "Dashboard", "Visualises Prometheus data.")
    }

    Rel(user, nextjs, "Uses", "HTTPS :3000")
    Rel(admin, nextjs, "Manages content", "HTTPS :3000")
    Rel(nextjs, gin, "Proxies API calls", "HTTP :8080")
    Rel(gin, redis, "Seat locks, sessions", "Redis protocol :6379")
    Rel(gin, mongodb, "Movies, bookings", "MongoDB wire protocol :27017")
    Rel(prometheus, gin, "Scrapes metrics", "HTTP GET /metrics")
    Rel(grafana, prometheus, "Queries", "PromQL")
```
