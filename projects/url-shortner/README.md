# URL Shortner

## Prerequisites
- go 1.24+
- redis
- postgres
- docker

## go packages to install
- Redis Client for go [link](https://github.com/redis/go-redis)
- GORM - ORM library for Golang [link](https://gorm.io/)
- Fiber framework [link](https://gofiber.io/)
- GoDotEnv [link](https://pkg.go.dev/github.com/joho/godotenv)

## Installation

### go-redis

```bash
go get github.com/redis/go-redis/v9
```

### gorm
```bash
go get -u gorm.io/gorm
go get -u gorm.io/driver/postgres
```

### go-fiber
```bash
go get github.com/gofiber/fiber/v2
go get github.com/gofiber/fiber/v2/middleware/limiter@v2.52.9
```

### go-dotenv 
```bash
go get github.com/joho/godotenv
```

### .env for local development side
```bash
SERVER_PORT=3000
SERVER_BASE_URL=http://localhost:3000

REDIS_HOST=localhost
REDIS_PORT=6379

POSTGRES_HOST=localhost
POSTGRES_PORT=5444
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DBNAME=url_shortner
POSTGRES_SSLMODE=disable
```

## Run Service
```bash
godotenv -f .env go run ./cmd/serve
```

## Test the API
```bash
# Create short URL
curl -X POST http://localhost:3000/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Redirect
curl -L http://localhost:3000/abc123

# Health check
curl http://localhost:3000/health
```

## References
- [bytebytego](https://bytebytego.com/courses/system-design-interview/design-a-url-shortener)
- [systemdesignschool](https://systemdesignschool.io/problems/url-shortener/solution)