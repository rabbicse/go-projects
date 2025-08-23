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
```

### go-fiber
```bash
go get github.com/gofiber/fiber/v2
go get github.com/gofiber/fiber/v2/middleware/limiter@v2.52.9
```

### go-dotenv 
```bash
go get github.com/joho/godotenv
go get -u gorm.io/driver/postgres
```

## Test the API
```bash
# Create short URL
curl -X POST http://localhost:8080/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Redirect
curl -L http://localhost:8080/abc123

# Health check
curl http://localhost:8080/health
```