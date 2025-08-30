FROM golang:latest AS builder

WORKDIR /app

# Install dependencies (using apt for Debian-based images)
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o api-gateway ./cmd

FROM alpine:3.18

WORKDIR /app

# Install CA certificates and curl for health checks (using apk for Alpine runtime)
RUN apk --no-cache add ca-certificates curl

# Copy built binary
COPY --from=builder /app/api-gateway .

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -u 1000 -G appuser -D appuser && \
    chown -R appuser:appuser /app

USER appuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Run the application
CMD ["./api-gateway"]