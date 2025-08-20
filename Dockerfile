FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# Get build information
RUN BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) && \
    GIT_COMMIT=$(git rev-parse --short HEAD || echo "unknown") && \
    GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD || echo "unknown") && \
    GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "dev") && \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
    -X main.version=${GIT_TAG} \
    -X main.commit=${GIT_COMMIT} \
    -X main.date=${BUILD_DATE}" \
    -o booli-admin-api ./cmd/server

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata curl

RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app/booli-admin-api .

RUN mkdir -p /app/logs /app/tmp /app/configs && \
    chown -R appuser:appgroup /app

USER appuser

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

ENV GIN_MODE=release
ENV PORT=8081

CMD ["./booli-admin-api"]