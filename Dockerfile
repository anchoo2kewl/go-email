# Build stage
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git
WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o emaild ./cmd/emaild

# Runtime stage
FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata wget && \
    addgroup -g 1001 -S emaild && \
    adduser -u 1001 -S emaild -G emaild
WORKDIR /app
COPY --from=builder --chown=emaild:emaild /build/emaild .
USER emaild
EXPOSE 8095
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8095/health || exit 1
CMD ["./emaild"]
