# Butler Server - Multi-stage build
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /workspace

# Install build dependencies
RUN apk add --no-cache git

# Copy butler-api first (for local replace directive)
COPY --from=butler-api . /butler-api

# Copy go mod files for dependency caching
COPY go.mod go.sum ./

# Update replace directive to point to copied butler-api
RUN go mod edit -replace github.com/butlerdotdev/butler-api=/butler-api

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the server binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -a -ldflags="-s -w" -o server ./cmd/server

# Final stage - alpine for shell + kubectl support
FROM alpine:3.21
ARG TARGETARCH

# Install bash, kubectl, and ca-certs
RUN apk add --no-cache bash curl ca-certificates && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${TARGETARCH}/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/ && \
    rm -rf /var/cache/apk/*

WORKDIR /app

# Copy the binary
COPY --from=builder /workspace/server .

# Create non-root user matching distroless nonroot uid
RUN adduser -D -u 65532 -g 65532 butler
USER 65532:65532

# Expose API port
EXPOSE 8080

ENTRYPOINT ["/app/server"]
