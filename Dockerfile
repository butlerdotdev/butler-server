# Butler Server - Multi-stage build
FROM golang:1.24-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

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

# Final stage - minimal runtime image
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# Copy the binary
COPY --from=builder /workspace/server .

# Run as non-root user
USER 65532:65532

# Expose API port
EXPOSE 8080

ENTRYPOINT ["/server"]
