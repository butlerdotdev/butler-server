# Contributing to Butler Server

Thank you for your interest in contributing to Butler Server!

## Development Setup

### Prerequisites

- Go 1.24+
- Docker
- Access to a Kubernetes cluster with Butler CRDs installed
- `make`

### Building

```bash
# Build binary
make build

# Build with console embedded
make build-all

# Build container image
make docker-build
```

### Running Locally

```bash
# Start the server with your local kubeconfig
make run

# Or manually with dev mode
go run ./cmd/server -dev -kubeconfig ~/.kube/config
```

### Running Tests

```bash
make test
```

### Linting

```bash
make lint
```

## Code Guidelines

### Project Structure

- `cmd/server/` - Entry point
- `internal/api/handlers/` - HTTP handlers (one file per resource type)
- `internal/api/router.go` - Route definitions
- `internal/auth/` - Authentication and authorization
- `internal/k8s/` - Kubernetes client wrapper
- `internal/websocket/` - WebSocket hub and terminal proxy

### Adding a New API Endpoint

1. Create or update the handler file in `internal/api/handlers/`
2. Add route(s) in `internal/api/router.go`
3. Add any required RBAC permissions to the Helm chart
4. Update the README.md API endpoint table
5. Write tests

### Handler Pattern

All handlers follow this pattern:

```go
func (h *Handler) GetResource(w http.ResponseWriter, r *http.Request) {
    // 1. Extract path params
    name := chi.URLParam(r, "name")

    // 2. Get user context
    user := auth.UserFromContext(r.Context())

    // 3. Check authorization
    if !user.HasAccessToTeam(teamName) {
        helpers.WriteError(w, http.StatusForbidden, "access denied")
        return
    }

    // 4. Perform K8s operations
    result, err := h.client.Get(ctx, name, namespace)
    if err != nil {
        helpers.WriteError(w, http.StatusInternalServerError, err.Error())
        return
    }

    // 5. Return JSON response
    helpers.WriteJSON(w, http.StatusOK, result)
}
```

### Error Responses

Always return structured JSON errors:

```json
{"error": "descriptive error message"}
```

Use appropriate HTTP status codes:
- `400` - Bad request (invalid input)
- `401` - Unauthorized (no valid session)
- `403` - Forbidden (valid session, insufficient permissions)
- `404` - Not found
- `409` - Conflict (resource already exists)
- `500` - Internal server error

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run tests and linting: `make test && make lint`
5. Commit with conventional commit messages
6. Push to your fork and open a PR

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(auth): add OIDC group claim mapping`
- `fix(clusters): handle missing kubeconfig gracefully`
- `docs: update API endpoint documentation`

## Developer Certificate of Origin

By contributing to this project, you agree to the Developer Certificate of Origin (DCO). This means you certify that you wrote the contribution or have the right to submit it under the project's license.

Sign off your commits with `git commit -s` or add `Signed-off-by: Your Name <your.email@example.com>` to your commit messages.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
