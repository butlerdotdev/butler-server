# Butler Server

Backend API server for Butler Console, providing REST APIs and WebSocket connections for Kubernetes multi-cluster management.

## Overview

Butler Server is a Go backend that:

- Authenticates users (JWT-based sessions)
- Proxies Kubernetes API requests (avoids CORS issues)
- Watches TenantCluster resources and broadcasts updates via WebSocket
- Provides terminal access to management and tenant clusters
- Serves the Butler Console static files

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       butler-server                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ Auth Layer  │  │ API Routes  │  │ WebSocket Hub           │  │
│  │ (JWT)       │  │ (chi)       │  │ (cluster watch, terminal)│  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    K8s Client (client-go)                    ││
│  └─────────────────────────────────────────────────────────────┘│
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
                   Kubernetes API Server
```

## API Endpoints

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Login with username/password |
| POST | `/api/auth/logout` | Invalidate session |
| POST | `/api/auth/refresh` | Refresh JWT token |
| GET | `/api/auth/me` | Get current user |

### Clusters

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/clusters` | List all tenant clusters |
| POST | `/api/clusters` | Create a tenant cluster |
| GET | `/api/clusters/{ns}/{name}` | Get cluster details |
| DELETE | `/api/clusters/{ns}/{name}` | Delete cluster |
| PATCH | `/api/clusters/{ns}/{name}/scale` | Scale cluster workers |
| GET | `/api/clusters/{ns}/{name}/kubeconfig` | Download kubeconfig |
| GET | `/api/clusters/{ns}/{name}/nodes` | Get cluster nodes |
| GET | `/api/clusters/{ns}/{name}/addons` | Get addon status |
| GET | `/api/clusters/{ns}/{name}/events` | Get cluster events |

### Example API Usage

```bash
# Login and get session cookie
curl -c cookies.txt -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# List clusters (using saved cookie)
curl -b cookies.txt http://localhost:8080/api/clusters

# Get cluster details
curl -b cookies.txt http://localhost:8080/api/clusters/butler-tenants/my-cluster

# Download kubeconfig
curl -b cookies.txt http://localhost:8080/api/clusters/butler-tenants/my-cluster/kubeconfig \
  -o my-cluster.kubeconfig

# Scale cluster workers
curl -b cookies.txt -X PATCH http://localhost:8080/api/clusters/butler-tenants/my-cluster/scale \
  -H "Content-Type: application/json" \
  -d '{"replicas": 5}'

# List providers
curl -b cookies.txt http://localhost:8080/api/providers
```

### Providers

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/providers` | List provider configs |
| GET | `/api/providers/{ns}/{name}` | Get provider details |
| POST | `/api/providers/{ns}/{name}/validate` | Validate provider connectivity |

### WebSocket

| Path | Description |
|------|-------------|
| `/ws/clusters` | Real-time cluster status updates |
| `/ws/terminal/{type}/{ns}/{cluster}` | Terminal session |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BUTLER_JWT_SECRET` | (required) | Secret for JWT signing |
| `BUTLER_ADMIN_USERNAME` | `admin` | Admin username |
| `BUTLER_ADMIN_PASSWORD` | (required) | Admin password |
| `BUTLER_TENANT_NAMESPACE` | `butler-tenants` | Tenant cluster namespace |
| `BUTLER_SYSTEM_NAMESPACE` | `butler-system` | System namespace |

## Development

### Prerequisites

- Go 1.24+
- Access to a Kubernetes cluster with Butler CRDs installed

### Run Locally

```bash
# With kubeconfig
make run

# Or manually
go run ./cmd/server -dev -kubeconfig ~/.kube/config
```

### Build

```bash
# Binary only
make build

# With console embedded
make build-all

# Docker image
make docker-build
```

### Test

```bash
make test
```

## Deployment

Butler Server runs in the management cluster alongside Butler controllers:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: butler-server
  namespace: butler-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: butler-server
  template:
    metadata:
      labels:
        app: butler-server
    spec:
      serviceAccountName: butler-server
      containers:
        - name: butler-server
          image: ghcr.io/butlerdotdev/butler-server:latest
          ports:
            - containerPort: 8080
          env:
            - name: BUTLER_JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: butler-server-config
                  key: jwt-secret
            - name: BUTLER_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: butler-server-config
                  key: admin-password
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
```

## License

Apache 2.0
