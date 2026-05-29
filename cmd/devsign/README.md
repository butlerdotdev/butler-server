# devsign

Dev-time helper that mints butler-server session JWTs for end-to-end testing
of the CLI device flow. Located in `cmd/devsign/` and built like any other
`cmd/` binary.

## What it is

A small CLI that signs a `UserSession` JWT using the same HS256 algorithm and
secret that butler-server's `SessionService` uses. The output is a valid
butler-server session token — `SessionMiddleware` accepts it as if it came
from a normal login.

## When to use it

For local E2E verification of changes that touch the CLI device-flow contract
(originally the `feat(auth): issue butler-session JWT from cli device flow`
change). The `POST /api/auth/cli/approve` step requires an authenticated
session; in a local dev server with no IdP wired up, devsign produces that
session out-of-band so you can drive the approval without a browser or a real
OIDC flow.

## Usage

```bash
CGO_ENABLED=0 go build -o /tmp/devsign ./cmd/devsign

# Mint an admin session JWT (24h default lifetime)
/tmp/devsign \
  -secret "$BUTLER_JWT_SECRET" \
  -email tester@example.com \
  -name "Tester" \
  -platform-admin

# Custom expiry
/tmp/devsign -secret ... -email ... -expiry 1h
```

Flags:

| Flag | Purpose |
|---|---|
| `-secret` | JWT signing secret. Must match `BUTLER_JWT_SECRET` of the running butler-server. Defaults to the env var of the same name. |
| `-email` | Email to embed in the session (required). |
| `-name` | Optional display name. |
| `-platform-admin` | Set `IsPlatformAdmin: true` on the session. |
| `-expiry` | Session lifetime (default 24h). |

The JWT is printed to stdout. Errors go to stderr with a non-zero exit.

## Not for production

This tool sidesteps every identity check (no IdP, no User CRD, no Team CRD
resolution) and trusts the caller to supply identity claims directly. The risk
model is plain: anyone with the running butler-server's `BUTLER_JWT_SECRET`
can mint a platform-admin session JWT with this tool. That secret is the only
gate.

Do not build, ship, or deploy devsign anywhere a production butler-server can
be reached. Treat `BUTLER_JWT_SECRET` accordingly: it is a session-issuance
secret, not a config knob.
