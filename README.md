# Bastion Gateway

Default-deny firewall for AI agents. Apache-2.0.

Your agents can delete, spend, email, and leak — at machine speed. Bastion Gateway sits in front of them: it allows what you permit, blocks what you don't, redacts secrets on the way out, holds risky actions for approval, and signs a record of everything.

## Run

```bash
docker run -p 8080:8080 \
  -v ./policy.yaml:/policy.yaml:ro \
  ghcr.io/vystartasv/bastion-gateway
```

Point your agent's `base_url` at `http://localhost:8080`. That's the only change.

## Policy

```yaml
default: deny

redact:
  - type: builtin
    name: bearer
  - type: builtin
    name: jwt
  - type: builtin
    name: email

agents:
  researcher:
    allow:
      - GET api.internal/search
      - GET api.internal/documents/*
    hold:
      - POST api.internal/orders/*
      - DELETE *
```

## What it does

1. **Allowlist** — name the tools and endpoints each agent may touch. Everything else denied by default.
2. **Redaction** — secrets and personal data stripped from outbound calls before they leave your network.
3. **Risk gate** — destructive actions (deletes, spend, sends) held for human approval.
4. **Signed audit log** — every call becomes a signed, immutable record. Exportable as compliance evidence.

## Approvals

Held requests wait in `/var/bastion/approvals/`. Approve or deny via CLI:

```bash
bastion list                    # view pending requests
bastion approve <request-id>    # approve and forward
bastion deny <request-id>       # deny and discard
```

## Audit

```bash
bastion export                  # export all signed audit records
bastion genkey                  # generate a signing key
```

## What it talks to

Nothing. Only the traffic you route through it. No telemetry, no phone-home, no account.

## Build

```bash
docker build -t bastion-gateway .
```

## Tests

```bash
go test ./...
```
