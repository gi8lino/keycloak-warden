# Keycloak Warden

**Protect your Keycloak services from repeated failed login attempts.**

Warden receives authenticated security events from [Keycloak Snitch](https://github.com/gi8lino/keycloak-snitch), detects repeated failed logins from the same IP address, and keeps the desired ban state synchronized with Cloudflare and/or HTTP webhook destinations.

```mermaid
flowchart LR
    A[Keycloak] --> B[Snitch]
    B --> C[Warden]
    C --> D[Cloudflare]
    C --> E[Webhook receiver]
```

## Why Warden?

- **Focused detection.** A configurable threshold and rolling time window, keyed by client IP.
- **Authenticated ingestion.** Snitch signs outbound events; Warden verifies the shared HMAC secret.
- **Durable decisions.** SQLite persists ban decisions, sources, and destination delivery acknowledgements.
- **Independent delivery.** Named Cloudflare zones and webhook endpoints each receive updates, with retries.
- **Operator control.** Ban and unban addresses via the CLI and authenticated application API.
- **Simple operations.** A single Go service, separate application and management listeners, health probes, and optional Prometheus metrics.

## Get started

1. [Run the local demo](getting-started.md) with Docker Compose and a real Keycloak instance.
2. [Configure a rule and destination](configuration.md) for your environment.
3. [Deploy Warden](deployment.md) and connect Keycloak Snitch.

For how reconciliation, expiration, and storage work, see [Architecture](architecture.md). For manual bans and diagnostics, see [CLI](cli.md), [API](api.md), and [Operations](operations.md).

[Browse the source on GitHub](https://github.com/gi8lino/keycloak-warden) · [Download a release](https://github.com/gi8lino/keycloak-warden/releases)
