# Keycloak Warden

Keycloak Warden protects Keycloak by automatically blocking IP addresses after repeated failed login attempts.

It receives signed security events from [Keycloak Snitch](https://github.com/gi8lino/keycloak-snitch) and can enforce bans through **Cloudflare** or notify external systems using **webhooks**.

Manual IP bans are also supported through an authenticated API and CLI.

## Quick Start — Kubernetes

Warden runs alongside Keycloak in the same Kubernetes namespace, using a persistent SQLite database.

### 1. Configure Warden

Copy the example configuration:

```bash
cp examples/warden.yaml warden.yaml
```

Configure the detection rule and enable the destinations you want to use:

```yaml
rule:
  threshold: 5
  window: 1m
  ban: 15m

targets:
  edge:
    enabled: true
    provider: cloudflare
    zone-id: "YOUR_CLOUDFLARE_ZONE_ID"
    secret: "YOUR_CLOUDFLARE_API_TOKEN"
```

This blocks an IP for 15 minutes after five failed login attempts within one minute.

Without an enabled destination, Warden records decisions but does not enforce them externally.

### 2. Create Kubernetes Secrets

Generate two secrets:

```bash
# shared-secret
openssl rand -hex 32
# admin-token
openssl rand -hex 32
```

Save them in `warden.env`:

```dotenv
WARDEN__SNITCH_SECRET=<shared-secret>
WARDEN__ADMIN_TOKEN=<admin-token>
```

Create the Kubernetes Secrets in the existing Keycloak namespace:

```bash
kubectl -n keycloak create secret generic warden-config \
  --from-file=warden.yaml

kubectl -n keycloak create secret generic warden-credentials \
  --from-env-file=warden.env
```

The Snitch secret must be shared with Keycloak. The administrator token is used only for Warden's manual-ban API.

Keep these files private and do not commit them to Git.

### 3. Deploy Warden

This repository does not currently include Kubernetes manifests. Configure your Deployment and Service with:

- One Warden replica with persistent SQLite storage
- Application port `8080`
- Management port `8081` for health and readiness probes, and optional Prometheus metrics
- The configuration and credentials from Kubernetes Secrets

Check that Warden is running:

```bash
kubectl -n keycloak get pods
kubectl -n keycloak logs deployment/warden
```

## Connect Keycloak Snitch

Warden requires the [Keycloak Snitch](https://github.com/gi8lino/keycloak-snitch) event listener plugin.

1. Install the plugin in Keycloak.
2. Enable the **Snitch** event listener for your realm.
3. Enable the `LOGIN_ERROR` event type.
4. Configure the webhook URL and shared secret.

Add these settings to the Keycloak deployment:

```dotenv
KC_SPI_EVENTS_LISTENER__SNITCH__WEBHOOK_URL=http://warden:8080/events
KC_SPI_EVENTS_LISTENER__SNITCH__WEBHOOK_SECRET=<same-shared-secret-as-warden>
```

The URL uses Kubernetes service discovery because Keycloak and Warden run in the same namespace. The shared secret can be referenced from the same Kubernetes Secret.

Warden verifies event signatures before processing login failures.

## Manual Bans

Warden also supports manually blocking and unblocking IP addresses.

### Ban IP addresses

```bash
kubectl -n keycloak exec deployment/warden -- \
  /keycloak-warden ban 203.0.113.42 198.51.100.10 \
  --duration 1h \
  --reason "Suspicious activity"
```

### Unban IP addresses

```bash
kubectl -n keycloak exec deployment/warden -- \
  /keycloak-warden unban 203.0.113.42 198.51.100.10
```

The commands use the local Warden API and the configured `WARDEN__ADMIN_TOKEN`.

Both commands accept one or more IP addresses, deduplicate equivalent addresses, and report results per IP. Individual API failures do not stop other addresses from being processed; the command exits nonzero if any operation fails.

Unbanning an IP clears both manual and automatic ban sources and resets its failure count. New failed logins can trigger another automatic ban.

These commands require Kubernetes `pods/exec` permission.

## Output formats

Use the global `--output` flag with any command that produces a result. Available formats are `text` (default), `json`, and `yaml`. The flag also works after the command name.

```bash
warden ban 203.0.113.42 --duration 1h --reason "Incident" --output json
warden unban 203.0.113.42 --output yaml
warden list-active --database warden.db --output yaml
warden inspect <decision-id> --database warden.db --output json
```

`JSON` and `YAML` emit one structured document per command. Bulk ban/unban results include each requested IP's success status, returned ban details, and any error. The command still exits nonzero if an IP operation fails; stderr carries the human-readable error diagnostics. Text output prints successful operations and an aggregate summary. `list-active` includes automatic and manual ban sources.

## End-to-end testing

Run the [local Compose stack](examples/e2e/README.md) with a real Keycloak instance, Snitch release JAR, Warden, and a webhook receiver that prints request headers and JSON bodies to stdout:

```bash
make e2e-up
make e2e-logs
make e2e-test
make e2e-down
```

**For browser testing, open [the warden-e2e account console](http://127.0.0.1:18080/realms/warden-e2e/account/)** and try `demo` with a wrong password twice within one minute. The correct development password is `dev-password`. The demo user and Snitch listener belong to `warden-e2e`; logging into the master admin console will not send events to Warden. Receiver logs show ban/release webhooks, not each failed login.

In Compose, Warden uses application port **8080** (host **18081**, prefix `/warden`) and management port **8081** (host **18082**, no prefix). Keycloak is available on host port **18080**.

The Makefile downloads a pinned Snitch release automatically. `make e2e-test` resets **only the E2E Compose volume** and checks automatic banning, the signed webhook, unbanning, and the release webhook. No separate Snitch source checkout or Python smoke script is needed.

## Development

```bash
make download
make serve
make check
make build
```

Run `make help` for additional commands.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
