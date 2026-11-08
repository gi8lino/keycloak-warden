# Keycloak Warden

Warden watches for repeated failed logins from the same IP address. [Keycloak Snitch](https://github.com/gi8lino/keycloak-snitch) sends the login events. You choose how many failures trigger a ban, how long it lasts, and whether Warden blocks the IP through Cloudflare or sends a webhook.

```mermaid
flowchart TD
    subgraph K["Keycloak"]
        E["User events"] -->|Event Listener SPI| S["Snitch plugin"]
    end
    S -->|Signed HTTP POST /events| W["Warden"]
    W -->|Block or unblock an IP| C["Cloudflare"]
    W -->|Notify on ban or release| H["Webhook receiver"]
```

## Try it locally

From the repository root, start the Docker Compose demo and follow its logs:

```sh
make e2e-up
make e2e-logs
```

Open the [demo realm’s account console](http://127.0.0.1:18080/realms/warden-e2e/account/) and sign in as `demo` with a wrong password twice within one minute. Look for a webhook with `"active": true` in the receiver logs. The demo uses a local receiver, so you can try it without a Cloudflare account.

Press Ctrl+C to stop following the logs, then run `make e2e-down` to stop the stack. The [Compose guide](examples/e2e/README.md) includes the automated end-to-end test.

## Configuration

Warden reads detection rules and named targets from `warden.yaml`. Different targets may use different Cloudflare zone IDs and API tokens; each enabled target receives the same decision independently and retries failed delivery.

```yaml
rule:
  threshold: 5
  window: 1m
  ban: 15m

targets:
  edge-primary:
    enabled: true
    provider: cloudflare
    zone-id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    secret: env:CLOUDFLARE_PRIMARY_TOKEN
  edge-secondary:
    enabled: true
    provider: cloudflare
    zone-id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    secret: env:CLOUDFLARE_SECONDARY_TOKEN
```

The `secret` field accepts literal strings or [Resolver](https://github.com/containeroo/resolver) sources: `env:VARIABLE`, `file:/path/to/secret`, `json:`, `yaml:`, `ini:`, and `toml:` references. Use `literal:` if a literal secret starts with a source prefix (for example, `literal:env:not-a-reference`). Empty values, missing environment variables, and unrecognized source prefixes are rejected at startup for enabled targets. Values are resolved once at startup; restart after rotating credentials.

For Kubernetes, use a ConfigMap for the rules and destination definitions and Kubernetes Secrets for the credentials. See the Kubernetes example for an end-to-end configuration.

## Deploy on Kubernetes

Follow the [Kubernetes guide](examples/kubernetes/README.md) to connect Snitch to your realm, configure a destination, and deploy Warden.

## Check whether Cloudflare applied a ban

When the CLI prints `Banned`, Warden has recorded the decision. To confirm delivery, check the Warden logs:

```sh
kubectl -n keycloak logs deployment/keycloak-warden --since=10m
```

Look for `delivery_completed` with `active: true` for your Cloudflare destination and decision. If you see `delivery_failed`, the error explains why the attempt failed. Warden retries automatically.

To check in Cloudflare, open **Security → Security rules** for the configured zone. Under **IP access rules**, look for the blocked IP and the note `warden:<decision-id>`.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
