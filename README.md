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

Warden reads detection rules and provider-grouped, named targets from `warden.yaml`. Each configured target receives the same decision independently and retries failed delivery. To disable a target, remove it from the configuration after ensuring it no longer owns any active bans.

```yaml
rule:
  threshold: 5
  window: 1m
  ban: 15m

targets:
  webhook:
    edge:
      url: env:WEBHOOK_URL
      headers:
        Authorization: env:WEBHOOK_AUTHORIZATION
        X-Source: warden
        X-API-Key: file:/run/secrets/webhook-api-key

  cloudflare:
    primary:
      zone-id: env:CLOUDFLARE_PRIMARY_ZONE_ID
      api-token: env:CLOUDFLARE_PRIMARY_TOKEN
    secondary:
      zone-id: env:CLOUDFLARE_SECONDARY_ZONE_ID
      api-token: env:CLOUDFLARE_SECONDARY_TOKEN
```

The example creates three independent destinations: `webhook.edge`, `cloudflare.primary`, and `cloudflare.secondary`. Provider-qualified names are used in delivery records, logs, and metrics.

Cloudflare targets require `zone-id` and `api-token` (the zone ID must resolve to 32 hexadecimal characters). Webhook targets require `url`; `headers` are optional. Header names are literal HTTP field names; each value and the URL can use a resolver. Header values must not be blank or contain invalid HTTP control characters. Transport-managed headers such as `Host`, `Content-Length`, and `Content-Type` are not configurable; Warden sends JSON with `Content-Type: application/json`. Webhooks have no built-in signing: configure an `Authorization` or API-key header if required by the receiver.

All `url`, `headers` values, `zone-id`, and `api-token` entries accept literal values or [Resolver](https://github.com/containeroo/resolver) sources including `env:VARIABLE` and `file:/path/to/value`. Use `literal:` to escape a special prefix (for example, `literal:env:not-a-reference`). Missing or blank values and unrecognized references cause startup to fail. Values are resolved once at startup; restart Warden after rotating them.

Warden requires HTTPS webhook endpoints, except HTTP on explicit loopback hosts (`localhost`, `127.0.0.1`, or `::1`). Redirects are not followed. **Inbound events from Snitch are still authenticated with HMAC signatures**; the optional webhook headers apply only to outbound notifications.

The YAML parser rejects unknown fields, including the removed flat target format, `provider`, `enabled`, and `signing-secret`. There is no compatibility mode.

For Kubernetes, use a ConfigMap for the rules and destination definitions and Kubernetes Secrets for credentials. See the Kubernetes example for an end-to-end configuration.

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
