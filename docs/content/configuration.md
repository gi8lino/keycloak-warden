# Configuration

Warden separates **security policy and destinations** (YAML) from **runtime settings and secrets** (flags or environment variables).

## Detection rule and destinations

Create `warden.yaml`:

```yaml
rule:
  threshold: 5
  window: 1m
  ban: 15m

targets:
  cloudflare:
    edge:
      zone-id: env:CLOUDFLARE_ZONE_ID
      api-token: env:CLOUDFLARE_API_TOKEN
  webhook:
    notifications:
      url: env:WARDEN_WEBHOOK_URL
      headers:
        Authorization: env:WARDEN_WEBHOOK_AUTHORIZATION
        X-Source: warden
    slack:
      url: env:SLACK_WEBHOOK_URL
      body-template: file:/config/templates/slack.json.tmpl
```

{code highlight="2-4,8-9,11-19" note="2:Number of failed logins needed to trigger a ban." note="3:Rolling detection window, counted per client IP." note="4:Duration of an automatic ban." note="8-9:Cloudflare credentials resolve from the environment." note="11-19:Named webhook destinations with optional headers and body templates." reference-position="right" reference-color="blue" line-numbers="true"}

**At least one destination is required.** Each destination independently reconciles the same desired decision. Names appear as `cloudflare.edge` and `webhook.notifications` in delivery records and logs.

### Templated webhook bodies

`body-template` is optional for each webhook target. Without it, Warden sends its original decision JSON unchanged. With it, Warden resolves the **template contents** at startup (`file:`, `env:`, or `literal:`), compiles them with [Notifykit text templates](https://github.com/containeroo/notifykit), and renders JSON separately for each desired decision. Restart Warden to reload template files.

For example, `/config/templates/slack.json.tmpl` (a complete example is included at `examples/templates/slack.json.tmpl`):

```json
{"text": {{ if eq .State "banned" }}{{ json (printf "Warden blocked %s (revision %d)" .IP .Revision) }}{{ else }}{{ json (printf "Warden released %s" .IP) }}{{ end }}}
```

The template context is the existing decision with fields `.ID`, `.Revision`, `.IP`, `.State`, and `.ExpiresAt`. Use the `json` helper for all dynamic strings to ensure correct escaping. Rendered bodies must be valid JSON and cannot exceed 64 KiB. Warden checks both `banned` and `unbanned` outputs at startup; later rendering errors are reported as delivery failures and retried by the existing worker.

Slack incoming webhooks accept JSON objects containing `text`. The `examples/templates/teams.json.tmpl` sample emits an Adaptive Card message envelope; check that it matches the input format of your selected Microsoft Teams Workflow trigger. Notification receivers may see duplicate messages when a response is lost and Warden retries—Warden continues to acknowledge revisions only on HTTP 2xx.

### Webhook response validation (optional)

By default, webhook destinations acknowledge **any HTTP 2xx** response without reading or matching its body. This is unchanged. A `response` section opts a single webhook into Notifykit's response rules. Warden parses the YAML, while [Notifykit's `response` package](https://github.com/containeroo/notifykit/tree/main/response) evaluates the HTTP status and response body.

For Slack's `chat.postMessage` API (Bot OAuth token), a successful HTTP 200 alone is insufficient: Slack may return `{"ok":false}`. Configure:

```yaml
webhook:
  slack-bot:
    url: https://slack.com/api/chat.postMessage
    headers:
      Authorization: env:SLACK_AUTHORIZATION
    body-template: file:/config/templates/slack-bot.json.tmpl
    response:
      json:
        pointer: /ok
        equals: true
        error-pointer: /error
```

Place `webhook` under the existing `targets` mapping. Set `SLACK_AUTHORIZATION` to the complete `Bearer xoxb-...` header value, and include a `channel` field in the bot request body template. Incoming Slack webhooks continue working without response validation or an Authorization header.

A response such as `{"ok":false,"error":"channel_not_found"}` is rejected, and Warden logs the extracted `channel_not_found` error under its existing `delivery_failed` event. Only the configured error value is exposed; Notifykit sanitizes and truncates it. Other response fields are not logged.

For other HTTP APIs, an accepted status range and a plain-text matcher can be configured together or separately:

```yaml
response:
  status-codes: "200-204,207"
  text:
    equals: "ok"
```

Use `text.contains` instead of `text.equals` for substring matching. A text matcher intentionally allows the response text to appear as a truncated, sanitized failure detail. JSON also supports nested pointers (for example `/result/delivery/accepted`) and array indices (for example `/results/0/status`):

```yaml
response:
  json:
    pointer: /result/delivery/accepted
    equals: true
    error-pointer: /error/details/message
```

Rules follow these conditions:

- `status-codes` accepts comma-separated HTTP codes and inclusive ranges; when omitted, the default is 200–299. An explicit list overrides this default, so `status-codes: "202"` rejects HTTP 200.
- `text` and `json` are mutually exclusive. Text must specify exactly one of `equals` or `contains`.
- `json.equals` is required when `json` is configured. JSON values retain their types: YAML `true`, `"true"`, and `null` are different expectations. Missing pointer values and invalid JSON fail validation.
- Invalid rules fail startup. Response bodies are read only for body matchers and are limited to **64 KiB**. Large bodies fail delivery rather than being partially matched.
- Failed validation is retried by Warden's existing durable action worker, just like HTTP status failures. No new database or retry configuration is required.

## Secrets and value resolution

Warden resolves destination values once on startup using [Resolver](https://github.com/containeroo/resolver). Use `env:NAME`, `file:/path/to/secret`, or a literal value. `literal:` escapes a value that would otherwise look like a resolver reference.

For webhook targets, **HTTPS is required** except when explicitly addressing loopback hosts such as `localhost` or `127.0.0.1`. Redirects are not followed. The `Content-Type` header is reserved; Warden sends JSON with `application/json`. Webhooks have no built-in outbound signing, so supply an authentication header if needed. Templates should be treated as trusted configuration, not user-supplied content.

Inbound requests from Snitch are separately protected by the `--snitch-secret` HMAC key. **Never expose this secret in the public documentation or commit it to the repository.**

## Runtime flags

Run Warden with:

```sh
warden serve \
  --config=warden.yaml \
  --database=/data/warden.db \
  --listen-address=:8080 \
  --management-listen-address=:8081 \
  --snitch-secret="$SNITCH_SECRET" \
  --admin-token="$WARDEN_ADMIN_TOKEN" \
  --metrics \
  --prune-interval=1h \
  --optimize-interval=24h
```

{code highlight="4-7,9-10" note="4-5:Separate listeners for ingestion and management endpoints." note="6:Required shared HMAC secret for incoming Snitch events." note="7:Optional bearer token enabling the manual-ban HTTP API." note="9-10:Independent pruning and optimization schedules; neither changes data retention." reference-position="right" reference-color="blue" line-numbers="true"}

| Flag                          | Default          | Purpose                                           |
| ----------------------------- | ---------------- | ------------------------------------------------- |
| `--config`                    | `warden.yaml`    | YAML rules and destinations                       |
| `--database`                  | `warden.db`      | SQLite database path                              |
| `--snitch-secret`             | Required         | Shared Snitch HMAC key                            |
| `--admin-token`               | Empty            | Enables authenticated administrative API when set |
| `--listen-address`            | `127.0.0.1:8080` | Application listener                              |
| `--management-listen-address` | `127.0.0.1:8081` | Health and metrics listener                       |
| `--route-prefix`              | Empty            | Prefix for application routes                     |
| `--metrics`                   | Off              | Prometheus exposition and instrumentation         |
| `--access-log`                | Off              | HTTP access logs                                  |
| `--debug`                     | Off              | Diagnostic logging                                |
| `--log-format`                | `json`           | `json` or `text`                                  |
| `--prune-interval`            | `1h`             | Observation cleanup frequency                     |
| `--optimize-interval`         | `24h`            | SQLite query-planner optimization frequency       |

Flags can also be configured through `WARDEN__<FLAG_NAME>` environment variables, replacing hyphens with underscores. For example, `WARDEN__SNITCH_SECRET` and `WARDEN__OPTIMIZE_INTERVAL`.

The two maintenance intervals must be between `5m` and `8760h`. Intervals determine how frequently maintenance runs, **not** the observation retention duration.

Consult `warden serve --help` for the definitive list of supported flags for your installed release.
