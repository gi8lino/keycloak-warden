# Configuration

Warden separates **security policy and destinations** (YAML) from **runtime settings and secrets** (flags or environment variables).

## Detection rules and destinations

Create `warden.yaml`:

```yaml
rules:
  brute-force:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 5
      window: 1m
    actions:
      ban: 15m
      notify: [slack-security]

enforcements:
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

notifications:
  webhook:
    slack-security:
      url: env:SLACK_WEBHOOK_URL
      body-template: file:/config/templates/incident-slack-api.json.tmpl
    msteams-administrators:
      url: env:MSTEAMS_WEBHOOK_URL
      body-template: file:/config/templates/incident-msteams.json.tmpl
```

**Destination names** must be at most 128 bytes and cannot contain whitespace or control characters.

At least one enforcement destination is required when a rule requests a ban, unless observe-only mode is enabled. Monitoring-only deployments may omit enforcements; manual bans are then unavailable. Each destination independently reconciles the same desired decision. Names appear as `cloudflare.edge` and `webhook.notifications` in delivery records and logs.

Destination identity is bound while a target has active bans or unacknowledged revisions. Changing a Cloudflare zone or webhook URL or resolved template variables requires reconciling outstanding obligations first. Credentials can rotate independently. Custom webhook routing changes through headers or receiver behavior remain the operator’s responsibility.

## Named detection rules

Configure one to 64 named rules under `rules`. Each rule selects user or administrative events, counts matching events or distinct identities within a sliding window, and records incidents or requests an IP ban.

See [Detection rules](detection-rules.md) for the complete field reference, supported aggregation combinations, enforcement restrictions, Snitch settings and practical examples.

## Incident notification destinations

The top-level `enforcements` and `notifications` sections configure separate delivery workflows. Enforcement destinations receive desired ban/unban revisions globally. Notifications send immutable incident occurrences only to the destinations selected by `actions.notify`. Both webhook maps share the same settings and transport. Every notification reference must match a name in `notifications.webhook`; duplicates are rejected.

```yaml
notifications:
  max-attempts: 3
  retry-initial-delay: 10s
  retry-max-delay: 5m
  webhook:
    slack-security:
      url: env:SLACK_SECURITY_WEBHOOK_URL
      body-template: file:/config/templates/incident-slack-api.json.tmpl
    slack-operations:
      url: env:SLACK_OPERATIONS_WEBHOOK_URL
      body-template: file:/config/templates/incident-slack-api.json.tmpl
    msteams-administrators:
      url: env:MSTEAMS_ADMIN_WEBHOOK_URL
      body-template: file:/config/templates/incident-msteams.json.tmpl
    siem:
      url: env:SIEM_WEBHOOK_URL
      headers:
        Authorization: env:SIEM_AUTHORIZATION
```

Without `body-template`, notification webhooks send the canonical incident JSON described in [API](api.md). The same `url`, `headers`, `body-template`, `template-vars`, `response`, and `max-attempts` fields apply to enforcement webhooks. Templates expose the typed payload under `.Payload` and resolved variables under `.Vars`. For Slack or Teams, use one of the six templates in `deploy/kubernetes/templates/`; use the incident variants for notification webhooks and the ban variants for enforcement webhooks. Slack Bot API needs a channel template variable and a response rule requiring `/ok` to equal `true`. Teams ban templates use MessageCard; incident templates use an Adaptive Card envelope. Verify endpoint format compatibility.

The notification worker persists retries separately from enforcement, using the shared YAML delivery settings above (defaults shown). Each destination is processed in occurrence order; a delayed retry does not prevent another destination from becoming eligible. Jobs are queued atomically with incidents, survive restart and retain their snapshot even when the incident itself is pruned. Completed and exhausted jobs are pruned according to `--incident-retention`, measured from completion. Exhausted jobs remain terminal unless explicitly retried through the administrative API; changing attempt limits does not automatically replay them. A retry preserves prior attempts and requires the original destination identity. Delivery is at-least-once until acknowledged or exhausted: receivers may see duplicates after an ambiguous network result or interrupted shutdown.

Observe-only mode still sends notifications. A notification describes an incident and any requested or hypothetical ban, not proof that enforcement succeeded. Manual bans, unbans and ban renewals do not produce incident notifications. Removing or changing a notification destination's endpoint or template routing variables is blocked while it owns pending jobs. Remove the rule reference first, allow the queue to drain, then remove the destination. Credential rotation is independent; template content and header-based routing changes remain the operator's responsibility.

Existing incidents are not retroactively notified. Release and reconcile outstanding enforcement obligations before removing or reassigning destinations.

## Webhook destinations

### Templated webhook bodies

Each enforcement destination gets **3 total attempts per decision revision** by default, including the first delivery. Set `enforcements.max-attempts` to change the shared limit, or set `max-attempts` on an individual webhook or Cloudflare destination. Limits must be positive integers. For example:

```yaml
enforcements:
  max-attempts: 4
  webhook:
    firewall:
      url: env:FIREWALL_WEBHOOK_URL
      max-attempts: 2
      headers:
        Authorization: env:FIREWALL_AUTHORIZATION
      body-template: file:/config/templates/firewall.json.tmpl
```

After the last failure, `inspect` shows `exhausted` and the worker stops retrying that delivery. A new revision has its own budget. Restarting preserves completed attempts. Raising the limit and restarting makes an exhausted **current** revision eligible again. An exhausted release means the destination has not acknowledged the unban. Retry limits belong to the runtime targets, not the database; SQLite stores only per-destination delivery history and state.

`body-template` is optional for each webhook target. Without it, Warden sends the decision or incident JSON according to the configured section. With it, Warden resolves the **template contents** at startup (`file:`, `env:`, or `literal:`), compiles them with [Notifykit text templates](https://github.com/containeroo/notifykit), and renders JSON separately for each delivered payload. Restart Warden to reload template files.

For example, `/config/templates/firewall.json.tmpl`:

```json
{"address": {{ .Payload.IP | json }}, "state": {{ .Payload.State | json }}, "revision": {{ .Payload.Revision }}}
```

A webhook can declare `template-vars` as a map of names to string values. Warden resolves them at startup using the destination resolver, including `env:`, `file:`, and `literal:` references. Reference them as `.Vars.name` in the template and use the `json` helper when rendering strings. Missing environment references fail startup.

Decision templates use `.Payload.ID`, `.Payload.Revision`, `.Payload.IP`, `.Payload.State`, and `.Payload.ExpiresAt`. Incident templates use `.Payload.Rule`, `.Payload.EventKind`, `.Payload.EventType`, `.Payload.Count`, `.Payload.Threshold`, `.Payload.BanUntil`, and the other incident fields. Use the `json` helper for all dynamic strings to ensure correct escaping. Rendered bodies must be valid JSON and cannot exceed 64 KiB. Warden checks both `banned` and `unbanned` outputs and representative user/admin incidents at startup; later rendering errors are reported as delivery failures and retried by the existing worker.

### Webhook response validation (optional)

By default, webhook destinations acknowledge **any HTTP 2xx** response without reading its body. A `response` section opts a single webhook into Notifykit's response rules. Warden parses the YAML, while [Notifykit's `response` package](https://github.com/containeroo/notifykit/tree/main/response) evaluates the HTTP status and response body.

An accepted status range and a plain-text matcher can be configured together or separately:

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
- Response validation failures follow the same retry policy as HTTP status failures.

## Secrets and value resolution

Warden resolves destination values once on startup using [Resolver](https://github.com/containeroo/resolver). Use `env:NAME`, `secret:/path/to/mounted-secret`, `file:/path/to/value`, or a literal value. `literal:` escapes a value that would otherwise look like a resolver reference.

Use `secret:` for mounted Kubernetes or Docker secret files. It removes trailing CR/LF while preserving spaces and tabs; no Kubernetes API access is needed. `file:` uses Resolver’s default behavior, trimming surrounding whitespace. Replace existing `file:` secret references with `secret:` if their surrounding spaces must be preserved. Restart Warden after changing a mounted secret.

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
  --prune-interval=24h \
  --optimize-interval=24h \
  --incident-retention=720h
```

{code highlight="4-7,9-11" note="4-5:Separate listeners for ingestion and management endpoints." note="6:Required shared HMAC secret for incoming Snitch events." note="7:Optional bearer token enabling the manual-ban HTTP API." note="9-10:Independent pruning and optimization schedules." note="11:Incident and terminal notification retention." reference-position="right" reference-color="blue" line-numbers="true"}

| Flag                          | Default          | Purpose                                           |
| ----------------------------- | ---------------- | ------------------------------------------------- |
| `--config`                    | `warden.yaml`    | YAML rules and destinations                       |
| `--database`                  | `warden.db`      | SQLite database path                              |
| `--snitch-secret`             | Required         | Shared Snitch HMAC key                            |
| `--admin-token`               | Empty            | Enables authenticated administrative API when set |
| `--listen-address`            | `127.0.0.1:8080` | Application listener                              |
| `--management-listen-address` | `127.0.0.1:8081` | Health and metrics listener                       |
| `--route-prefix`              | Empty            | Prefix for application routes                     |
| `--observe-only`              | Off              | Record hypothetical bans without enforcement      |
| `--metrics`                   | Off              | Prometheus exposition and instrumentation         |
| `--access-log`                | Off              | HTTP access logs                                  |
| `--debug`                     | Off              | Diagnostic logging                                |
| `--log-format`                | `json`           | `json` or `text`                                  |
| `--prune-interval`            | `24h`            | Database pruning frequency                        |
| `--optimize-interval`         | `24h`            | SQLite query-planner optimization frequency       |
| `--incident-retention`        | `720h`           | Incident and terminal notification retention      |

Flags can also be configured through `WARDEN__<FLAG_NAME>` environment variables, replacing hyphens with underscores. For example, `WARDEN__SNITCH_SECRET` and `WARDEN__OPTIMIZE_INTERVAL`.

Listener addresses are parsed as TCP addresses, including when an explicit administrative URL is supplied. Blank addresses and the ambiguous wildcard `:0` are rejected; use an explicit IP such as `127.0.0.1:0` or `[::]:0` for an automatically allocated port.

Each of `enforcements` and `notifications` independently accepts `retry-initial-delay` (default `10s`) and `retry-max-delay` (default `5m`) in YAML. Omitted or zero values use the defaults. Effective delays must be positive whole milliseconds, with maximum at least initial. Equal values give a constant pause. Enforcement backs off per destination; notification retries retain their own persisted state. Changing settings requires a restart and affects future calculated delays, not already persisted deadlines. Each section also has an independent `max-attempts` default of 3.

The two maintenance intervals must be between `5m` and `8760h`. Intervals determine how frequently maintenance runs, **not** how long records are retained. `--incident-retention` (`WARDEN__INCIDENT_RETENTION`) accepts `24h` through `8760h` and defaults to `720h` (30 days). It controls incident history and completed or exhausted notification deliveries, measured from incident recording or delivery completion respectively. Pending notification deliveries are preserved. Counting observations retain at least 24 hours or the longest detection window, whichever is longer. Remove any old `incident-retention` YAML key; it is no longer supported. Lowering the retention can permanently delete history during startup pruning or subsequent maintenance.

Administrative CLI commands (`ban`, `unban`, `list-active`, `inspect`, and `maintenance` subcommands) also accept `--request-timeout` (default `10s`), `--maintenance-timeout` (default `35s`), and `--max-response-bytes` (default `1048576`). These flags configure only the outgoing administrative HTTP client, not Warden's server request limits or outbound webhook destinations. Their corresponding environment variables are `WARDEN__REQUEST_TIMEOUT`, `WARDEN__MAINTENANCE_TIMEOUT`, and `WARDEN__MAX_RESPONSE_BYTES`. Both timeouts must be positive; the response limit must also be less than `MaxInt64`.

Consult `warden serve --help` for the definitive list of supported flags for your installed release.

## Protected addresses

`protected-ips` is an optional top-level YAML setting:

```yaml
protected-ips:
  - 192.0.2.10
  - 198.51.100.0/24
  - 2001:db8:1234::/48
```

Protected addresses are matched after canonicalization, including IPv4-mapped IPv6. Matching events from protected addresses are excluded from ban rules. If no monitoring-only rule matches, they are not persisted and produce a `protected` debug outcome. Monitoring-only rules may still record incidents; those observations remain ineligible for future bans even if protection is removed. HTTP ingestion metrics still count successfully processed events. Existing failure observations are not deleted when protection is enabled; they age out under the usual window and retention policies. Manual bans return HTTP 409. Invalid IPs/CIDRs fail startup. Protection does not silently release existing bans: release affected active bans and reconcile their deliveries before adding protection. Unban operations are never blocked by the protected-address policy.

## Observe-only mode

Enable the runtime mode using the serve flag or its environment variable:

```sh
warden serve --observe-only
```

```sh
WARDEN__OBSERVE_ONLY=true warden serve
```

In Kubernetes, set `WARDEN__OBSERVE_ONLY` to `"true"` in the Warden container environment. The mode defaults to off; restart Warden with the flag omitted and the environment variable unset (or use `--observe-only=false`) to resume enforcement. `observe-only` is a runtime flag, not a YAML key.

Observe-only mode allows Warden to evaluate all configured detection rules without creating ban sources, enforcement decisions, or delivery jobs. Manual bans are rejected with HTTP 409. Targets may be omitted; configured enforcement structures are still validated, but enforcement credentials are not resolved and enforcement providers are not constructed. Notifications remain enabled and their credentials are resolved. Warden refuses to start in this mode if the database contains active bans or destination-owned work, including exhausted releases. Reconcile and release those first, or use an isolated database for rule tuning.

Each threshold crossing (and every matching event for threshold-one rules) records the hypothetical automatic ban in incident history. Later events above threshold may qualify for renewal without producing another incident. These records are never replayed as enforcement jobs. Incident history uses `--incident-retention` (default `720h`, range `24h`–`8760h`). Recent failure counts themselves remain in the sliding detection window, so a fresh event after switching back can trigger a real ban. The authenticated `GET /incidents` endpoint exposes the recorded outcomes through `observeOnly`, `banUntil` and `effectiveBanUntil`.
