# HTTP API

The application listener handles Snitch event ingestion and authenticated administrative operations. Health and metrics are exposed separately on the management listener.

## Event ingestion

`POST /events` accepts JSON event envelopes sent by Keycloak Snitch. Requests must carry the valid HMAC signature derived from the shared Snitch secret. Use the [Snitch integration](https://github.com/gi8lino/keycloak-snitch) rather than constructing unsigned requests manually.

Request bodies are limited to **64 KiB**. Larger requests are rejected with HTTP `413 Request Entity Too Large`.

A successfully processed event returns HTTP `204 No Content`. An event is not necessarily a new ban: the configured detection threshold decides when a new desired state is recorded.

## Administrative endpoints

When `--admin-token` is set, Warden registers these authenticated routes:

| Method   | Route        | Description                             |
| -------- | ------------ | --------------------------------------- |
| `POST`   | `/bans`      | Create or extend a manual ban           |
| `GET`    | `/bans`      | List current active bans                |
| `GET`    | `/bans/{id}` | Inspect one decision and its sources    |
| `DELETE` | `/bans/{id}` | Clear the decision's active ban sources |

Requests require `Authorization: Bearer <admin-token>`. An empty admin token **disables** the routes; it does not make them public.

`POST /bans` accepts JSON request bodies up to **16 KiB**. Larger requests are rejected with HTTP `413 Request Entity Too Large`.

For a manual ban, send a JSON object such as:

```json
{
  "ipAddress": "203.0.113.10",
  "duration": "1h",
  "reason": "Investigation"
}
```

The API responds with a ban record containing three sections: `decision` (desired state), `sources` (currently active automatic and manual reasons), and `deliveries` (acknowledged revisions per destination). Individual decision reads additionally return an unpaged `currentDeliveries` list for all current-revision destinations (distinct from paginated history), up to 50 newest `sourceChanges` (source additions, edits, and removals persisted since the source journal migration) and a bounded `deliveryHistory` page with per-revision statuses and completed attempts. The `inspect` CLI presents this history under `deliveries`. Decisions use `"state":"banned"` or `"state":"unbanned"`, not the older `"active"` boolean.

For example, an active manual ban that has been acknowledged by a webhook might look like:

```json
{
  "decision": {
    "id": "fee0c026-0eb3-416a-9e13-823248fdb9da",
    "revision": 4,
    "ipAddress": "203.0.113.10",
    "state": "banned",
    "expiresAt": "2026-11-10T22:33:04Z"
  },
  "sources": [
    {
      "kind": "manual",
      "expiresAt": "2026-11-10T22:33:04Z",
      "reason": "Investigation"
    }
  ],
  "deliveries": [
    {
      "destination": "webhook.receiver",
      "acknowledgedRevision": 4
    }
  ]
}
```

`GET /bans` returns an array of records; `GET /bans/{id}` returns one record. History uses numbered pages ordered by revision descending and destination ascending (up to 16 entries per request, with the latest 16 attempts per entry). The first page is returned by default. Request any one-based page directly with `GET /bans/{id}?history-page=100` (SQL `LIMIT/OFFSET`). To keep newer revisions from shifting page boundaries, pass the first response’s `decision.revision` as `history-through-revision` on subsequent requests. This bounds group membership; attempts and statuses can still update. The response includes `historyPage` and, when more entries exist, `historyNextPage`. Attempts omitted from an entry are indicated by `attemptsTruncated`. All completed attempts remain stored in SQLite; paging does not prune them. The acknowledgement describes the last successfully accepted revision, which may be lower than the desired revision while delivery is pending or retrying. Only currently active sources are returned, and `sources` is empty for a released decision. Failed-login observation counts remain internal to detection, not part of the decision or webhook payload.

## Decision revision journal and current deliveries

The effective decision revision journal records only revisions that change the desired decision. Source edits that leave the effective state and expiry unchanged are audited separately in `sourceChanges` on `GET /bans/{id}` without creating a delivery revision. Older source changes from before the journal migration cannot be reconstructed. The journal records source type and values, not a per-human actor identity (Warden uses a shared admin token).

Warden also exposes two authenticated, read-only cross-decision endpoints, using the same bearer token and application route prefix as `/bans`:

- `GET /decisions/history` lists **committed effective decision changes** (including extensions and releases), newest first. Each entry includes the stable decision ID, canonical IP, revision, desired state, expiry, UTC commit timestamp, cause (`automatic`, `manual`, `release`, `expiry`, or `reconciled`), and the active source snapshot (kind, reason, expiry) evaluated for that revision. Use `page=2`, `through-sequence=<first response throughSequence>` to pin subsequent pages against new inserts, `ip=203.0.113.42` (exact canonical IP), and `state=banned|unbanned` to filter.
- `GET /deliveries` lists **only the current revision** for each persisted decision/destination, including released decisions whose unban delivery has not been acknowledged. Each row includes desired and acknowledged revision, state, status, attempt count, optional latest provider error and retry time. Use `page=2`, `status=pending|retrying|delivered|exhausted`, and `destination=cloudflare.edge` to filter.

Both responses use `{ "items": [...], "page": 1, "nextPage": 2 }`, with a maximum of 20 entries per page. `nextPage` is omitted for the last page. Filters are single-valued; invalid/duplicate parameters return HTTP 400. Navigation is ordered by revision commit time (and deterministic tie-breakers), with SQL LIMIT/OFFSET; new changes can shift page boundaries between requests. Use the decision detail endpoint for complete delivery attempts.

Decision revisions are written **in the same SQLite transaction as the state change**. The journal starts recording after migration `0008`; earlier decisions are not given invented timestamps or source histories. No event is written when the effective revision is unchanged, even if the reason on a current source changes. Warden does not record a separate authenticated operator identity for administrative changes.

A `delivered` status confirms acceptance of a notification, not necessarily that a remote firewall already reconciled it. In particular, an `exhausted` unban delivery may mean a destination still blocks an IP after Warden released the decision.

## Go administration client

The public [`pkg/client`](https://github.com/gi8lino/keycloak-warden/tree/main/pkg/client) package validates its administrative API URL before sending requests. By default, it requires HTTPS for non-loopback hosts; plain HTTP is accepted for `localhost`, `127.0.0.1`, and `::1`.

For a restricted Kubernetes ClusterIP Service, callers can explicitly opt in to plain HTTP:

```go
api, err := client.New(
    "http://keycloak-warden.keycloak.svc.cluster.local:8080",
    adminToken,
    client.WithAllowInsecureHTTP(),
)
```

The same option is accepted by URL validation: `client.ValidateURL(address, client.WithAllowInsecureHTTP())`. Calls without the option retain the existing HTTPS requirement. Unsupported schemes, URL credentials, query strings, fragments, and malformed application prefixes are always rejected.

**Security:** HTTP does not encrypt the administrator bearer token in transit. Restrict access to Warden's application Service using Kubernetes network policies or equivalent controls. The opt-in affects **only the Go client**, not the Warden server, administrative CLI commands, outgoing webhook targets, TLS certificate verification, or redirect handling.

## Webhook delivery

Configured webhook targets receive a JSON representation of the desired decision, including its stable ID, revision, IP address, state, and expiry. When a target defines `body-template`, Warden renders a custom JSON body using those same fields; the default payload remains unchanged for other targets.

Webhook responses in the `2xx` range acknowledge a delivery by default. Individual targets may optionally configure a `response` rule for allowed HTTP status codes and plain-text or JSON body matching (including nested JSON error extraction). A rejected response is retried; a successful webhook response means the **receiver accepted the notification**, not necessarily that an external firewall has already reconciled the state. See [Configuration](configuration.md) for response rules.

## Route prefix

With `--route-prefix=/warden`, the application routes become `/warden/events` and `/warden/bans`. Management paths remain `/healthz`, `/readyz`, and `/metrics` without that prefix.

Use [CLI](cli.md) for supported manual operations and [Configuration](configuration.md) for authentication and destination setup.

## Database maintenance

Authenticated administrator requests (the same bearer token as `/bans`) can inspect and trigger housekeeping:

- `GET /maintenance` — status of in-process observation pruning and SQLite optimization, including last attempts and results.
- `POST /maintenance/prune` — remove expired failure observations using Warden's configured retention rule.
- `POST /maintenance/optimize` — invoke SQLite `PRAGMA optimize` (not a full `VACUUM`).

Manual operations run synchronously, return updated status, and are serialized with scheduled maintenance. A concurrent request returns `409 Conflict`; failures return a safe error response. These operations do not remove bans, decisions, delivery acknowledgements, or live observations. No request bodies or arbitrary SQL are accepted.

Example:

```sh
curl -fsS -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN" http://127.0.0.1:8080/maintenance
curl -fsS -X POST -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN" http://127.0.0.1:8080/maintenance/prune
```

With a route prefix, these routes are prefixed like `/bans`; the management listener remains separate.
