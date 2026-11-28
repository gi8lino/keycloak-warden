# HTTP API

The application listener handles Snitch event ingestion and authenticated administrative operations. Health and metrics are exposed separately on the management listener.

## Event ingestion

`POST /events` accepts JSON event envelopes sent by Keycloak Snitch. Requests must carry the valid HMAC signature derived from the shared Snitch secret. Use the [Snitch integration](https://github.com/gi8lino/keycloak-snitch) rather than constructing unsigned requests manually.

Request bodies are limited to **64 KiB**. Larger requests are rejected with HTTP `413 Request Entity Too Large`.

A successfully processed event returns HTTP `204 No Content`. An event is not necessarily a new ban: the configured detection threshold decides when a new desired state is recorded.

The envelope requires `schemaVersion: 2`, `id`, `source: "keycloak"`, `kind` and `timestamp`, plus exactly one non-null event object matching the kind. Unknown fields are rejected. User events carry their native type in `user.type`; administrative events carry operation and resource metadata in `admin`, with the administrator identity in `admin.actor`. The actor may be null. Representations and arbitrary event details are not accepted.

### User event

```json
{
  "schemaVersion": 2,
  "id": "bb685023-a081-4423-be47-0d40fe4aa59c",
  "source": "keycloak",
  "kind": "user",
  "timestamp": "2026-11-05T14:30:00Z",
  "user": {
    "type": "LOGIN_ERROR",
    "realmId": "example",
    "clientId": "application",
    "userId": null,
    "ipAddress": "203.0.113.42",
    "error": "invalid_user_credentials"
  }
}
```

### Administrative event

```json
{
  "schemaVersion": 2,
  "id": "ea9fc922-39e3-48d5-8d80-ef3aa801c36f",
  "source": "keycloak",
  "kind": "admin",
  "timestamp": "2026-11-05T14:35:00Z",
  "admin": {
    "realmId": "example",
    "operationType": "CREATE",
    "resourceType": "REALM_ROLE_MAPPING",
    "resourcePath": "users/example-user/role-mappings/realm",
    "actor": {
      "realmId": "master",
      "clientId": "admin-client-id",
      "userId": "administrator-id",
      "ipAddress": "203.0.113.42"
    },
    "error": null
  }
}
```

`admin.realmId` identifies the affected realm; `admin.actor.realmId` identifies the authentication realm. Admin client IDs are native Keycloak identifiers.

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

The API responds with a ban record containing three sections: `decision` (desired state), `sources` (currently active automatic and manual reasons), and `deliveries` (acknowledged revisions per destination). Individual decision reads additionally return an unpaged `currentDeliveries` list for all current-revision destinations (distinct from paginated history), up to 50 newest `sourceChanges` (source additions, edits, and removals persisted since the source journal migration) and a bounded `deliveryHistory` page with per-revision statuses and completed attempts. The `inspect` CLI presents this history under `deliveries`. Decisions use `"state":"banned"` or `"state":"unbanned"`.

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
- `GET /workers` reports the enforcement, notification and maintenance worker lifecycles, current-revision delivery counts, active bans, the next source-expiry/delivery deadline, latest completed delivery attempt, and maintenance task outcomes. It is read-only and requires the same administrator token.

Both responses use `{ "items": [...], "page": 1, "nextPage": 2 }`, with a maximum of 20 entries per page. `nextPage` is omitted for the last page. Filters are single-valued; invalid/duplicate parameters return HTTP 400. Navigation is ordered by revision commit time (and deterministic tie-breakers), with SQL LIMIT/OFFSET; new changes can shift page boundaries between requests. Use the decision detail endpoint for complete delivery attempts.

Decision revisions are written **in the same SQLite transaction as the state change**. The journal starts recording after migration `0008`; earlier decisions are not given invented timestamps or source histories. No event is written when the effective revision is unchanged, even if the reason on a current source changes. Warden does not record a separate authenticated operator identity for administrative changes.

A `delivered` status confirms acceptance of a notification, not necessarily that a remote firewall already reconciled it. In particular, an `exhausted` unban delivery may mean a destination still blocks an IP after Warden released the decision.

## Worker status

`GET /workers` returns one read-only snapshot of the Warden background workers. It is authenticated with the same bearer token as bans and maintenance. The **enforcement** worker reports its runtime lifecycle (`idle`, `processing`, `stopped`) and persisted delivery counts for the current revision of each decision, plus the next persisted wake-up deadline and the last completed attempt. The **maintenance** worker reports its runtime state and the existing prune/optimize task statuses. The same maintenance snapshot, including `state` and `startedAt`, is also returned by `GET /maintenance`.

The Go client provides `Client.WorkerStatus(ctx)` with typed results. The endpoint uses the application route prefix. The response has `enforcement`, `notifications`, and `maintenance` fields. Notifications include pending, retrying, delivered and exhausted counts, the next eligible deadline, the last recorded attempt time and an optional `runtime` object (absent if no worker is configured). Worker states and database counts are collected separately, so this is not a transactional snapshot.

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

## Enforcement webhook delivery

Configured `enforcements.webhook` targets receive a JSON representation of the desired decision, including its stable ID, revision, IP address, state, and expiry. A target with `body-template` renders a custom JSON body using those fields.

Webhook responses in the `2xx` range acknowledge a delivery by default. Individual targets may optionally configure a `response` rule for allowed HTTP status codes and plain-text or JSON body matching (including nested JSON error extraction). A rejected response is retried; a successful webhook response means the **receiver accepted the notification**, not necessarily that an external firewall has already reconciled the state. See [Configuration](configuration.md) for response rules.

## Route prefix

With `--route-prefix=/warden`, the application routes become `/warden/events` and `/warden/bans`. Management paths remain `/healthz`, `/readyz`, and `/metrics` without that prefix.

Use [CLI](cli.md) for supported manual operations and [Configuration](configuration.md) for authentication and destination setup.

## Database maintenance

Authenticated administrator requests (the same bearer token as `/bans`) can inspect and trigger housekeeping:

- `GET /maintenance` — worker lifecycle (`state`, `startedAt`) and in-process pruning/optimization task status, including last attempts and results, configured intervals (`pruneInterval`, `optimizeInterval`), and effective retention (`observationRetention`, `incidentRetention`) as Go duration strings.
- `POST /maintenance/prune` — remove expired observations, incidents, and terminal notification deliveries using Warden's retention settings.
- `POST /maintenance/optimize` — invoke SQLite `PRAGMA optimize` (not a full `VACUUM`).

Manual operations run synchronously, return updated status, and are serialized with scheduled maintenance. A concurrent request returns `409 Conflict`; failures return a safe error response. These operations do not remove bans, decisions, enforcement delivery acknowledgements, pending notifications, or live observations. No request bodies or arbitrary SQL are accepted.

Example:

```sh
curl -fsS -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN" http://127.0.0.1:8080/maintenance
curl -fsS -X POST -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN" http://127.0.0.1:8080/maintenance/prune
```

With a route prefix, these routes are prefixed like `/bans`; the management listener remains separate.

## Delivery health, explicit retries, and decision timelines

These authenticated application endpoints use the existing admin bearer token and route prefix:

| Method | Path                         | Purpose                                                                                            |
| ------ | ---------------------------- | -------------------------------------------------------------------------------------------------- |
| GET    | `/deliveries/health`         | Aggregate current-revision status counts per destination, including failed and exhausted releases. |
| POST   | `/deliveries/retry`          | Requeue one exhausted current-revision delivery.                                                   |
| GET    | `/bans/{id}/timeline?page=1` | Paginated newest-first source, revision, delivery attempt and retry activity.                      |

A retry request contains `decisionId`, positive `revision`, `destination`, and nonblank `actor` (at most 512 bytes):

```json
{
  "decisionId": "fee0c026-0eb3-416a-9e13-823248fdb9da",
  "revision": 4,
  "destination": "webhook.receiver",
  "actor": "operator"
}
```

HTTP 202 with `{"queued":true}` acknowledges queue admission, not delivery success. HTTP 409 rejects stale revisions, already queued or delivered work, expired bans, or unavailable destinations. The request, identity, and number of previously completed attempts are stored atomically with queue admission. The configured attempt budget starts again, but attempt numbers and previous errors are never erased. Shared destination backoff remains in force. A shared admin token cannot authenticate individual human identities; the direct API caller asserts `actor`, whereas WebUI supplies its authenticated account name server-side.

Health is based on current persisted delivery status, not a provider connectivity probe. It includes destinations with recorded current history, even for released decisions. Failed unbans are retrying or exhausted current releases; exhausted unbans are a subset. Timeline pages contain up to 20 records and reflect live data (new inserts can shift pages). The timeline reports recorded timestamps, causes, source edits, delivery attempts and explicit retries. Scheduled expiry is not proof of release.

## Detection incidents

`GET /incidents` returns named rule threshold hits, newest first, with `items` and optional `nextBeforeId`. Pass that cursor as `before-id` to retrieve the next page; optional `rule` and `kind` filters must remain the same across pages. It requires the administrative bearer token and uses the application route prefix. Each item includes the incident ID, rule name, triggering event identity and metadata (`eventKind` is `user` or `admin`; `eventType` is present only for user events), producer and processing timestamps, count, threshold, aggregation context (`groupBy`, `groupKey`, `identityRealm`, `distinct`, `window`), optional `banUntil` and longest requested `effectiveBanUntil`, optional resulting decision ID/revision, and `observeOnly`. The expiry is the requested rule expiry, not an external delivery acknowledgement. This endpoint is not a complete administrative audit log: only qualifying named rules record incidents. Incidents expire under the independent `--incident-retention` policy.

## Incident notifications

Generic `notifications.webhook` destinations receive the incident item JSON returned by `/incidents`, including its stable incident ID, rule, event metadata, count, threshold and requested ban information. All webhooks support optional templates, including the supplied Slack and Teams examples. Notification delivery does not change the enforcement API, delivery history or acknowledgement semantics.

### Notification delivery administration

These endpoints use the authenticated application listener and its route prefix:

| Method | Path                                            | Purpose                                                      |
| ------ | ----------------------------------------------- | ------------------------------------------------------------ |
| GET    | `/notifications?before-id=123`                  | List retained occurrence deliveries, newest first.           |
| GET    | `/notifications/{id}/attempts?before-number=10` | List recorded send attempts, newest first.                   |
| POST   | `/notifications/{id}/retry`                     | Requeue one exhausted delivery using a fresh attempt budget. |

Each list returns up to 20 `items`; omit the cursor for the first page, then use `nextBeforeId` or `nextBeforeNumber` if present. The delivery list includes destination, incident ID, lifetime attempt count, status, latest error and scheduling timestamps. Attempt history is recorded from migration 0015; older attempts are not fabricated. A missing attempt history returns an empty list.

Retry requires `{"actor":"operator"}` and returns HTTP 202 with `{"queued":true}`; unavailable, reassigned, unknown-identity or non-exhausted deliveries return 409. The operator identity is asserted by the authenticated caller. The retry journal and prior attempts remain in SQLite until the retained delivery is pruned. The Go client exposes `ListNotifications`, `NotificationAttempts` and `RetryNotification`.
