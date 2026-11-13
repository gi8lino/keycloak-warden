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

The API responds with a ban record containing three sections: `decision` (desired state), `sources` (currently active automatic and manual reasons), and `deliveries` (acknowledged revisions per destination). These records use the same structure as the `list-active` and `inspect` CLI commands. Decisions use `"state":"banned"` or `"state":"unbanned"`, not the older `"active"` boolean.

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

`GET /bans` returns an array of records; `GET /bans/{id}` returns one record. The acknowledgement describes the last successfully accepted revision, which may be lower than the desired revision while delivery is pending or retrying. Only currently active sources are returned, and `sources` is empty for a released decision. Failed-login observation counts remain internal to detection, not part of the decision or webhook payload.

## Webhook delivery

Configured webhook targets receive a JSON representation of the desired decision, including its stable ID, revision, IP address, state, and expiry. When a target defines `body-template`, Warden renders a custom JSON body using those same fields; the default payload remains unchanged for other targets.

Webhook responses in the `2xx` range acknowledge a delivery. An unsuccessful delivery is retried; a successful webhook response means the **receiver accepted the notification**, not necessarily that an external firewall has already reconciled the state.

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


