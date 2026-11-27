# Operations

## Health and readiness

The management listener defaults to `127.0.0.1:8081`:

| Endpoint       | Purpose                                           |
| -------------- | ------------------------------------------------- |
| `GET /healthz` | Process liveness                                  |
| `GET /readyz`  | SQLite readiness and configured delivery workers  |
| `GET /metrics` | Prometheus metrics; exposed only with `--metrics` |

The management listener is independent of the optional application `--route-prefix`.

Warden reports successful delivery only after a destination acknowledges a decision revision. Look for `delivery_completed`, `delivery_failed`, and the destination name in logs.

## Diagnostic logging

Normal operation logs effective automatic ban updates and destination acknowledgements at INFO.
A committed expiry that releases the last active source emits `ban_expired` at INFO.
Unexpected authenticated event-contract failures and retryable delivery failures use WARN.
With `--debug`, Warden also explains why an event was ignored, identified as a duplicate,
remained below the detection threshold, or left a decision unchanged. DEBUG logs do not
repeat ordinary successful event processing or delivery starts. HTTP access logs remain
independently controlled by `--access-log`.

Notification deliveries use `notification_completed`, `notification_failed` and `notification_queue_error` log events. Failures do not stop enforcement or make an otherwise running worker unready. Exhausted notification jobs remain terminal until explicitly retried and are retained until their completion passes the incident retention cutoff. Use `/notifications` for incident delivery history and `/notifications/{id}/attempts` for recorded sends. `/deliveries` remains enforcement-only.

## Worker status

`GET /workers` is available on the **authenticated application listener** when an administrator token is configured; it is not exposed by the management listener. It reports the status of the background workers:

- **Enforcement:** `idle`, `processing`, or `stopped`; start time; unexpired ban IP count; `pending`, `retrying`, and `exhausted` counts for each destination's **current** decision revision; the next persisted expiry/delivery deadline; and the most recent completed delivery attempt. The last attempt can predate the current process because it is read from SQLite.
- **Notifications:** optional runtime state, retained pending/retrying/exhausted/delivered counts, the next eligible retry deadline and latest recorded attempt.
- **Maintenance:** worker state and start time, configured prune/optimize intervals, and each operation's latest attempt, success, and error information. Manual and scheduled work share the existing maintenance runner.

Example:

```sh
curl -fsS -H "Authorization: Bearer $WARDEN_ADMIN_TOKEN" \
  http://127.0.0.1:8080/workers
```

The endpoint is observational only. A healthy worker can coexist with exhausted delivery revisions: `exhausted` means that destination has not acknowledged the current revision, and an exhausted unban may leave a remote block in place. Queue counts and the deadline are snapshots, not an atomic view of concurrent changes.

## SQLite maintenance

Warden runs SQLite `PRAGMA optimize` when opening its database and periodically afterward. It also prunes stale failed-login observations. The two schedules are independent:

```sh
warden serve \
  --config=warden.yaml \
  --prune-interval=1h \
  --optimize-interval=24h
```

The corresponding environment variables are `WARDEN__PRUNE_INTERVAL` and `WARDEN__OPTIMIZE_INTERVAL`. Both intervals must be between `5m` and `8760h`.

Pruning runs at startup and then on schedule. Counting observations are retained for at least 24 hours or the longest configured detection window, whichever is longer. Incidents, including hypothetical bans, use `incident-retention` (default 30 days). Optimization does **not** run a full `VACUUM`; SQLite reuses freed pages, and its automatic WAL checkpointing remains enabled.

Manual maintenance is available through the authenticated application API (`GET /maintenance`, `POST /maintenance/prune`, and `POST /maintenance/optimize`). Scheduled tasks continue unchanged, and operations are serialized to avoid overlapping housekeeping. These actions do not delete ban decisions or run `VACUUM`.

## Migration baselines

To consolidate SQLite migrations:

```sh
make merge-migrations
# Review the generated file under build/migrations/
make cleanup-migrations
make test
```

The first target generates and validates a candidate baseline without modifying source migrations. The cleanup target replaces old migration files after validation. Existing databases already at the consolidated version can adopt the baseline; **partially migrated databases must first be upgraded using the older migration set**.

Back up persistent databases before replacing migration files and keep the previous migrations available through Git history.

## Logs and investigation

Enable request logs with `--access-log` and additional diagnostics with `--debug`. Choose `--log-format=json` (default) or `--log-format=text`. Inspect a decision and its destination acknowledgements with:

```sh
warden inspect DECISION_ID --admin-token="$WARDEN_ADMIN_TOKEN" -o json
```

The `inspect` and `list-active` commands use the authenticated application API and require a running Warden instance. Direct SQLite reads are not supported by administrative CLI commands.

See [Architecture](architecture.md) for why a `banned` decision does not automatically prove Cloudflare has applied the block.

The `warden_snitch_events_total` counter is labeled by `realm`, `event_kind` (`user` or `admin`) and `event_type` (the native user event name, empty for administrative events). Named rule threshold hits use `warden_incidents_total{rule="..."}`.

Notification HTTP attempts and latency are exposed independently as `warden_notification_attempts_total{destination,outcome}` and `warden_notification_duration_seconds{destination}`. Explicit retries preserve attempt history and require the same destination identity; see [API](api.md).
