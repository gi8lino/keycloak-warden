# Command-line interface

The Warden binary provides server operation, manual ban management, decision inspection, and database maintenance.

## Commands

| Command                | Purpose                                                                                        |
| ---------------------- | ---------------------------------------------------------------------------------------------- |
| `serve`                | Start HTTP ingestion, delivery, and maintenance workers                                        |
| `ban`                  | Create or extend one or more manual bans through the application API                           |
| `unban`                | Remove active ban sources for one or more IPs through the application API                      |
| `list-active`          | List active bans through the authenticated application API                                     |
| `inspect`              | Inspect decisions, active sources, and completed delivery attempts by revision and destination |
| `maintenance status`   | Read the latest scheduled and manual cleanup results                                           |
| `maintenance prune`    | Trigger expired failure-observation cleanup                                                    |
| `maintenance optimize` | Refresh SQLite query planner statistics                                                        |

## Start Warden

```sh
warden serve --config=warden.yaml --database=/data/warden.db
```

A shared Snitch secret is required; set `WARDEN__SNITCH_SECRET` securely or pass `--snitch-secret`.

## Ban or unban an address

The administrative API is enabled only when the running server has an admin token. All administrative commands (`ban`, `unban`, `list-active`, `inspect`, and `maintenance`) use that bearer token to call the application listener. No administrative CLI command opens SQLite directly.

```sh
warden ban 203.0.113.10 \
  --duration=1h \
  --reason="Suspicious login attempts" \
  --admin-token="$WARDEN_ADMIN_TOKEN"

warden unban 203.0.113.10 \
  --admin-token="$WARDEN_ADMIN_TOKEN"
```

Both commands accept multiple addresses. All administrative commands accept `--application-url` and `--admin-token`. They also accept `--request-timeout` (default `10s`), `--maintenance-timeout` (default `35s`), and `--max-response-bytes` (default `1048576`) to bound the administrative HTTP client. Both timeouts must be positive; the response limit must also be less than `MaxInt64`. When the server is not local, set `--application-url=https://your-warden.example/warden` (with the actual base path) to reach the application API. The server must be running.

## Inspect persisted state

```sh
warden list-active --admin-token="$WARDEN_ADMIN_TOKEN" -o json
warden inspect DECISION_ID --admin-token="$WARDEN_ADMIN_TOKEN" -o json
```

Both commands query the running application server; `--database` belongs to `serve` only. Set `--application-url` for remote instances or a non-default address or route prefix.

> Ban and unban print a concise confirmation for each successful IP by default, such as `Banned 203.0.113.10`. Other commands default to YAML. Use `--quiet` / `-q` to suppress command results; errors still go to stderr and failures return a nonzero exit code. `--quiet` and `--output` are mutually exclusive. Explicit output formats include the full result. Use `-o json` or `--output=json` for JSON, and `-o yaml` or `--output=yaml` for YAML. `--output=text` remains a compatibility alias for YAML. Both commands return `decision`, `sources`, and `deliveries`. In `inspect`, deliveries are grouped by revision (newest first) and destination. Each completed attempt records its number, UTC completion time, outcome and any provider error. A retrying delivery shows its next retry deadline; an acknowledged delivery retains previous failures and shows when it succeeded. A delivery that reaches its attempt limit is marked `exhausted` and retains its failed attempts. Unfinished revisions replaced by a later revision are marked `superseded`. Older databases retain known acknowledgements; attempt history starts at upgrade. Attempts are retained in SQLite for the lifetime of the decision. The default `inspect` view shows page 1 (16 entries per page). Use `warden inspect DECISION_ID --history-page=100` to request page 100 directly with SQL `LIMIT/OFFSET`, or `warden inspect DECISION_ID --history-all` to collect every page. The two flags cannot be combined. Each entry includes up to 16 recent attempts; all attempts remain stored in SQLite. Numbered pages can shift if new history is written between requests.

## Database maintenance

Warden automatically prunes expired login observations and periodically optimizes SQLite. To check the in-process maintenance status or trigger those same operations immediately, use:

```sh
warden maintenance status --admin-token="$WARDEN_ADMIN_TOKEN"
warden maintenance prune --admin-token="$WARDEN_ADMIN_TOKEN"
warden maintenance optimize --admin-token="$WARDEN_ADMIN_TOKEN"
```

All three commands call the running application's authenticated HTTP API; they do **not** open the SQLite database directly. `status` uses `GET /maintenance`; `prune` and `optimize` use `POST /maintenance/prune` and `POST /maintenance/optimize` respectively. They print the updated maintenance status in the selected output format.

As with the ban commands, specify `--application-url` for remote Warden instances, e.g. `--application-url=https://warden.example/warden`. If another maintenance run is already in progress, the API returns `409 Conflict`, and the CLI reports the error.

Pruning removes only expired failure observations. Optimization runs `PRAGMA optimize`; it does not run a full `VACUUM`, reset the database, or remove ban and delivery records.

## Discover flags

```sh
warden --help
warden serve --help
warden ban --help
warden maintenance --help
warden maintenance prune --help
```

See [Configuration](configuration.md) for runtime flags and [API](api.md) for the corresponding HTTP routes.

## Retry an exhausted delivery

After fixing the destination and restarting Warden if credentials changed, use the stable decision ID, exact destination, and current revision from `inspect` or WebUI:

```sh
warden retry-delivery fee0c026-0eb3-416a-9e13-823248fdb9da webhook.receiver \
  --revision 4 --actor operator
```

The command uses the same authenticated application API flags as `inspect`. The actor is asserted by the administrative CLI caller and stored with the retry audit record. A queued result is not a provider acknowledgement. Existing destination backoff is preserved.
