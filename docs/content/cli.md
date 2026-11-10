# Command-line interface

The Warden binary provides server operation, manual ban management, and inspection of persisted decisions.

## Commands

| Command       | Purpose                                                                         |
| ------------- | ------------------------------------------------------------------------------- |
| `serve`       | Start HTTP ingestion, delivery, and maintenance workers                         |
| `ban`         | Create or extend one or more manual bans through the application API            |
| `unban`       | Remove active ban sources for one or more IPs through the application API       |
| `list-active` | Read active bans from SQLite                                                    |
| `inspect`     | Inspect decisions, active sources, and delivery acknowledgements by decision ID |

## Start Warden

```sh
warden serve --config=warden.yaml --database=/data/warden.db
```

A shared Snitch secret is required; set `WARDEN__SNITCH_SECRET` securely or pass `--snitch-secret`.

## Ban or unban an address

The manual API is enabled only when the running server has an admin token. The CLI uses that same bearer token to call the application listener.

```sh
warden ban 203.0.113.10 \
  --duration=1h \
  --reason="Suspicious login attempts" \
  --admin-token="$WARDEN_ADMIN_TOKEN"

warden unban 203.0.113.10 \
  --admin-token="$WARDEN_ADMIN_TOKEN"
```

Both commands accept multiple addresses. When the server is not local, set `--application-url=https://your-warden.example/warden` (with the actual base path) to reach the application API.

## Inspect persisted state

```sh
warden list-active --database=/data/warden.db --output=json
warden inspect DECISION_ID --database=/data/warden.db --output=json
```

Use `--output=text`, `--output=json`, or `--output=yaml` with commands that produce output. `list-active` and `inspect` return the same record structure (`decision`, `sources`, and `deliveries`) in JSON and YAML. The `inspect` command also includes the currently active sources for historical decisions. Both commands read SQLite directly rather than calling the administrative HTTP API, so run them where the database is accessible.

## Discover flags

```sh
warden --help
warden serve --help
warden ban --help
```

See [Configuration](configuration.md) for runtime flags and [API](api.md) for the corresponding HTTP routes.
