# Keycloak Warden: local end-to-end stack

This is a **development-only** Docker Compose setup. It exercises real Keycloak logins, the actual [Keycloak Snitch](https://github.com/gi8lino/keycloak-snitch) JAR, Warden's detection engine, and [Hookglass](https://github.com/gi8lino/hookglass), which verifies Warden's configurable outbound `X-API-Key` header and logs accepted requests.

No Snitch checkout, Maven, fake event injection, or Python smoke harness is needed.

## Start

From the **Warden project root**:

```sh
make e2e-up               # downloads the pinned Snitch release JAR and starts Compose
make e2e-logs             # follow Warden, Keycloak, and Hookglass logs
make e2e-test             # resets only this E2E stack, starts it, and tests the full flow
make e2e-down             # stop containers; preserve the E2E SQLite volume
make e2e-reset            # stop containers and delete the E2E SQLite volume
```

The Snitch JAR is downloaded by `make snitch-download` (also run by `make download` and `make e2e-up`). The Makefile pins `SNITCH_VERSION`; override it with, for example, `make e2e-up SNITCH_VERSION=v0.0.4` to select that release. The versioned JAR is cached under `test/e2e/snitch/` and ignored by Git. The Keycloak image version in `Dockerfile.keycloak` must remain compatible with the Snitch release.

## Endpoints and test users

- Keycloak: `http://127.0.0.1:18080` (`warden-e2e` realm)
- Warden events: `http://127.0.0.1:18081/events` (receives signed Snitch events)
- Warden management: `http://127.0.0.1:18082/readyz` (health and metrics)
- Hookglass: `http://127.0.0.1:18090/healthz` (verifies the header at `/header`)

Keycloak administrator: `dev-admin` / `dev-admin-password`. Test user: `demo` / `dev-password`.

**For demo logins, open the [warden-e2e account console](http://127.0.0.1:18080/realms/warden-e2e/account/).** Try `demo` with a wrong password twice within one minute to trigger a ban and an outbound webhook in Hookglass logs. This example forwards only `LOGIN_ERROR`; a successful login does not produce a webhook. Hookglass logs authenticated ban/release webhooks, not individual Snitch login events.

The `demo` user and `snitch` listener exist only in **warden-e2e**. The root Keycloak URL leads to the **master** admin console, where a failed `demo` login does not reach Warden. For administration, use [the admin console](http://127.0.0.1:18080/admin/master/console/) with the administrator credentials above. Client for automated password-grant tests: `smoke`.

Inside the containers, Warden listens on application port **8080** and management port **8081**. Compose publishes these as host ports **18081** and **18082** respectively; Keycloak uses host port **18080** to avoid conflicts with other local stacks. If you override a host port, adjust the browser URLs accordingly.

The Makefile variables `E2E_KC_PORT`, `E2E_WARDEN_PORT`, `E2E_MANAGEMENT_PORT`, `E2E_RECEIVER_PORT`, and `E2E_PROJECT` can be overridden to avoid conflicts.

To inspect authenticated outbound webhook requests:

```sh
docker compose -p keycloak-warden-e2e -f test/e2e/compose.yaml logs -f receiver
```

To inspect active bans through the authenticated application API:

```sh
docker compose -p keycloak-warden-e2e -f test/e2e/compose.yaml exec warden \
    /keycloak-warden list-active --admin-token development-admin-token -o json
```

## What `make e2e-test` verifies

1. Starts the actual Compose services with a fresh E2E-only SQLite volume.
2. Waits for Warden and Hookglass, checks that `/header` rejects requests missing the API key, and waits for Keycloak.
3. Sends two **real invalid password grants** to Keycloak's token endpoint.
4. Confirms Snitch's signed events caused Warden to ban the originating IP.
5. Confirms Hookglass accepted and logged Warden's header-authenticated banned-state webhook.
6. Unbans the recorded IP through Warden's authenticated API.
7. Confirms the release webhook, empty active-ban list, and Prometheus metrics.

The stack stays up after a successful test so you can inspect Hookglass's logs. Shut it down with `make e2e-down` or remove its data with `make e2e-reset`.

## Why Hookglass shares Warden's network

Warden forbids unencrypted HTTP webhooks to arbitrary network hosts. This demo keeps that protection intact: Hookglass uses `network_mode: service:warden`, listens on `:8090`, and Warden resolves `env:WARDEN_E2E_WEBHOOK_URL` to `http://127.0.0.1:8090/header`. Warden also resolves `X-API-Key: env:WARDEN_E2E_WEBHOOK_KEY`, which Hookglass validates against `WEBHOOK_API_KEY`. Snitch still reaches Warden by the normal Compose DNS name, at `http://warden:8080/events`, and Warden still verifies Snitch's HMAC signature on incoming events.

Hookglass logs only accepted request bodies and verification status; it intentionally does not log secret header values. The Compose file pins `ghcr.io/gi8lino/hookglass:v0.0.2`; ensure that image tag is published and pullable.

All HTTP ports are bound to host **127.0.0.1** and credentials are deliberately hard-coded for local development. Do not deploy this Compose file to production.

**Note:** Restart the stack together (`make e2e-down && make e2e-up`) rather than recreating only Warden, because Hookglass shares Warden's network namespace.
