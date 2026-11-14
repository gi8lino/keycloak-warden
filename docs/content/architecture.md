# Architecture

Warden has a small pipeline: **event ingestion → detection → durable desired state → independent delivery**.

```mermaid
flowchart TD
    A["Keycloak user event"]
    B["Snitch event listener"]
    C["Warden /events"]
    D["SQLite decisions and sources"]
    E["Delivery worker"]
    F["Cloudflare zone(s)"]
    G["HTTP webhook(s)"]

    A --> B
    B -->|"Signed HTTP request"| C
    C -->|"Validate, deduplicate, count failures"| D
    D --> E
    E --> F
    E --> G

```

## Ingestion and detection

Keycloak Snitch sends signed event envelopes to the application listener. Warden validates the event contract, normalizes the client IP, and processes matching Keycloak `LOGIN_ERROR` events. The rule counts distinct failures within the configured sliding window, keyed by **IP address**, not by user or realm.

When the threshold is reached, Warden records or extends a decision in SQLite. Duplicate events do not cause duplicate observations.

Detection policy stays in the ingestion service. Runtime targets own their provider settings and retry limits; ingestion, ban administration, and the delivery worker pass the necessary destination identifiers to SQLite operations when creating or reconciling decisions. The store does not retain detection rules or target configuration.

## Desired versus delivered state

A decision's `state` is either `banned` or `unbanned`. This is **Warden's desired state**, not proof that an external system has already applied it. Each destination acknowledges revisions independently, and unsuccessful deliveries are retried.

Automatic expiry or a manual unban changes the desired state to `unbanned`. A manual ban and an automatic ban are independent sources; releasing an IP removes the active reasons for blocking it.

Maintenance computes the observation retention cutoff from the detection window (at least 24 hours) and supplies that cutoff directly to SQLite. Only delivery state and destination identifiers needed to resume delivery are persisted.

The administrative API, `list-active`, and `inspect` return the same record shape: `decision`, `sources`, and `deliveries`. `sources` describes the independent currently active automatic or manual reasons for a block, while `deliveries` contains the last acknowledged revision for each destination. A released decision retains its historical identity and delivery acknowledgements, but has no active sources.

A webhook receives only the desired decision (`id`, `revision`, `ipAddress`, `state`, and `expiresAt`). Failure observations are retained internally for detection and replay protection, not exported as part of the decision.

## Two listeners

The application listener serves `POST /events` and, when an admin token is configured, authenticated `/bans` routes. The independent management listener serves `/healthz`, `/readyz`, and optionally `/metrics`.

`--route-prefix` applies to the application routes. Management paths stay at their root paths.

See [API](api.md) for the endpoints and [Operations](operations.md) for maintenance and readiness behavior.

## Ban reconciliation ownership

The `bans` application package evaluates source extension and effective decision revisions. SQLite exposes transactional read/write primitives and synchronizes persisted delivery rows without interpreting ban policy.

## Delivery retry backoff

The `actions` package calculates the capped exponential retry delay (10 seconds up to 5 minutes) using the destination's last persisted delay. SQLite only loads the previous delay and atomically stores the calculated pause and retry deadline along with the attempt result.

## Expiry and release workflows

`bans` orchestrates manual releases and source expiry using atomic `TransactBan` callbacks. The application clears sources, advances the observation generation, computes effective decisions and enqueues delivery revisions; SQLite provides only the corresponding persistence primitives. The action worker delegates expiry to `bans.ExpiryService`, rather than asking SQLite to maintain ban policy.
