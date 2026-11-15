-- Consolidated SQLite schema and seed data for Keycloak Warden.
-- warden:replaces-through=5

CREATE TABLE ban_sources (
    ip TEXT NOT NULL REFERENCES decisions (ip) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('automatic', 'manual')),
    expires INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ip, kind)
);
CREATE TABLE decisions (
    ip TEXT PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'unbanned' CHECK (state IN ('banned', 'unbanned')),
    expires INTEGER NOT NULL,
    failure_generation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE deliveries (
    ip TEXT NOT NULL REFERENCES decisions (ip),
    destination TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    retry_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, destination)
);
CREATE TABLE delivery_attempts (
    ip TEXT NOT NULL,
    revision INTEGER NOT NULL,
    destination TEXT NOT NULL,
    number INTEGER NOT NULL,
    completed_at INTEGER NOT NULL,
    error TEXT,
    PRIMARY KEY (ip, revision, destination, number),
    FOREIGN KEY (ip, revision, destination)
        REFERENCES delivery_history(ip, revision, destination) ON DELETE CASCADE
);
CREATE TABLE delivery_history (
    ip TEXT NOT NULL REFERENCES decisions(ip) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    destination TEXT NOT NULL,
    desired_state TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'retrying', 'delivered', 'exhausted', 'superseded')),
    acknowledged_at INTEGER,
    superseded_by INTEGER,
    PRIMARY KEY (ip, revision, destination)
);
CREATE TABLE destination_backoff (
    destination TEXT PRIMARY KEY,
    delay_ms INTEGER NOT NULL,
    retry_at INTEGER NOT NULL
);
CREATE TABLE failures (
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    received INTEGER NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source, event_id)
);
CREATE INDEX failures_by_ip ON failures (ip, received);
CREATE INDEX failures_by_time ON failures (received);
CREATE INDEX expiry ON decisions (state, expires);
CREATE INDEX ban_sources_by_expiry ON ban_sources (expires);
