ALTER TABLE failures RENAME TO event_observations;
DROP INDEX failures_by_ip;
DROP INDEX failures_by_time;
CREATE INDEX event_observations_by_ip ON event_observations (ip, received);
CREATE INDEX event_observations_by_time ON event_observations (received);

ALTER TABLE event_observations ADD COLUMN event_kind TEXT NOT NULL DEFAULT 'user' CHECK (event_kind IN ('user', 'admin'));
ALTER TABLE event_observations ADD COLUMN event_type TEXT NOT NULL DEFAULT 'LOGIN_ERROR';
ALTER TABLE event_observations ADD COLUMN realm_id TEXT NOT NULL DEFAULT '';
ALTER TABLE event_observations ADD COLUMN identity_realm TEXT NOT NULL DEFAULT '';
ALTER TABLE event_observations ADD COLUMN user_id TEXT NOT NULL DEFAULT '';
ALTER TABLE event_observations ADD COLUMN operation_type TEXT NOT NULL DEFAULT '';
ALTER TABLE event_observations ADD COLUMN resource_type TEXT NOT NULL DEFAULT '';
ALTER TABLE event_observations ADD COLUMN event_error TEXT NOT NULL DEFAULT '';
ALTER TABLE event_observations ADD COLUMN ban_eligible INTEGER NOT NULL DEFAULT 1 CHECK (ban_eligible IN (0, 1));
CREATE INDEX event_observations_by_user ON event_observations (identity_realm, user_id, received);
CREATE INDEX event_observations_by_realm ON event_observations (realm_id, received);

CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('user', 'admin')),
    event_type TEXT NOT NULL,
    realm_id TEXT NOT NULL,
    actor_realm_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    event_error TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_path TEXT NOT NULL,
    event_at INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    count INTEGER NOT NULL,
    threshold INTEGER NOT NULL,
    ban_until INTEGER,
    observe_only INTEGER NOT NULL CHECK (observe_only IN (0, 1))
);
CREATE INDEX incidents_by_time ON incidents (observed_at);
