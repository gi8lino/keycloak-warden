CREATE TABLE notification_identities (
    name TEXT PRIMARY KEY,
    identity TEXT NOT NULL
);

CREATE TABLE notification_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL CHECK (incident_id > 0),
    destination TEXT NOT NULL REFERENCES notification_identities (name),
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    delay INTEGER NOT NULL DEFAULT 0 CHECK (delay >= 0),
    next_at INTEGER NOT NULL,
    completed_at INTEGER,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'exhausted')),
    CHECK ((state = 'pending' AND completed_at IS NULL) OR (state <> 'pending' AND completed_at IS NOT NULL)),
    UNIQUE (incident_id, destination)
);

CREATE INDEX notification_ready ON notification_deliveries (next_at, id) WHERE state = 'pending';
CREATE INDEX notification_destination ON notification_deliveries (destination, id) WHERE state = 'pending';
CREATE INDEX notification_completed ON notification_deliveries (completed_at) WHERE state <> 'pending';
