-- Persist hypothetical threshold hits and explicit retry requests independently of decisions.
CREATE TABLE ban_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    failures INTEGER NOT NULL,
    threshold INTEGER NOT NULL
);
CREATE INDEX ban_observations_time ON ban_observations(observed_at);

CREATE TABLE delivery_retries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    revision INTEGER NOT NULL,
    destination TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    previous_attempts INTEGER NOT NULL,
    FOREIGN KEY (ip, revision, destination) REFERENCES delivery_history(ip, revision, destination) ON DELETE CASCADE
);
CREATE INDEX delivery_retries_group ON delivery_retries(ip, revision, destination, id DESC);
