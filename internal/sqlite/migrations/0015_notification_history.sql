ALTER TABLE notification_deliveries ADD COLUMN identity TEXT;
ALTER TABLE notification_deliveries ADD COLUMN retry_baseline INTEGER NOT NULL DEFAULT 0 CHECK (retry_baseline >= 0 AND retry_baseline <= attempts);

UPDATE notification_deliveries
SET identity = (SELECT identity FROM notification_identities WHERE name = destination)
WHERE state = 'pending';

CREATE TABLE notification_attempts (
    delivery_id INTEGER NOT NULL REFERENCES notification_deliveries (id) ON DELETE CASCADE,
    number INTEGER NOT NULL CHECK (number > 0),
    completed_at INTEGER NOT NULL,
    error TEXT,
    PRIMARY KEY (delivery_id, number)
);

CREATE TABLE notification_retries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id INTEGER NOT NULL REFERENCES notification_deliveries (id) ON DELETE CASCADE,
    previous_attempts INTEGER NOT NULL CHECK (previous_attempts >= 0),
    requested_at INTEGER NOT NULL,
    actor TEXT NOT NULL
);
