CREATE TABLE destination_backoff (
    destination TEXT PRIMARY KEY,
    delay_ms INTEGER NOT NULL,
    retry_at INTEGER NOT NULL
);
