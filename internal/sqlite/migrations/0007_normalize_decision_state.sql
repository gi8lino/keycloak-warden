-- Version 6 shipped both active INTEGER and state TEXT as the fourth decision
-- column. Rebuild the related tables together so foreign keys remain enforced.
ALTER TABLE decisions RENAME TO old_decisions;
ALTER TABLE ban_sources RENAME TO old_ban_sources;
ALTER TABLE deliveries RENAME TO old_deliveries;
ALTER TABLE delivery_history RENAME TO old_delivery_history;
ALTER TABLE delivery_attempts RENAME TO old_delivery_attempts;

CREATE TABLE decisions (
    ip TEXT PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'unbanned' CHECK (state IN ('banned', 'unbanned')),
    expires INTEGER NOT NULL,
    failure_generation INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE ban_sources (
    ip TEXT NOT NULL REFERENCES decisions (ip) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('automatic', 'manual')),
    expires INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ip, kind)
);

CREATE TABLE deliveries (
    ip TEXT NOT NULL REFERENCES decisions (ip),
    destination TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    retry_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, destination)
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

WITH previous(ip, id, revision, state_value, expires, failure_generation) AS (
    SELECT * FROM old_decisions
)
INSERT INTO decisions (ip, id, revision, state, expires, failure_generation)
SELECT ip, id, revision,
       CASE state_value WHEN 1 THEN 'banned' WHEN 0 THEN 'unbanned' ELSE state_value END,
       expires, failure_generation
FROM previous;
INSERT INTO ban_sources SELECT * FROM old_ban_sources;
INSERT INTO deliveries SELECT * FROM old_deliveries;
INSERT INTO delivery_history SELECT * FROM old_delivery_history;
INSERT INTO delivery_attempts SELECT * FROM old_delivery_attempts;

DROP TABLE old_delivery_attempts;
DROP TABLE old_delivery_history;
DROP TABLE old_deliveries;
DROP TABLE old_ban_sources;
DROP TABLE old_decisions;

CREATE INDEX expiry ON decisions (state, expires);
CREATE INDEX ban_sources_by_expiry ON ban_sources (expires);
