CREATE TABLE delivery_history (
    ip TEXT NOT NULL REFERENCES decisions(ip) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    destination TEXT NOT NULL,
    desired_state TEXT,
    status TEXT NOT NULL,
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

-- Older acknowledgements carry no historical state, timestamp or attempt details.
INSERT INTO delivery_history (ip, revision, destination, status)
SELECT ip, acknowledged, destination, 'delivered'
FROM deliveries
WHERE acknowledged > 0;

INSERT OR REPLACE INTO delivery_history (ip, revision, destination, desired_state, status)
SELECT d.ip, d.revision, q.destination,
       CASE WHEN d.active THEN 'banned' ELSE 'unbanned' END,
       CASE WHEN q.acknowledged = d.revision THEN 'delivered'
            WHEN q.retry_at > 0 THEN 'retrying' ELSE 'pending' END
FROM deliveries q JOIN decisions d USING (ip)
WHERE d.revision > 0;
