-- Add a permanent insertion sequence for stable history paging, including after VACUUM.
-- Preserve existing revision events, including their original commit timestamps.
CREATE TABLE decision_revisions_ordered (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL REFERENCES decisions(ip) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (state IN ('banned', 'unbanned')),
    expires INTEGER NOT NULL,
    changed_at INTEGER NOT NULL,
    sources_json TEXT NOT NULL,
    cause TEXT NOT NULL CHECK (cause IN ('automatic', 'manual', 'release', 'expiry', 'reconciled')),
    UNIQUE (ip, revision)
);

INSERT INTO decision_revisions_ordered (ip, revision, state, expires, changed_at, sources_json, cause)
SELECT ip, revision, state, expires, changed_at, sources_json, cause
FROM decision_revisions
ORDER BY changed_at ASC, ip, revision ASC;

DROP TABLE decision_revisions;
ALTER TABLE decision_revisions_ordered RENAME TO decision_revisions;
CREATE INDEX decision_revisions_recent
    ON decision_revisions (changed_at DESC, ip, revision DESC);
CREATE INDEX decision_revisions_by_state
    ON decision_revisions (state, changed_at DESC, ip, revision DESC);
