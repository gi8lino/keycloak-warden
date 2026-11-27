-- Record every new effective decision revision, without fabricating timestamps
-- or reasons for decisions created before this migration.
CREATE TABLE decision_revisions (
    ip TEXT NOT NULL REFERENCES decisions (ip) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (state IN ('banned', 'unbanned')),
    expires INTEGER NOT NULL,
    changed_at INTEGER NOT NULL,
    sources_json TEXT NOT NULL,
    cause TEXT NOT NULL CHECK (cause IN ('automatic', 'manual', 'release', 'expiry', 'reconciled')),
    PRIMARY KEY (ip, revision)
);
CREATE INDEX decision_revisions_recent
    ON decision_revisions (changed_at DESC, ip, revision DESC);
CREATE INDEX decision_revisions_by_state
    ON decision_revisions (state, changed_at DESC, ip, revision DESC);
CREATE INDEX delivery_history_current_status
    ON delivery_history (status, ip, revision, destination);
