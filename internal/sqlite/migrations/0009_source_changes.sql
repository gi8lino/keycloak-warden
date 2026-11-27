-- Audit persisted source mutations separately from effective decision revisions.
-- Triggers share the source transaction and never schedule a delivery revision.
CREATE TABLE source_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL REFERENCES decisions (ip) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('added', 'updated', 'removed')),
    expires INTEGER NOT NULL,
    reason TEXT NOT NULL,
    changed_at INTEGER NOT NULL
);
CREATE INDEX source_changes_by_ip ON source_changes (ip, id DESC);

CREATE TRIGGER source_changes_insert AFTER INSERT ON ban_sources
BEGIN
    INSERT INTO source_changes (
        ip,
        kind,
        action,
        expires,
        reason,
        changed_at
    )
    VALUES (
        NEW.ip,
        NEW.kind,
        'added',
        NEW.expires,
        NEW.reason,
        UNIXEPOCH('subsec') * 1000
    );
END;

CREATE TRIGGER source_changes_update AFTER UPDATE OF expires, reason ON ban_sources
WHEN NEW.expires != OLD.expires OR NEW.reason != OLD.reason
BEGIN
    INSERT INTO source_changes (
        ip,
        kind,
        action,
        expires,
        reason,
        changed_at
    )
    VALUES (
        NEW.ip,
        NEW.kind,
        'updated',
        NEW.expires,
        NEW.reason,
        UNIXEPOCH('subsec') * 1000
    );
END;

CREATE TRIGGER source_changes_delete AFTER DELETE ON ban_sources
BEGIN
    INSERT INTO source_changes (
        ip,
        kind,
        action,
        expires,
        reason,
        changed_at
    )
    VALUES (
        OLD.ip,
        OLD.kind,
        'removed',
        OLD.expires,
        OLD.reason,
        UNIXEPOCH('subsec') * 1000
    );
END;
