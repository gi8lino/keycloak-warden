ALTER TABLE incidents ADD COLUMN group_by TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN group_key TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN group_identity_realm TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN distinct_by TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN window TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN effective_ban_until INTEGER;
ALTER TABLE incidents ADD COLUMN decision_id TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN decision_revision INTEGER NOT NULL DEFAULT 0;

DROP TABLE ban_observations;

CREATE TABLE target_identities (
    name TEXT PRIMARY KEY,
    identity TEXT NOT NULL
);
