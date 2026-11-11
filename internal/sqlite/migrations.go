package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migration identifies one ordered, embedded SQL migration.
type migration struct {
	// version orders this embedded database migration.
	version int
	// name is the embedded migration SQL filename.
	name string
	// replacesThrough is the highest historical migration consolidated into a baseline.
	replacesThrough int
}

// migrate applies each unapplied migration and records its version atomically.
func migrate(ctx context.Context, db *sql.DB) error {
	return migrateFrom(ctx, db, migrationFiles)
}

// migrateFrom plans and applies the supplied migrations without changing the database on invalid input.
func migrateFrom(ctx context.Context, db *sql.DB, files fs.FS) error {
	planned, err := planMigrations(files)
	if err != nil {
		return err
	}
	return applyMigrations(ctx, db, files, planned)
}

// planMigrations reads and orders the available migrations before starting a transaction.
func planMigrations(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, "migrations")
	if err != nil {
		return nil, err
	}

	planned := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		item, err := parseMigration(files, entry.Name())
		if err != nil {
			return nil, err
		}
		planned = append(planned, item)
	}
	if len(planned) == 0 {
		return nil, fmt.Errorf("no SQL migrations were embedded")
	}

	slices.SortFunc(planned, func(a, b migration) int { return a.version - b.version })
	for index := 1; index < len(planned); index++ {
		if planned[index-1].version == planned[index].version {
			return nil, fmt.Errorf("duplicate migration version %d", planned[index].version)
		}
	}
	return planned, nil
}

// parseMigration validates a versioned filename and its optional baseline version fence.
func parseMigration(files fs.FS, name string) (migration, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return migration{}, fmt.Errorf("invalid migration name %q", name)
	}

	version, err := strconv.Atoi(prefix)
	if err != nil || version < 1 {
		return migration{}, fmt.Errorf("invalid migration version in %q", name)
	}

	item := migration{version: version, name: name}
	if !strings.HasSuffix(name, "_baseline.sql") {
		return item, nil
	}

	body, err := fs.ReadFile(files, "migrations/"+name)
	if err != nil {
		return migration{}, err
	}
	item.replacesThrough, err = baselineReplacesThrough(body)
	if err != nil {
		return migration{}, fmt.Errorf("migration %q: %w", name, err)
	}
	if item.replacesThrough != item.version-1 {
		return migration{}, fmt.Errorf("migration %q: baseline must replace through version %d", name, item.version-1)
	}
	return item, nil
}

// applyMigrations records every unapplied migration in a single atomic transaction.
func applyMigrations(ctx context.Context, db *sql.DB, files fs.FS, planned []migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
)
`); err != nil {
		return err
	}

	var databaseVersion int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&databaseVersion); err != nil {
		return err
	}
	if supportedVersion := planned[len(planned)-1].version; databaseVersion > int64(supportedVersion) {
		return fmt.Errorf("database schema version %d is newer than supported version %d", databaseVersion, supportedVersion)
	}

	for _, item := range planned {
		var applied bool
		if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM schema_migrations
    WHERE version = ?
)
`, item.version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		if err := applyMigration(ctx, tx, files, item, databaseVersion); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// applyMigration executes an unapplied migration or adopts its baseline after verifying the version fence.
func applyMigration(ctx context.Context, tx *sql.Tx, files fs.FS, item migration, databaseVersion int64) error {
	// Historical databases that reached the previous version already contain the
	// baseline schema. Never replay its CREATE TABLE statements over their data.
	if item.replacesThrough > 0 && databaseVersion > 0 {
		if databaseVersion != int64(item.replacesThrough) {
			return fmt.Errorf("database schema version %d must be upgraded to %d before applying baseline %d", databaseVersion, item.replacesThrough, item.version)
		}
	} else {
		body, err := fs.ReadFile(files, "migrations/"+item.name)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("migration %q: %w", item.name, err)
		}
	}

	_, err := tx.ExecContext(ctx, `
INSERT INTO schema_migrations (version, applied_at)
VALUES (?, ?)
`, item.version, time.Now().Unix())
	return err
}

// baselineReplacesThrough reads the version fence generated by the consolidation script.
func baselineReplacesThrough(body []byte) (int, error) {
	const marker = "-- warden:replaces-through="
	for line := range strings.SplitSeq(string(body), "\n") {
		if value, ok := strings.CutPrefix(line, marker); ok {
			version, err := strconv.Atoi(value)
			if err != nil || version < 1 {
				return 0, fmt.Errorf("invalid baseline replaces-through marker %q", value)
			}
			return version, nil
		}
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "--") {
			break
		}
	}
	return 0, fmt.Errorf("missing baseline replaces-through marker")
}
