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
}

// migrate applies each unapplied migration and records its version atomically.
func migrate(ctx context.Context, db *sql.DB) error {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return err
	}

	planned := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return fmt.Errorf("invalid migration name %q", entry.Name())
		}

		version, err := strconv.Atoi(prefix)
		if err != nil || version < 1 {
			return fmt.Errorf("invalid migration version in %q", entry.Name())
		}

		planned = append(planned, migration{version: version, name: entry.Name()})
	}

	if len(planned) == 0 {
		return fmt.Errorf("no SQL migrations were embedded")
	}

	slices.SortFunc(planned, func(a, b migration) int { return a.version - b.version })

	for index := 1; index < len(planned); index++ {
		if planned[index-1].version == planned[index].version {
			return fmt.Errorf("duplicate migration version %d", planned[index].version)
		}
	}

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

		body, err := fs.ReadFile(migrationFiles, "migrations/"+item.name)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("migration %q: %w", item.name, err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO schema_migrations (version, applied_at)
VALUES (?, ?)
`, item.version, time.Now().Unix()); err != nil {
			return err
		}
	}

	return tx.Commit()
}
