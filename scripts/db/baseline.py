#!/usr/bin/env python3
"""Generate and install verified SQLite migration baselines for Warden."""

import argparse
import os
import re
import sqlite3
import tempfile
from pathlib import Path

MIGRATION_NAME = re.compile(r"^([0-9]+)_[^/]+\.sql$")
BASELINE_MARKER = "-- warden:replaces-through="


class BaselineError(Exception):
    """An input migration or generated baseline is unsafe to consolidate."""


def migrations_in(directory: Path) -> list[tuple[int, Path]]:
    """Return all SQL migrations in numeric order with unique positive versions."""
    if not directory.is_dir():
        raise BaselineError(f"Migration directory does not exist: {directory}")

    migrations = []
    versions = set()
    for path in directory.glob("*.sql"):
        match = MIGRATION_NAME.fullmatch(path.name)
        if not match:
            raise BaselineError(f"Invalid migration filename: {path.name}")
        version = int(match.group(1))
        if version == 0 or version in versions:
            raise BaselineError(f"Invalid or duplicate migration version {version}: {path.name}")
        if not path.is_file() or path.is_symlink():
            raise BaselineError(f"Migration must be a regular file: {path}")
        versions.add(version)
        migrations.append((version, path))

    if not migrations:
        raise BaselineError(f"No SQL migrations found in {directory}")
    migrations.sort()

    baselines = [(version, path) for version, path in migrations if path.name.endswith("_baseline.sql")]
    if len(baselines) > 1:
        raise BaselineError("Multiple baseline migrations found")
    if baselines and baselines[0][0] != migrations[0][0]:
        raise BaselineError("Existing baseline must be the earliest migration")
    return migrations


def newest_baseline(migrations: list[tuple[int, Path]]) -> int | None:
    """Return the current baseline version, if present."""
    for version, path in migrations:
        if path.name.endswith("_baseline.sql"):
            return version
    return None


def expected_baseline(migrations: list[tuple[int, Path]]) -> tuple[int, str]:
    """Choose the next revision without merging an unchanged baseline."""
    highest = migrations[-1][0]
    existing = newest_baseline(migrations)
    if existing is not None and highest == existing:
        raise BaselineError(f"No newer migrations to consolidate (baseline {existing})")
    return highest, f"{highest + 1:04d}_baseline.sql"


def compile_migrations(migrations: list[tuple[int, Path]]) -> sqlite3.Connection:
    """Apply migrations to a disposable, empty SQLite database."""
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        for _, path in migrations:
            print(f"Applying: {path.name}")
            try:
                connection.executescript(path.read_text(encoding="utf-8"))
            except sqlite3.Error as error:
                raise BaselineError(f"Failed to apply {path.name}: {error}") from error
            connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except BaseException:
        connection.close()
        raise


def render_baseline(connection: sqlite3.Connection, replaces_through: int) -> str:
    """Dump all application schema objects and seed data as executable SQL."""
    # SQLite iterdump includes transaction delimiters, but Go's migrator already
    # wraps migration execution in a transaction. Remove only those delimiters.
    statements = [
        statement for statement in connection.iterdump()
        if statement.strip() not in ("BEGIN TRANSACTION;", "COMMIT;")
    ]
    return (
        "-- Consolidated SQLite schema and seed data for Keycloak Warden.\n"
        f"{BASELINE_MARKER}{replaces_through}\n\n"
        + "\n".join(statements)
        + "\n"
    )


def baseline_replaces_through(sql: str) -> int:
    """Validate the baseline version marker consumed by Warden's Go loader."""
    for line in sql.splitlines():
        if line.startswith(BASELINE_MARKER):
            value = line.removeprefix(BASELINE_MARKER)
            if not value.isascii() or not value.isdigit() or int(value) < 1:
                raise BaselineError("Invalid baseline replaces-through marker")
            return int(value)
        if line.strip() and not line.lstrip().startswith("--"):
            break
    raise BaselineError("Missing baseline replaces-through marker")


def snapshot(connection: sqlite3.Connection) -> tuple:
    """Capture every persistent application schema object and table row."""
    schema = tuple(connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ))
    tables = [entry[1] for entry in schema if entry[0] == "table"]
    rows = []
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        data = connection.execute(f"SELECT * FROM {quoted}").fetchall()
        rows.append((table, tuple(sorted(data, key=repr))))
    return schema, tuple(rows)


def validate_baseline(sql: str, original: sqlite3.Connection) -> None:
    """Prove that the new file reproduces the migrations' schema and data."""
    candidate = sqlite3.connect(":memory:")
    candidate.execute("PRAGMA foreign_keys = ON")
    try:
        candidate.executescript(sql)
        violations = candidate.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise BaselineError(f"Generated baseline has foreign-key violations: {violations}")
        if snapshot(candidate) != snapshot(original):
            raise BaselineError("Generated baseline differs from the migrated database")
    except sqlite3.Error as error:
        raise BaselineError(f"Generated baseline cannot be applied: {error}") from error
    finally:
        candidate.close()


def separate_directories(migrations: Path, generated: Path) -> None:
    """Refuse an output directory inside the migration source tree."""
    if generated == migrations or migrations in generated.parents:
        raise BaselineError("Generated baseline directory must be outside migrations")


def merge(migrations_dir: Path, output_dir: Path) -> None:
    """Generate a validated baseline without modifying current migrations."""
    migrations_dir = migrations_dir.resolve(strict=True)
    output_dir = output_dir.resolve()
    separate_directories(migrations_dir, output_dir)
    migrations = migrations_in(migrations_dir)
    previous, name = expected_baseline(migrations)

    original = compile_migrations(migrations)
    try:
        baseline = render_baseline(original, previous)
        validate_baseline(baseline, original)
    finally:
        original.close()

    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output_dir,
                                     prefix=f".{name}.", suffix=".tmp", delete=False) as candidate:
        candidate.write(baseline)
        temp_file = Path(candidate.name)
    try:
        target = output_dir / name
        temp_file.replace(target)
        for old in output_dir.glob("*_baseline.sql"):
            if old != target:
                old.unlink()
    finally:
        temp_file.unlink(missing_ok=True)
    print(f"Validated baseline: {target}")


def cleanup(migrations_dir: Path, generated_dir: Path) -> None:
    """Install a freshly revalidated baseline and retain a rollback on failure."""
    migrations_dir = migrations_dir.resolve(strict=True)
    generated_dir = generated_dir.resolve(strict=True)
    separate_directories(migrations_dir, generated_dir)
    migrations = migrations_in(migrations_dir)
    previous, name = expected_baseline(migrations)
    generated = list(generated_dir.glob("*_baseline.sql"))
    if len(generated) != 1 or generated[0].name != name:
        raise BaselineError(f"Expected exactly one generated baseline named {name}")
    if generated[0].is_symlink():
        raise BaselineError("Generated baseline must be a regular file")

    sql = generated[0].read_text(encoding="utf-8")
    if baseline_replaces_through(sql) != previous:
        raise BaselineError("Generated baseline replaces-through version is stale")
    original = compile_migrations(migrations)
    try:
        validate_baseline(sql, original)
    finally:
        original.close()

    # Kumbuka-style cleanup: stage the verified baseline, preserve originals
    # until successful installation, and restore originals if anything fails.
    with tempfile.TemporaryDirectory(prefix="warden-migration-backup-", dir=migrations_dir) as backup_dir:
        backup = Path(backup_dir)
        staged = migrations_dir / (f".{name}.tmp.{os.getpid()}")
        try:
            staged.write_text(sql, encoding="utf-8")
            moved = []
            try:
                for _, old in migrations:
                    destination = backup / old.name
                    old.replace(destination)
                    moved.append(destination)
                staged.replace(migrations_dir / name)
            except BaseException:
                (migrations_dir / name).unlink(missing_ok=True)
                for previous_file in moved:
                    previous_file.replace(migrations_dir / previous_file.name)
                raise
        finally:
            staged.unlink(missing_ok=True)

    generated[0].unlink()
    print(f"Replaced {len(migrations)} migration(s) with {migrations_dir / name}")


def main() -> None:
    """Parse a Kumbuka-style merge or cleanup command."""
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    merge_command = subcommands.add_parser("merge", help="Generate and validate a new baseline")
    merge_command.add_argument("--migrations", type=Path, required=True)
    merge_command.add_argument("--output-dir", type=Path, required=True)
    cleanup_command = subcommands.add_parser("cleanup", help="Replace migrations with verified baseline")
    cleanup_command.add_argument("--migrations", type=Path, required=True)
    cleanup_command.add_argument("--generated-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "merge":
            merge(args.migrations, args.output_dir)
        else:
            cleanup(args.migrations, args.generated_dir)
    except (BaselineError, OSError) as error:
        parser.exit(1, f"Migration baseline error: {error}\n")


if __name__ == "__main__":
    main()
