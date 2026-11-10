"""Regression tests for SQLite migration consolidation and cleanup."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from baseline import BaselineError, cleanup, merge, migrations_in


class MigrationBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.migrations = root / "migrations"
        self.generated = root / "generated"
        self.migrations.mkdir()
        (self.migrations / "0001_initial.sql").write_text(
            "CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT);\n"
            "INSERT INTO items VALUES(1, 'initial');\n", encoding="utf-8"
        )
        (self.migrations / "0002_index.sql").write_text(
            "CREATE INDEX items_by_value ON items(value);\n", encoding="utf-8"
        )

    def test_merge_preserves_source_migrations_and_seed_rows(self):
        merge(self.migrations, self.generated)
        self.assertTrue((self.migrations / "0001_initial.sql").exists())
        self.assertTrue((self.migrations / "0002_index.sql").exists())
        baseline = (self.generated /
                    "0003_baseline.sql").read_text(encoding="utf-8")
        self.assertIn("-- warden:replaces-through=2", baseline)
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript(baseline)
        self.assertEqual(db.execute(
            "SELECT value FROM items WHERE id=1").fetchone(), ("initial",))

    def test_cleanup_replaces_only_sql_migrations(self):
        extra = self.migrations / "notes.txt"
        extra.write_text("preserve this", encoding="utf-8")
        merge(self.migrations, self.generated)
        cleanup(self.migrations, self.generated)
        self.assertEqual([path.name for _, path in migrations_in(
            self.migrations)], ["0003_baseline.sql"])
        self.assertEqual(extra.read_text(encoding="utf-8"), "preserve this")
        self.assertFalse((self.generated / "0003_baseline.sql").exists())
        with self.assertRaisesRegex(BaselineError, "No newer migrations"):
            merge(self.migrations, self.generated)

    def test_later_migration_creates_another_baseline(self):
        merge(self.migrations, self.generated)
        cleanup(self.migrations, self.generated)
        (self.migrations / "0004_extra.sql").write_text(
            "ALTER TABLE items ADD COLUMN detail TEXT DEFAULT '';\n", encoding="utf-8"
        )
        merge(self.migrations, self.generated)
        self.assertTrue((self.generated / "0005_baseline.sql").exists())
        cleanup(self.migrations, self.generated)
        self.assertEqual([path.name for _, path in migrations_in(
            self.migrations)], ["0005_baseline.sql"])

    def test_cleanup_rejects_stale_or_modified_baseline_without_deleting_sources(self):
        merge(self.migrations, self.generated)
        candidate = self.generated / "0003_baseline.sql"
        candidate.write_text(candidate.read_text(
            encoding="utf-8").replace("initial", "altered"), encoding="utf-8")
        with self.assertRaisesRegex(BaselineError, "differs"):
            cleanup(self.migrations, self.generated)
        self.assertTrue((self.migrations / "0001_initial.sql").exists())
        self.assertTrue((self.migrations / "0002_index.sql").exists())

    def test_duplicate_versions_are_rejected(self):
        (self.migrations / "0002_duplicate.sql").write_text("SELECT 1;\n", encoding="utf-8")
        with self.assertRaisesRegex(BaselineError, "duplicate"):
            merge(self.migrations, self.generated)

    def test_output_inside_migrations_is_rejected(self):
        with self.assertRaisesRegex(BaselineError, "outside migrations"):
            merge(self.migrations, self.migrations / "build")


if __name__ == "__main__":
    unittest.main()
