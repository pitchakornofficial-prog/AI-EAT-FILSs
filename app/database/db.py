"""
Database module for AI Storage Cleaner.

Uses SQLite to store scan results, classifications, and action logs.
All operations are local and do not require external database servers.
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


# Default database path inside the project directory
DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "storage_cleaner.db"


class Database:
    """SQLite database for scan results, classifications, and audit logs."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _init_db(self):
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id         TEXT PRIMARY KEY,
                target_path     TEXT NOT NULL,
                started_at      TEXT NOT NULL,
                completed_at    TEXT,
                total_items     INTEGER DEFAULT 0,
                total_size      INTEGER DEFAULT 0,
                status          TEXT DEFAULT 'running'
            );

            CREATE TABLE IF NOT EXISTS scan_items (
                item_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                full_path       TEXT NOT NULL,
                filename        TEXT NOT NULL,
                extension       TEXT,
                size_bytes      INTEGER DEFAULT 0,
                modified_time   TEXT,
                parent_folder   TEXT,
                app_name        TEXT,
                file_type       TEXT,
                is_directory    INTEGER DEFAULT 0,
                classification  TEXT DEFAULT 'UNKNOWN',
                confidence      REAL DEFAULT 0.0,
                reason          TEXT,
                classified_by   TEXT,
                ai_response     TEXT,
                created_at      TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS action_log (
                log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                action          TEXT NOT NULL,
                source_path     TEXT NOT NULL,
                dest_path       TEXT,
                size_bytes      INTEGER,
                classification  TEXT,
                reason          TEXT,
                user_confirmed  INTEGER DEFAULT 0,
                performed_at    TEXT NOT NULL,
                restored_at     TEXT,
                status          TEXT DEFAULT 'completed'
            );

            CREATE INDEX IF NOT EXISTS idx_scan_items_scan_id
                ON scan_items(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scan_items_classification
                ON scan_items(classification);
            CREATE INDEX IF NOT EXISTS idx_scan_items_size
                ON scan_items(size_bytes DESC);
            CREATE INDEX IF NOT EXISTS idx_action_log_action
                ON action_log(action);
        """)
        conn.commit()

    # ── Scan operations ──────────────────────────────────────────────

    def create_scan(self, scan_id: str, target_path: str) -> str:
        """Create a new scan record."""
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO scans (scan_id, target_path, started_at) VALUES (?, ?, ?)",
            (scan_id, target_path, datetime.now().isoformat()),
        )
        conn.commit()
        return scan_id

    def complete_scan(self, scan_id: str, total_items: int, total_size: int):
        """Mark a scan as completed."""
        conn = self._get_conn()
        conn.execute(
            """UPDATE scans
               SET completed_at = ?, total_items = ?, total_size = ?, status = 'completed'
               WHERE scan_id = ?""",
            (datetime.now().isoformat(), total_items, total_size, scan_id),
        )
        conn.commit()

    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Get scan details by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_latest_scan(self) -> Optional[dict]:
        """Get the most recent scan."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def list_scans(self, limit: int = 20) -> list[dict]:
        """List recent scans."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Scan item operations ─────────────────────────────────────────

    def add_scan_item(self, scan_id: str, item: dict):
        """Add a single scan item."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO scan_items
               (scan_id, full_path, filename, extension, size_bytes,
                modified_time, parent_folder, app_name, file_type,
                is_directory, classification, confidence, reason,
                classified_by, ai_response, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                item.get("full_path", ""),
                item.get("filename", ""),
                item.get("extension", ""),
                item.get("size_bytes", 0),
                item.get("modified_time", ""),
                item.get("parent_folder", ""),
                item.get("app_name", ""),
                item.get("file_type", ""),
                1 if item.get("is_directory", False) else 0,
                item.get("classification", "UNKNOWN"),
                item.get("confidence", 0.0),
                item.get("reason", ""),
                item.get("classified_by", ""),
                json.dumps(item.get("ai_response")) if item.get("ai_response") else None,
                datetime.now().isoformat(),
            ),
        )
        conn.commit()

    def add_scan_items_batch(self, scan_id: str, items: list[dict]):
        """Add multiple scan items in a single transaction."""
        conn = self._get_conn()
        rows = []
        now = datetime.now().isoformat()
        for item in items:
            rows.append((
                scan_id,
                item.get("full_path", ""),
                item.get("filename", ""),
                item.get("extension", ""),
                item.get("size_bytes", 0),
                item.get("modified_time", ""),
                item.get("parent_folder", ""),
                item.get("app_name", ""),
                item.get("file_type", ""),
                1 if item.get("is_directory", False) else 0,
                item.get("classification", "UNKNOWN"),
                item.get("confidence", 0.0),
                item.get("reason", ""),
                item.get("classified_by", ""),
                json.dumps(item.get("ai_response")) if item.get("ai_response") else None,
                now,
            ))
        conn.executemany(
            """INSERT INTO scan_items
               (scan_id, full_path, filename, extension, size_bytes,
                modified_time, parent_folder, app_name, file_type,
                is_directory, classification, confidence, reason,
                classified_by, ai_response, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        conn.commit()

    def update_item_classification(
        self,
        item_id: int,
        classification: str,
        confidence: float,
        reason: str,
        classified_by: str,
        ai_response: Optional[dict] = None,
    ):
        """Update the classification of a scan item."""
        conn = self._get_conn()
        conn.execute(
            """UPDATE scan_items
               SET classification = ?, confidence = ?, reason = ?,
                   classified_by = ?, ai_response = ?
               WHERE item_id = ?""",
            (
                classification,
                confidence,
                reason,
                classified_by,
                json.dumps(ai_response) if ai_response else None,
                item_id,
            ),
        )
        conn.commit()

    def get_scan_items(
        self,
        scan_id: str,
        classification: Optional[str] = None,
        min_size: int = 0,
        limit: int = 500,
    ) -> list[dict]:
        """Get scan items, optionally filtered by classification and size."""
        conn = self._get_conn()
        query = "SELECT * FROM scan_items WHERE scan_id = ? AND size_bytes >= ?"
        params: list = [scan_id, min_size]

        if classification:
            query += " AND classification = ?"
            params.append(classification)

        query += " ORDER BY size_bytes DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_unclassified_items(self, scan_id: str) -> list[dict]:
        """Get items that need AI classification."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM scan_items
               WHERE scan_id = ? AND classification = 'UNKNOWN'
               ORDER BY size_bytes DESC""",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_scan_summary(self, scan_id: str) -> dict:
        """Get a summary of scan results by classification."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT classification,
                      COUNT(*) as count,
                      SUM(size_bytes) as total_size
               FROM scan_items
               WHERE scan_id = ?
               GROUP BY classification
               ORDER BY total_size DESC""",
            (scan_id,),
        ).fetchall()
        return {
            row["classification"]: {
                "count": row["count"],
                "total_size": row["total_size"] or 0,
            }
            for row in rows
        }

    # ── Action log operations ────────────────────────────────────────

    def log_action(
        self,
        action: str,
        source_path: str,
        dest_path: Optional[str] = None,
        size_bytes: int = 0,
        classification: str = "",
        reason: str = "",
        user_confirmed: bool = False,
    ) -> int:
        """Log an action (quarantine, restore, delete) for audit trail."""
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO action_log
               (action, source_path, dest_path, size_bytes,
                classification, reason, user_confirmed, performed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                action,
                source_path,
                dest_path,
                size_bytes,
                classification,
                reason,
                1 if user_confirmed else 0,
                datetime.now().isoformat(),
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def get_action_log(self, limit: int = 100) -> list[dict]:
        """Get recent action log entries."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM action_log ORDER BY performed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Cleanup ──────────────────────────────────────────────────────

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
