from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


PREFERENCES_FILENAME = "audit-preferences.sqlite3"
PREFERENCES_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_preferences (
    username TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_at TEXT NOT NULL
) WITHOUT ROWID;
"""


@dataclass(frozen=True, slots=True)
class AuditPreference:
    enabled: bool
    updated_at: str | None


class AuditPreferenceStore:
    def __init__(self, data_dir: Path, busy_timeout_ms: int, timezone: Any) -> None:
        self.path = data_dir / PREFERENCES_FILENAME
        self.busy_timeout_ms = busy_timeout_ms
        self.timezone = timezone
        self._connection: sqlite3.Connection | None = None
        self._preferences: dict[str, AuditPreference] = {}

    def start(self) -> None:
        if self._connection is not None:
            return
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
        )
        connection.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.executescript(PREFERENCES_SCHEMA)
        connection.commit()
        self._preferences = {
            str(row[0]): AuditPreference(bool(row[1]), str(row[2]))
            for row in connection.execute(
                "SELECT username, enabled, updated_at FROM audit_preferences"
            )
        }
        self._connection = connection

    def close(self) -> None:
        if self._connection is None:
            return
        self._connection.close()
        self._connection = None
        self._preferences.clear()

    def get(self, username: str) -> AuditPreference:
        self._require_connection()
        return self._preferences.get(
            username,
            AuditPreference(enabled=False, updated_at=None),
        )

    def is_enabled(self, username: str) -> bool:
        return self.get(username).enabled

    def set_enabled(self, username: str, enabled: bool) -> AuditPreference:
        connection = self._require_connection()
        updated_at = datetime.now(self.timezone).isoformat()
        connection.execute(
            """
            INSERT INTO audit_preferences(username, enabled, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                enabled=excluded.enabled,
                updated_at=excluded.updated_at
            """,
            (username, int(enabled), updated_at),
        )
        connection.commit()
        preference = AuditPreference(enabled=enabled, updated_at=updated_at)
        self._preferences[username] = preference
        return preference

    def health(self) -> dict[str, Any]:
        self._require_connection()
        enabled_users = sum(
            preference.enabled for preference in self._preferences.values()
        )
        return {
            "path": str(self.path),
            "default_enabled": False,
            "enabled_users": enabled_users,
        }

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("audit preference store is not started")
        return self._connection
