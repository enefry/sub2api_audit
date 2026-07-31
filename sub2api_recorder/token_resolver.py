from __future__ import annotations

import threading
import time
from dataclasses import dataclass

try:
    import psycopg
except ImportError:  # Runtime dependency; optional for local schema-only tests.
    psycopg = None


@dataclass(frozen=True, slots=True)
class TokenResolution:
    status: str
    api_key_id: int | None = None
    user_id: int | None = None
    key_name: str | None = None
    username: str | None = None


class ReadOnlyTokenResolver:
    """Looks up Sub2API tokens through a transaction-read-only PostgreSQL session."""

    def __init__(self, dsn: str | None, timeout_seconds: int, cache_seconds: int):
        self.dsn = dsn
        self.timeout_seconds = timeout_seconds
        self.cache_seconds = cache_seconds
        self._cache: dict[str, tuple[float, TokenResolution]] = {}
        self._lock = threading.Lock()
        self._last_health: tuple[float, bool, str | None] = (0.0, False, None)

    def _connection_kwargs(self) -> dict[str, object]:
        return {
            "connect_timeout": self.timeout_seconds,
            "options": (
                "-c default_transaction_read_only=on "
                f"-c statement_timeout={self.timeout_seconds * 1000}"
            ),
        }

    def resolve(self, token: str, fingerprint: str) -> TokenResolution:
        if not self.dsn:
            return TokenResolution("disabled")
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(fingerprint)
            if cached and cached[0] >= now:
                return cached[1]
        if psycopg is None:
            return TokenResolution("unavailable")
        try:
            with psycopg.connect(self.dsn, **self._connection_kwargs()) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SET TRANSACTION READ ONLY")
                    cursor.execute(
                        """
                        SELECT ak.id, ak.user_id, ak.name, u.username
                        FROM api_keys AS ak
                        LEFT JOIN users AS u ON u.id = ak.user_id
                        WHERE ak.key = %s AND ak.deleted_at IS NULL
                        LIMIT 1
                        """,
                        (token,),
                    )
                    row = cursor.fetchone()
            if row is None:
                result = TokenResolution("not_found")
            else:
                result = TokenResolution(
                    "resolved",
                    api_key_id=int(row[0]),
                    user_id=int(row[1]) if row[1] is not None else None,
                    key_name=str(row[2]) if row[2] is not None else None,
                    username=str(row[3]) if row[3] is not None else None,
                )
        except Exception:
            # Never include driver exception text: DSNs can contain credentials.
            result = TokenResolution("unavailable")
        if self.cache_seconds:
            with self._lock:
                self._cache[fingerprint] = (
                    now + self.cache_seconds,
                    result,
                )
        return result

    def health(self, max_cache_seconds: int = 15) -> tuple[bool, str | None]:
        if not self.dsn:
            return False, "disabled"
        now = time.monotonic()
        with self._lock:
            if self._last_health[0] + max_cache_seconds >= now:
                return self._last_health[1], self._last_health[2]
        if psycopg is None:
            result = (False, "driver_unavailable")
        else:
            try:
                with psycopg.connect(
                    self.dsn, **self._connection_kwargs()
                ) as connection:
                    with connection.cursor() as cursor:
                        cursor.execute("SET TRANSACTION READ ONLY")
                        cursor.execute("SELECT 1")
                        cursor.fetchone()
                result = (True, None)
            except Exception:
                result = (False, "unavailable")
        with self._lock:
            self._last_health = (now, result[0], result[1])
        return result

