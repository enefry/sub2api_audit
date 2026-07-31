from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import heapq
import json
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

from .cache import WeightedLRUCache, deep_sizeof
from .compression import decompress_bytes
from .dedupe import BodyProcessor, ContentKey, describe_binary
from .preview import (
    MAX_SEQUENCE_ITEMS,
    SEMANTIC_FIELDS,
    SEQUENCE_FIELDS,
    compact_request_body,
)
from .security import TokenFingerprint
from .token_resolver import TokenResolution


SCHEMA_VERSION = 1
MONTH_RE = re.compile(r"^audit-(\d{4}-(?:0[1-9]|1[0-2]))\.sqlite3$")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS token_dimensions (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    masked TEXT NOT NULL,
    source TEXT NOT NULL,
    resolver_status TEXT NOT NULL,
    api_key_id INTEGER,
    user_id INTEGER,
    key_name TEXT,
    username TEXT,
    first_seen_at_ms INTEGER NOT NULL,
    last_seen_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS uri_dimensions (
    id INTEGER PRIMARY KEY,
    uri TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS content_objects (
    object_hash TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    media_type TEXT NOT NULL,
    encoding TEXT NOT NULL,
    canonical_size INTEGER NOT NULL,
    compressed_size INTEGER NOT NULL,
    payload BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (object_hash, object_kind)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY,
    occurred_at_ms INTEGER NOT NULL,
    occurred_at_iso TEXT NOT NULL,
    method TEXT NOT NULL,
    model TEXT,
    token_dimension_id INTEGER,
    uri_dimension_id INTEGER NOT NULL,
    client_ip TEXT,
    user_agent TEXT,
    content_type TEXT,
    body_size INTEGER NOT NULL,
    body_sha256 TEXT NOT NULL,
    body_root_hash TEXT,
    body_root_kind TEXT,
    parse_status TEXT NOT NULL,
    resolver_status TEXT NOT NULL,
    FOREIGN KEY (token_dimension_id) REFERENCES token_dimensions(id),
    FOREIGN KEY (uri_dimension_id) REFERENCES uri_dimensions(id),
    FOREIGN KEY (body_root_hash, body_root_kind)
        REFERENCES content_objects(object_hash, object_kind)
);

CREATE TABLE IF NOT EXISTS request_content_refs (
    request_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    json_pointer TEXT NOT NULL,
    role TEXT NOT NULL,
    object_hash TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    PRIMARY KEY (request_id, ordinal),
    FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE RESTRICT,
    FOREIGN KEY (object_hash, object_kind)
        REFERENCES content_objects(object_hash, object_kind)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_requests_time_id
    ON requests (occurred_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_requests_model_time
    ON requests (model, occurred_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_requests_uri_time
    ON requests (uri_dimension_id, occurred_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_requests_token_time
    ON requests (token_dimension_id, occurred_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_token_api_key
    ON token_dimensions (api_key_id);
CREATE INDEX IF NOT EXISTS idx_token_user
    ON token_dimensions (user_id);
CREATE INDEX IF NOT EXISTS idx_refs_object
    ON request_content_refs (object_hash, object_kind);
"""


@dataclass(frozen=True, slots=True)
class RequestMetadata:
    occurred_at: datetime
    method: str
    uri: str
    client_ip: str | None
    user_agent: str | None
    content_type: str | None
    body_size: int
    body_sha256: str


@dataclass(frozen=True, slots=True)
class IngestResult:
    month: str
    request_id: int
    sealed_path: Path | None = None


@dataclass(frozen=True, slots=True)
class QueryFilters:
    start_ms: int
    end_ms: int
    model: str | None = None
    uri: str | None = None
    token: str | None = None
    key_name: str | None = None
    username: str | None = None


def month_from_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m")


def database_path(data_dir: Path, month: str) -> Path:
    if not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", month):
        raise ValueError("invalid month")
    return data_dir / f"audit-{month}.sqlite3"


def _open_database(
    path: Path, busy_timeout_ms: int, *, writable: bool
) -> sqlite3.Connection:
    if writable:
        connection = sqlite3.connect(path, timeout=busy_timeout_ms / 1000)
    else:
        uri = f"file:{path}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=busy_timeout_ms / 1000)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    if writable:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.executescript(SCHEMA_SQL)
        connection.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        connection.commit()
    return connection


def _encode_cursor(timestamp_ms: int, month: str, request_id: int) -> str:
    raw = json.dumps(
        {"t": timestamp_ms, "m": month, "i": request_id},
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(value: str | None) -> tuple[int, str, int] | None:
    if not value:
        return None
    try:
        padding = "=" * (-len(value) % 4)
        decoded = json.loads(
            base64.urlsafe_b64decode(value + padding).decode("utf-8")
        )
        timestamp = int(decoded["t"])
        month = str(decoded["m"])
        request_id = int(decoded["i"])
        database_path(Path("."), month)
        if timestamp < 0 or request_id < 1:
            raise ValueError
        return timestamp, month, request_id
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("invalid cursor") from exc


class MonthlyStorage:
    def __init__(
        self,
        data_dir: Path,
        busy_timeout_ms: int,
        timezone: Any,
        on_sealed: Callable[[Path], None] | None = None,
        read_workers: int = 2,
        cache_bytes: int = 128 * 1024 * 1024,
        full_cache_ttl_seconds: int = 120,
    ):
        self.data_dir = data_dir
        self.busy_timeout_ms = busy_timeout_ms
        self.timezone = timezone
        self.on_sealed = on_sealed
        self._lock = asyncio.Lock()
        self._connection: sqlite3.Connection | None = None
        self._current_month: str | None = None
        self._reader_pool = ThreadPoolExecutor(
            max_workers=max(1, int(read_workers)),
            thread_name_prefix="audit-reader",
        )
        self._reader_pool_closed = False
        cache_bytes = max(0, int(cache_bytes))
        self._cache = WeightedLRUCache(
            cache_bytes,
            max_item_bytes=cache_bytes // 2,
        )
        self._full_cache_ttl_seconds = max(1, int(full_cache_ttl_seconds))

    async def start(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(self.timezone)
        async with self._lock:
            self._open_current(month_from_datetime(now))

    def _open_current(self, month: str) -> None:
        self._connection = _open_database(
            database_path(self.data_dir, month), self.busy_timeout_ms, writable=True
        )
        self._current_month = month

    async def close(self) -> None:
        async with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
        if not self._reader_pool_closed:
            self._reader_pool_closed = True
            shutdown = functools.partial(
                self._reader_pool.shutdown,
                wait=True,
                cancel_futures=True,
            )
            await asyncio.to_thread(shutdown)
        self._cache.clear()

    async def _run_read(self, function: Callable[..., Any], *args: Any) -> Any:
        if self._reader_pool_closed:
            raise RuntimeError("storage is closed")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._reader_pool,
            functools.partial(function, *args),
        )

    @property
    def current_month(self) -> str | None:
        return self._current_month

    def _rotate_if_needed(self, month: str) -> Path | None:
        if self._current_month == month:
            return None
        if self._current_month is not None and month < self._current_month:
            raise RuntimeError("refusing to rotate backwards into a sealed month")
        previous_month = self._current_month
        previous_connection = self._connection

        # Create the new writer before closing/sealing the previous month.
        new_connection = _open_database(
            database_path(self.data_dir, month), self.busy_timeout_ms, writable=True
        )
        self._connection = new_connection
        self._current_month = month

        sealed_path: Path | None = None
        if previous_connection is not None and previous_month is not None:
            previous_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            result = previous_connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                previous_connection.close()
                raise RuntimeError(f"integrity check failed for {previous_month}")
            previous_connection.close()
            sealed_path = database_path(self.data_dir, previous_month)
        return sealed_path

    def _store_content(
        self,
        connection: sqlite3.Connection,
        inserted: list[ContentKey],
        now_ms: int,
        object_hash: str,
        object_kind: str,
        media_type: str,
        encoding: str,
        payload: bytes,
        canonical_size: int,
    ) -> ContentKey:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO content_objects(
                object_hash, object_kind, media_type, encoding,
                canonical_size, compressed_size, payload, created_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                object_hash,
                object_kind,
                media_type,
                encoding,
                canonical_size,
                len(payload),
                payload,
                now_ms,
            ),
        )
        if cursor.rowcount:
            inserted.append((object_hash, object_kind))
        return object_hash, object_kind

    def _ingest_sync(
        self,
        body_path: Path,
        metadata: RequestMetadata,
        token: TokenFingerprint | None,
        resolution: TokenResolution,
    ) -> IngestResult:
        month = month_from_datetime(metadata.occurred_at.astimezone(self.timezone))
        sealed_path = self._rotate_if_needed(month)
        connection = self._connection
        if connection is None:
            raise RuntimeError("storage is not started")
        now_ms = int(metadata.occurred_at.timestamp() * 1000)
        inserted: list[ContentKey] = []
        connection.execute("BEGIN IMMEDIATE")
        try:
            token_id: int | None = None
            if token is not None:
                connection.execute(
                    """
                    INSERT INTO token_dimensions(
                        fingerprint, masked, source, resolver_status,
                        api_key_id, user_id, key_name, username,
                        first_seen_at_ms, last_seen_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                        last_seen_at_ms=excluded.last_seen_at_ms,
                        resolver_status=CASE
                            WHEN excluded.resolver_status='resolved'
                            THEN excluded.resolver_status
                            ELSE token_dimensions.resolver_status
                        END,
                        api_key_id=COALESCE(excluded.api_key_id, token_dimensions.api_key_id),
                        user_id=COALESCE(excluded.user_id, token_dimensions.user_id),
                        key_name=COALESCE(excluded.key_name, token_dimensions.key_name),
                        username=COALESCE(excluded.username, token_dimensions.username)
                    """,
                    (
                        token.fingerprint,
                        token.masked,
                        token.source,
                        resolution.status,
                        resolution.api_key_id,
                        resolution.user_id,
                        resolution.key_name,
                        resolution.username,
                        now_ms,
                        now_ms,
                    ),
                )
                token_id = int(
                    connection.execute(
                        "SELECT id FROM token_dimensions WHERE fingerprint=?",
                        (token.fingerprint,),
                    ).fetchone()[0]
                )

            connection.execute(
                "INSERT OR IGNORE INTO uri_dimensions(uri) VALUES(?)",
                (metadata.uri,),
            )
            uri_id = int(
                connection.execute(
                    "SELECT id FROM uri_dimensions WHERE uri=?", (metadata.uri,)
                ).fetchone()[0]
            )

            processor = BodyProcessor(
                lambda object_hash,
                object_kind,
                media_type,
                encoding,
                payload,
                canonical_size: self._store_content(
                    connection,
                    inserted,
                    now_ms,
                    object_hash,
                    object_kind,
                    media_type,
                    encoding,
                    payload,
                    canonical_size,
                )
            )
            processed = processor.process(body_path, metadata.content_type)
            cursor = connection.execute(
                """
                INSERT INTO requests(
                    occurred_at_ms, occurred_at_iso, method, model,
                    token_dimension_id, uri_dimension_id, client_ip, user_agent,
                    content_type, body_size, body_sha256, body_root_hash,
                    body_root_kind, parse_status, resolver_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_ms,
                    metadata.occurred_at.isoformat(),
                    metadata.method[:32],
                    processed.model,
                    token_id,
                    uri_id,
                    metadata.client_ip,
                    metadata.user_agent,
                    metadata.content_type,
                    metadata.body_size,
                    metadata.body_sha256,
                    processed.root_hash,
                    processed.root_kind,
                    processed.parse_status,
                    resolution.status,
                ),
            )
            request_id = int(cursor.lastrowid)
            inserted_keys = set(inserted)
            referenced_keys: set[ContentKey] = set()
            new_references = []
            for ref in processed.references:
                key = (ref.object_hash, ref.object_kind)
                if key not in inserted_keys or key in referenced_keys:
                    continue
                referenced_keys.add(key)
                new_references.append(ref)
            connection.executemany(
                """
                INSERT INTO request_content_refs(
                    request_id, ordinal, json_pointer, role,
                    object_hash, object_kind
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        request_id,
                        ref.ordinal,
                        ref.pointer,
                        ref.role,
                        ref.object_hash,
                        ref.object_kind,
                    )
                    for ref in new_references
                ],
            )
            # Remove objects produced by a failed partial JSON parse.
            for object_hash, object_kind in inserted:
                connection.execute(
                    """
                    DELETE FROM content_objects
                    WHERE object_hash=? AND object_kind=?
                      AND NOT EXISTS (
                        SELECT 1 FROM request_content_refs
                        WHERE object_hash=? AND object_kind=?
                      )
                    """,
                    (object_hash, object_kind, object_hash, object_kind),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        return IngestResult(month, request_id, sealed_path)

    async def ingest(
        self,
        body_path: Path,
        metadata: RequestMetadata,
        token: TokenFingerprint | None,
        resolution: TokenResolution,
    ) -> IngestResult:
        async with self._lock:
            # SQLite is intentionally kept on the single Uvicorn event-loop thread.
            # This also guarantees one writer without relying on driver thread affinity.
            result = self._ingest_sync(body_path, metadata, token, resolution)
        if result.sealed_path is not None and self.on_sealed is not None:
            self.on_sealed(result.sealed_path)
        return result

    def _available_months(self) -> list[tuple[str, Path]]:
        result: list[tuple[str, Path]] = []
        if not self.data_dir.exists():
            return result
        for path in self.data_dir.iterdir():
            match = MONTH_RE.match(path.name)
            if match and path.is_file():
                result.append((match.group(1), path))
        result.sort(reverse=True)
        return result

    def _query_one_month(
        self,
        month: str,
        path: Path,
        filters: QueryFilters,
        cursor: tuple[int, str, int] | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        connection = _open_database(path, self.busy_timeout_ms, writable=False)
        try:
            conditions = ["r.occurred_at_ms>=?", "r.occurred_at_ms<?"]
            parameters: list[Any] = [filters.start_ms, filters.end_ms]
            if filters.model:
                conditions.append("r.model=?")
                parameters.append(filters.model)
            if filters.uri:
                conditions.append("u.uri LIKE ? ESCAPE '\\'")
                escaped = (
                    filters.uri.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                parameters.append(f"%{escaped}%")
            if filters.token:
                conditions.append("t.masked LIKE ? ESCAPE '\\'")
                escaped = (
                    filters.token.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                parameters.append(f"%{escaped}%")
            if filters.key_name:
                conditions.append("t.key_name=?")
                parameters.append(filters.key_name)
            if filters.username:
                conditions.append("t.username=?")
                parameters.append(filters.username)
            if cursor:
                timestamp, cursor_month, request_id = cursor
                if month < cursor_month:
                    conditions.append("r.occurred_at_ms<=?")
                    parameters.append(timestamp)
                elif month == cursor_month:
                    conditions.append(
                        "(r.occurred_at_ms<? OR "
                        "(r.occurred_at_ms=? AND r.id<?))"
                    )
                    parameters.extend((timestamp, timestamp, request_id))
                else:
                    conditions.append("r.occurred_at_ms<?")
                    parameters.append(timestamp)
            parameters.append(limit)
            rows = connection.execute(
                f"""
                SELECT
                    r.id, r.occurred_at_ms, r.occurred_at_iso, r.method,
                    r.model, r.client_ip, r.content_type, r.body_size,
                    r.parse_status, r.resolver_status, u.uri,
                    t.masked AS token_masked, t.api_key_id, t.user_id,
                    t.key_name, t.username
                FROM requests AS r
                JOIN uri_dimensions AS u ON u.id=r.uri_dimension_id
                LEFT JOIN token_dimensions AS t ON t.id=r.token_dimension_id
                WHERE {" AND ".join(conditions)}
                ORDER BY r.occurred_at_ms DESC, r.id DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            return [{**dict(row), "month": month} for row in rows]
        finally:
            connection.close()

    def _query_sync(
        self,
        filters: QueryFilters,
        cursor: tuple[int, str, int] | None,
        limit: int,
    ) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []
        for month, path in self._available_months():
            first_ms = int(
                datetime.strptime(month, "%Y-%m")
                .replace(tzinfo=self.timezone)
                .timestamp()
                * 1000
            )
            if first_ms >= filters.end_ms:
                continue
            candidates.extend(
                self._query_one_month(month, path, filters, cursor, limit + 1)
            )
        rows = heapq.nlargest(
            limit + 1,
            candidates,
            key=lambda row: (row["occurred_at_ms"], row["month"], row["id"]),
        )
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = _encode_cursor(
                last["occurred_at_ms"], last["month"], last["id"]
            )
        return {"items": rows, "next_cursor": next_cursor}

    async def query(
        self,
        filters: QueryFilters,
        cursor: tuple[int, str, int] | None,
        limit: int,
    ) -> dict[str, Any]:
        return await self._run_read(
            self._query_sync,
            filters,
            cursor,
            min(max(limit, 1), 200),
        )

    def _decode_object(
        self,
        connection: sqlite3.Connection,
        key: ContentKey,
    ) -> tuple[str, Any]:
        cache_key = ("object", *key)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        row = connection.execute(
            """
            SELECT media_type, encoding, canonical_size, payload
            FROM content_objects
            WHERE object_hash=? AND object_kind=?
            """,
            key,
        ).fetchone()
        if row is None:
            raise ValueError("missing content object")
        raw = decompress_bytes(
            row["encoding"], row["payload"], int(row["canonical_size"])
        )
        value = raw if key[1] == "binary" else json.loads(raw)
        decoded = (str(row["media_type"]), value)
        self._cache.put(
            cache_key,
            decoded,
            deep_sizeof(cache_key) + deep_sizeof(decoded),
        )
        return decoded

    def _load_object(
        self,
        connection: sqlite3.Connection,
        key: ContentKey,
        cache: dict[ContentKey, Any],
        depth: int = 0,
    ) -> Any:
        if depth > 100:
            raise ValueError("content reference depth exceeded")
        if key in cache:
            return cache[key]
        media_type, value = self._decode_object(connection, key)
        if key[1] == "binary":
            result = describe_binary(media_type, value)
        else:
            if key[1] == "raw_json":
                result = value
            elif key[1] == "template_json":
                result = self._render_template(
                    connection, value, cache, depth + 1
                )
            else:
                raise ValueError("unknown content object kind")
        cache[key] = result
        return result

    @staticmethod
    def _template_fields(template: Any) -> list[tuple[str, dict[str, Any]]]:
        if not isinstance(template, dict) or template.get("format") != "object_v1":
            raise ValueError("unknown template format")
        fields = template.get("fields")
        if not isinstance(fields, list):
            raise ValueError("invalid template fields")
        result: list[tuple[str, dict[str, Any]]] = []
        for item in fields:
            if not isinstance(item, list) or len(item) != 2:
                raise ValueError("invalid template field")
            key, descriptor = item
            if not isinstance(key, str) or not isinstance(descriptor, dict):
                raise ValueError("invalid template field")
            result.append((key, descriptor))
        return result

    def _render_descriptor(
        self,
        connection: sqlite3.Connection,
        descriptor: dict[str, Any],
        cache: dict[ContentKey, Any],
        depth: int,
    ) -> Any:
        if set(descriptor) == {"value"}:
            return descriptor["value"]
        if set(descriptor) == {"ref"}:
            reference = descriptor["ref"]
            if not (
                isinstance(reference, list)
                and len(reference) == 2
                and all(isinstance(item, str) for item in reference)
            ):
                raise ValueError("invalid content reference")
            return self._load_object(
                connection, (reference[0], reference[1]), cache, depth + 1
            )
        if set(descriptor) == {"array"} and isinstance(descriptor["array"], list):
            return [
                self._render_descriptor(connection, item, cache, depth + 1)
                for item in descriptor["array"]
            ]
        raise ValueError("invalid template descriptor")

    def _render_template(
        self,
        connection: sqlite3.Connection,
        template: Any,
        cache: dict[ContentKey, Any],
        depth: int,
    ) -> Any:
        if depth > 100:
            raise ValueError("invalid template")
        result: dict[str, Any] = {}
        for key, descriptor in self._template_fields(template):
            result[key] = self._render_descriptor(
                connection, descriptor, cache, depth + 1
            )
        return result

    def _load_compact_body(
        self,
        connection: sqlite3.Connection,
        root_key: ContentKey,
    ) -> Any:
        if root_key[1] != "template_json":
            return compact_request_body(
                self._load_object(connection, root_key, {})
            )

        _, template = self._decode_object(connection, root_key)
        fields = self._template_fields(template)
        field_map = {key: descriptor for key, descriptor in fields}
        top_level_fields = list(dict.fromkeys(key for key, _ in fields))
        rendered_cache: dict[ContentKey, Any] = {}
        selected: dict[str, Any] = {}

        model_descriptor = field_map.get("model")
        if model_descriptor is not None:
            selected["model"] = self._render_descriptor(
                connection,
                model_descriptor,
                rendered_cache,
                1,
            )

        sequence_total: int | None = None
        for field in SEQUENCE_FIELDS:
            descriptor = field_map.get(field)
            if (
                descriptor is None
                or set(descriptor) != {"array"}
                or not isinstance(descriptor["array"], list)
            ):
                continue
            sequence = descriptor["array"]
            selected[field] = [
                self._render_descriptor(
                    connection,
                    item,
                    rendered_cache,
                    1,
                )
                for item in sequence[-MAX_SEQUENCE_ITEMS:]
            ]
            sequence_total = len(sequence)
            break
        else:
            for field in SEMANTIC_FIELDS:
                descriptor = field_map.get(field)
                if descriptor is not None:
                    selected[field] = self._render_descriptor(
                        connection,
                        descriptor,
                        rendered_cache,
                        1,
                    )

        return compact_request_body(
            selected,
            sequence_total=sequence_total,
            top_level_fields=top_level_fields,
        )

    def _detail_sync(
        self,
        month: str,
        request_id: int,
        view: Literal["compact", "full"] = "full",
        required_username: str | None = None,
    ) -> dict[str, Any] | None:
        path = database_path(self.data_dir, month)
        if not path.is_file():
            return None
        connection = _open_database(path, self.busy_timeout_ms, writable=False)
        try:
            conditions = ["r.id=?"]
            parameters: list[Any] = [request_id]
            if required_username is not None:
                conditions.append("t.username=?")
                parameters.append(required_username)
            row = connection.execute(
                f"""
                SELECT
                    r.*, u.uri, t.masked AS token_masked, t.source AS token_source,
                    t.api_key_id, t.user_id, t.key_name, t.username
                FROM requests AS r
                JOIN uri_dimensions AS u ON u.id=r.uri_dimension_id
                LEFT JOIN token_dimensions AS t ON t.id=r.token_dimension_id
                WHERE {" AND ".join(conditions)}
                """,
                parameters,
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["month"] = month
            result.pop("token_dimension_id", None)
            result.pop("uri_dimension_id", None)
            root_hash = result.pop("body_root_hash", None)
            root_kind = result.pop("body_root_kind", None)
            if root_hash and root_kind:
                root_key = (root_hash, root_kind)
                if view == "compact":
                    result["body"] = self._load_compact_body(
                        connection,
                        root_key,
                    )
                else:
                    result["body"] = self._load_object(connection, root_key, {})
            else:
                result["body"] = (
                    compact_request_body(None) if view == "compact" else None
                )
            result["body_view"] = view
            return result
        finally:
            connection.close()

    def _detail_json_sync(
        self,
        month: str,
        request_id: int,
        view: Literal["compact", "full"],
        required_username: str | None = None,
    ) -> bytes | None:
        cache_key = (view, month, request_id, required_username)
        if required_username is not None:
            path = database_path(self.data_dir, month)
            if not path.is_file():
                return None
            connection = _open_database(path, self.busy_timeout_ms, writable=False)
            try:
                visible = connection.execute(
                    """
                    SELECT 1
                    FROM requests AS r
                    JOIN token_dimensions AS t ON t.id=r.token_dimension_id
                    WHERE r.id=? AND t.username=?
                    """,
                    (request_id, required_username),
                ).fetchone()
            finally:
                connection.close()
            if visible is None:
                return None
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        result = self._detail_sync(
            month,
            request_id,
            view,
            required_username,
        )
        if result is None:
            return None
        payload = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        payload_weight = deep_sizeof(payload) + deep_sizeof(cache_key)
        if view == "full":
            self._cache.put(
                cache_key,
                payload,
                payload_weight,
                ttl_seconds=self._full_cache_ttl_seconds,
                group="full",
                max_group_entries=2,
            )
        else:
            self._cache.put(cache_key, payload, payload_weight)
        return payload

    async def detail(
        self,
        month: str,
        request_id: int,
        view: Literal["compact", "full"] = "full",
        required_username: str | None = None,
    ) -> dict[str, Any] | None:
        return await self._run_read(
            self._detail_sync,
            month,
            request_id,
            view,
            required_username,
        )

    async def detail_json(
        self,
        month: str,
        request_id: int,
        view: Literal["compact", "full"],
        required_username: str | None = None,
    ) -> bytes | None:
        cache_key = (view, month, request_id, required_username)
        if required_username is None:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached
        return await self._run_read(
            self._detail_json_sync,
            month,
            request_id,
            view,
            required_username,
        )

    def _months_sync(
        self,
        required_username: str | None = None,
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for month, path in self._available_months():
            connection = _open_database(path, self.busy_timeout_ms, writable=False)
            try:
                if required_username is None:
                    count = int(
                        connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
                    )
                else:
                    count = int(
                        connection.execute(
                            """
                            SELECT COUNT(*)
                            FROM requests AS r
                            JOIN token_dimensions AS t ON t.id=r.token_dimension_id
                            WHERE t.username=?
                            """,
                            (required_username,),
                        ).fetchone()[0]
                    )
                schema_row = connection.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()
            finally:
                connection.close()
            if required_username is not None and count == 0:
                continue
            sidecar = path.with_suffix(".archive.json")
            archive_status: dict[str, Any] | None = None
            if sidecar.is_file():
                try:
                    archive_status = json.loads(sidecar.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    archive_status = {"status": "invalid_sidecar"}
            result.append(
                {
                    "month": month,
                    "current": month == self._current_month,
                    "records": count,
                    "size_bytes": (
                        path.stat().st_size if required_username is None else None
                    ),
                    "schema_version": (
                        int(schema_row[0]) if schema_row is not None else None
                    ),
                    "archive": archive_status if required_username is None else None,
                }
            )
        return result

    async def months(
        self,
        required_username: str | None = None,
    ) -> list[dict[str, Any]]:
        return await self._run_read(self._months_sync, required_username)

    def storage_health(self) -> dict[str, Any]:
        return {
            "current_month": self._current_month,
            "data_dir": str(self.data_dir),
            "writer_open": self._connection is not None,
            "read_cache": self._cache.stats(),
        }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
