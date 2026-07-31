from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

import pytest

from sub2api_recorder.security import fingerprint_token
from sub2api_recorder.storage import (
    MonthlyStorage,
    QueryFilters,
    RequestMetadata,
    database_path,
)
from sub2api_recorder.token_resolver import TokenResolution


def _write_body(path: Path, value: object) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return raw


def _metadata(settings, raw: bytes, uri: str = "/v1/responses?trace=1"):
    import hashlib

    return RequestMetadata(
        occurred_at=datetime.now(settings.timezone),
        method="POST",
        uri=uri,
        client_ip="192.0.2.10",
        user_agent="pytest",
        content_type="application/json",
        body_size=len(raw),
        body_sha256=hashlib.sha256(raw).hexdigest(),
    )


@pytest.mark.asyncio
async def test_history_deduplication_and_semantic_reconstruction(
    settings, tmp_path: Path
) -> None:
    storage = MonthlyStorage(
        settings.data_dir, settings.sqlite_busy_timeout_ms, settings.timezone
    )
    await storage.start()
    body1 = {
        "model": "gpt-test",
        "messages": [
            {"role": "system", "content": "Be exact."},
            {
                "role": "user",
                "content": [{"type": "text", "text": "你好"}],
            },
        ],
        "tools": [{"type": "function", "name": "lookup"}],
        "stream": True,
    }
    body2 = {
        **body1,
        "messages": [
            *body1["messages"],
            {"role": "assistant", "content": "收到"},
            {"role": "user", "content": "继续"},
        ],
    }
    path1 = tmp_path / "one.json"
    path2 = tmp_path / "two.json"
    raw1 = _write_body(path1, body1)
    raw2 = _write_body(path2, body2)
    plaintext = "sk-plaintext-must-not-appear-5678"
    token = fingerprint_token(plaintext, "authorization", settings.token_hmac_key)
    resolution = TokenResolution(
        "resolved", api_key_id=7, user_id=9, key_name="test-key", username="alice"
    )

    first = await storage.ingest(path1, _metadata(settings, raw1), token, resolution)
    second = await storage.ingest(path2, _metadata(settings, raw2), token, resolution)
    first_detail = await storage.detail(first.month, first.request_id)
    second_detail = await storage.detail(second.month, second.request_id)
    assert first_detail is not None and first_detail["body"] == body1
    assert second_detail is not None and second_detail["body"] == body2
    assert first_detail["model"] == "gpt-test"
    assert first_detail["token_masked"] == "…5678"

    db_path = database_path(settings.data_dir, first.month)
    connection = sqlite3.connect(db_path)
    repeated = connection.execute(
        """
        SELECT COUNT(DISTINCT object_hash || ':' || object_kind)
        FROM request_content_refs
        WHERE json_pointer='/messages/0'
        """
    ).fetchone()[0]
    requests = connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    content_objects = connection.execute(
        "SELECT COUNT(*) FROM content_objects"
    ).fetchone()[0]
    references = connection.execute(
        "SELECT COUNT(*) FROM request_content_refs"
    ).fetchone()[0]
    second_references = connection.execute(
        "SELECT COUNT(*) FROM request_content_refs WHERE request_id=?",
        (second.request_id,),
    ).fetchone()[0]
    connection.close()
    assert repeated == 1
    assert requests == 2
    assert references == content_objects
    assert second_references < len(body2["messages"])

    filters = QueryFilters(
        start_ms=int((_metadata(settings, raw1).occurred_at.timestamp() - 60) * 1000),
        end_ms=int((_metadata(settings, raw1).occurred_at.timestamp() + 60) * 1000),
        model="gpt-test",
    )
    listing = await storage.query(filters, None, 1)
    assert len(listing["items"]) == 1
    assert listing["next_cursor"]

    await storage.close()
    for candidate in settings.data_dir.glob("audit-*"):
        if candidate.is_file():
            assert plaintext.encode() not in candidate.read_bytes()


@pytest.mark.asyncio
async def test_invalid_json_is_preserved_as_binary(settings, tmp_path: Path) -> None:
    storage = MonthlyStorage(
        settings.data_dir, settings.sqlite_busy_timeout_ms, settings.timezone
    )
    await storage.start()
    path = tmp_path / "broken.json"
    raw = b'{"model":"x","messages":[{"content":"secret"}]'
    path.write_bytes(raw)
    result = await storage.ingest(
        path,
        _metadata(settings, raw),
        None,
        TokenResolution("no_token"),
    )
    detail = await storage.detail(result.month, result.request_id)
    assert detail is not None
    assert detail["parse_status"] == "invalid_json"
    assert detail["body"]["encoding"] == "base64"
    import base64

    assert base64.b64decode(detail["body"]["data"]) == raw
    await storage.close()


@pytest.mark.asyncio
async def test_compact_detail_only_loads_last_eight_sequence_items(
    settings,
    tmp_path: Path,
    monkeypatch,
) -> None:
    storage = MonthlyStorage(
        settings.data_dir, settings.sqlite_busy_timeout_ms, settings.timezone
    )
    await storage.start()
    body = {
        "model": "gpt-test",
        "messages": [
            {"role": "user", "content": f"unique-message-{index}"}
            for index in range(12)
        ],
        "tools": [{"name": "must-not-be-loaded"}],
    }
    path = tmp_path / "compact.json"
    raw = _write_body(path, body)
    result = await storage.ingest(
        path,
        _metadata(settings, raw),
        None,
        TokenResolution("no_token"),
    )

    connection = sqlite3.connect(database_path(settings.data_dir, result.month))
    referenced = {
        pointer: (object_hash, object_kind)
        for pointer, object_hash, object_kind in connection.execute(
            """
            SELECT json_pointer, object_hash, object_kind
            FROM request_content_refs
            WHERE request_id=?
            """,
            (result.request_id,),
        )
    }
    connection.close()
    loaded: list[tuple[str, str]] = []
    original_decode = storage._decode_object

    def tracking_decode(connection, key):
        loaded.append(key)
        return original_decode(connection, key)

    monkeypatch.setattr(storage, "_decode_object", tracking_decode)
    detail = await storage.detail(result.month, result.request_id, "compact")
    assert detail is not None
    assert [item["content"] for item in detail["body"]["messages"]] == [
        f"unique-message-{index}" for index in range(4, 12)
    ]
    assert detail["body"]["_audit_view"]["total_items"] == 12
    assert detail["body"]["_audit_view"]["omitted_items"] == 4
    assert referenced["/messages/0"] not in loaded
    assert referenced["/tools"] not in loaded
    for index in range(4, 12):
        assert referenced[f"/messages/{index}"] in loaded
    await storage.close()


@pytest.mark.asyncio
async def test_reads_use_dedicated_thread_and_compact_json_is_cached(
    settings,
    tmp_path: Path,
    monkeypatch,
) -> None:
    storage = MonthlyStorage(
        settings.data_dir, settings.sqlite_busy_timeout_ms, settings.timezone
    )
    await storage.start()
    path = tmp_path / "threaded.json"
    raw = _write_body(path, {"model": "gpt-test", "input": ["hello"]})
    result = await storage.ingest(
        path,
        _metadata(settings, raw),
        None,
        TokenResolution("no_token"),
    )

    caller_thread = threading.get_ident()
    reader_threads: list[int] = []
    original_detail_sync = storage._detail_sync

    def tracking_detail_sync(*args):
        reader_threads.append(threading.get_ident())
        return original_detail_sync(*args)

    monkeypatch.setattr(storage, "_detail_sync", tracking_detail_sync)
    first = await storage.detail_json(result.month, result.request_id, "compact")
    second = await storage.detail_json(result.month, result.request_id, "compact")
    assert first == second
    assert len(reader_threads) == 1
    assert reader_threads[0] != caller_thread
    await storage.close()


@pytest.mark.asyncio
async def test_compact_empty_body_keeps_preview_shape(settings, tmp_path: Path) -> None:
    storage = MonthlyStorage(
        settings.data_dir, settings.sqlite_busy_timeout_ms, settings.timezone
    )
    await storage.start()
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    result = await storage.ingest(
        path,
        _metadata(settings, b""),
        None,
        TokenResolution("no_token"),
    )
    detail = await storage.detail(result.month, result.request_id, "compact")
    assert detail is not None
    assert detail["body"] == {
        "_audit_view": {"mode": "compact"},
        "body": None,
    }
    await storage.close()


@pytest.mark.asyncio
async def test_rotation_opens_new_month_before_sealing(settings, tmp_path: Path) -> None:
    sealed: list[Path] = []
    storage = MonthlyStorage(
        settings.data_dir,
        settings.sqlite_busy_timeout_ms,
        settings.timezone,
        on_sealed=sealed.append,
    )
    await storage.start()
    current = datetime.now(settings.timezone)
    if current.month == 12:
        future = current.replace(year=current.year + 1, month=1, day=1)
    else:
        future = current.replace(month=current.month + 1, day=1)
    path = tmp_path / "future.json"
    raw = _write_body(path, {"model": "next-month", "prompt": "x"})
    metadata = _metadata(settings, raw)
    metadata = RequestMetadata(
        occurred_at=future,
        method=metadata.method,
        uri=metadata.uri,
        client_ip=metadata.client_ip,
        user_agent=metadata.user_agent,
        content_type=metadata.content_type,
        body_size=metadata.body_size,
        body_sha256=metadata.body_sha256,
    )
    result = await storage.ingest(
        path, metadata, None, TokenResolution("no_token")
    )
    assert result.month == future.strftime("%Y-%m")
    assert storage.current_month == result.month
    assert len(sealed) == 1
    assert sealed[0].is_file()
    await storage.close()
