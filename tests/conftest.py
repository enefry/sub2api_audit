from __future__ import annotations

from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from sub2api_recorder.config import ArchiveConfig, Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    archive = ArchiveConfig(
        enabled=False,
        endpoint_url=None,
        region=None,
        bucket=None,
        prefix="test",
        access_key_id=None,
        secret_access_key=None,
        encryption_key=None,
        key_id=None,
        retry_initial_seconds=1,
        retry_max_seconds=2,
    )
    return Settings(
        data_dir=tmp_path / "data",
        temp_dir=tmp_path / "data" / ".tmp",
        timezone=ZoneInfo("Asia/Hong_Kong"),
        proxy_secret="proxy-secret-" + ("x" * 32),
        token_hmac_key=b"hmac-key-" + (b"y" * 32),
        username_allowlist=frozenset({"auditor"}),
        max_body_bytes=2 * 1024 * 1024,
        body_chunk_bytes=64 * 1024,
        sqlite_busy_timeout_ms=1000,
        query_max_days=90,
        postgres_dsn=None,
        postgres_timeout_seconds=1,
        token_cache_seconds=0,
        archive=archive,
    )

