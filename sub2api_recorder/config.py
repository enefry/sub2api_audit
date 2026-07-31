from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ConfigError(ValueError):
    """Raised when security-sensitive configuration is invalid."""


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


def _secret_bytes(
    name: str, *, exact_length: int | None = None, minimum_length: int | None = None
) -> bytes:
    raw = os.getenv(name, "")
    if not raw:
        raise ConfigError(f"{name} is required")
    if raw.startswith("base64:"):
        try:
            value = base64.b64decode(raw[7:], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ConfigError(f"{name} contains invalid base64") from exc
    else:
        value = raw.encode("utf-8")
    if exact_length is not None and len(value) != exact_length:
        raise ConfigError(f"{name} must decode to exactly {exact_length} bytes")
    if minimum_length is not None and len(value) < minimum_length:
        raise ConfigError(f"{name} must decode to at least {minimum_length} bytes")
    return value


def _load_allowlist() -> frozenset[str]:
    names: set[str] = set()
    raw = os.getenv("AUDIT_USERNAME_ALLOWLIST", "")
    names.update(part.strip() for part in raw.split(",") if part.strip())
    filename = os.getenv("AUDIT_USERNAME_ALLOWLIST_FILE")
    if filename:
        path = Path(filename)
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                value = line.strip()
                if value and not value.startswith("#"):
                    names.add(value)
        except OSError as exc:
            raise ConfigError(f"cannot read AUDIT_USERNAME_ALLOWLIST_FILE: {exc}") from exc
    if not names:
        raise ConfigError(
            "AUDIT_USERNAME_ALLOWLIST or AUDIT_USERNAME_ALLOWLIST_FILE must contain an administrator"
        )
    return frozenset(names)


@dataclass(frozen=True, slots=True)
class ArchiveConfig:
    enabled: bool
    endpoint_url: str | None
    region: str | None
    bucket: str | None
    prefix: str
    access_key_id: str | None
    secret_access_key: str | None
    encryption_key: bytes | None
    key_id: str | None
    retry_initial_seconds: int
    retry_max_seconds: int


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    temp_dir: Path
    timezone: ZoneInfo
    proxy_secret: str
    token_hmac_key: bytes
    username_allowlist: frozenset[str]
    max_body_bytes: int
    body_chunk_bytes: int
    sqlite_busy_timeout_ms: int
    query_max_days: int
    postgres_dsn: str | None
    postgres_timeout_seconds: int
    token_cache_seconds: int
    archive: ArchiveConfig
    read_workers: int = 2
    cache_bytes: int = 128 * 1024 * 1024
    full_cache_ttl_seconds: int = 120

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.getenv("AUDIT_DATA_DIR", "/data")).resolve()
        temp_dir = Path(os.getenv("AUDIT_TEMP_DIR", str(data_dir / ".tmp"))).resolve()
        timezone_name = os.getenv("AUDIT_TIMEZONE", "Asia/Hong_Kong")
        try:
            timezone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ConfigError(f"unknown AUDIT_TIMEZONE: {timezone_name}") from exc

        proxy_secret = os.getenv("AUDIT_PROXY_SECRET", "")
        if len(proxy_secret.encode("utf-8")) < 32:
            raise ConfigError("AUDIT_PROXY_SECRET must be at least 32 bytes")

        archive_enabled = _env_bool("AUDIT_ARCHIVE_ENABLED")
        encryption_key: bytes | None = None
        if archive_enabled:
            encryption_key = _secret_bytes("AUDIT_ARCHIVE_KEY", exact_length=32)
        archive = ArchiveConfig(
            enabled=archive_enabled,
            endpoint_url=os.getenv("AUDIT_S3_ENDPOINT") or None,
            region=os.getenv("AUDIT_S3_REGION") or None,
            bucket=os.getenv("AUDIT_S3_BUCKET") or None,
            prefix=os.getenv("AUDIT_S3_PREFIX", "sub2api-audit").strip("/"),
            access_key_id=os.getenv("AUDIT_S3_ACCESS_KEY_ID") or None,
            secret_access_key=os.getenv("AUDIT_S3_SECRET_ACCESS_KEY") or None,
            encryption_key=encryption_key,
            key_id=os.getenv("AUDIT_ARCHIVE_KEY_ID") or None,
            retry_initial_seconds=_env_int(
                "AUDIT_ARCHIVE_RETRY_INITIAL_SECONDS", 60, minimum=1
            ),
            retry_max_seconds=_env_int(
                "AUDIT_ARCHIVE_RETRY_MAX_SECONDS", 3600, minimum=1
            ),
        )
        if archive.enabled and (not archive.bucket or not archive.key_id):
            raise ConfigError(
                "AUDIT_S3_BUCKET and AUDIT_ARCHIVE_KEY_ID are required when archiving is enabled"
            )
        if archive.retry_max_seconds < archive.retry_initial_seconds:
            raise ConfigError(
                "AUDIT_ARCHIVE_RETRY_MAX_SECONDS cannot be less than "
                "AUDIT_ARCHIVE_RETRY_INITIAL_SECONDS"
            )

        return cls(
            data_dir=data_dir,
            temp_dir=temp_dir,
            timezone=timezone,
            proxy_secret=proxy_secret,
            token_hmac_key=_secret_bytes(
                "AUDIT_TOKEN_HMAC_KEY", minimum_length=32
            ),
            username_allowlist=_load_allowlist(),
            max_body_bytes=_env_int(
                "AUDIT_MAX_BODY_BYTES", 256 * 1024 * 1024, minimum=1024
            ),
            body_chunk_bytes=_env_int(
                "AUDIT_BODY_CHUNK_BYTES", 1024 * 1024, minimum=4096
            ),
            sqlite_busy_timeout_ms=_env_int(
                "AUDIT_SQLITE_BUSY_TIMEOUT_MS", 5000, minimum=100
            ),
            query_max_days=_env_int("AUDIT_QUERY_MAX_DAYS", 90, minimum=1),
            postgres_dsn=os.getenv("SUB2API_READONLY_DSN") or None,
            postgres_timeout_seconds=_env_int(
                "SUB2API_POSTGRES_TIMEOUT_SECONDS", 2, minimum=1
            ),
            token_cache_seconds=_env_int(
                "SUB2API_TOKEN_CACHE_SECONDS", 300, minimum=0
            ),
            archive=archive,
            read_workers=_env_int("AUDIT_READ_WORKERS", 2, minimum=1),
            cache_bytes=_env_int(
                "AUDIT_CACHE_BYTES", 128 * 1024 * 1024, minimum=0
            ),
            full_cache_ttl_seconds=_env_int(
                "AUDIT_FULL_CACHE_TTL_SECONDS", 120, minimum=1
            ),
        )
