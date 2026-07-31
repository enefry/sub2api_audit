from __future__ import annotations

import asyncio
import hashlib
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import BaseModel, ConfigDict

from .archive import ArchiveManager
from .config import ConfigError, Settings
from .logging_config import configure_file_logging, remove_file_logging
from .preferences import AuditPreference, AuditPreferenceStore
from .security import (
    BodyTooLargeError,
    extract_token,
    fingerprint_token,
    secrets_equal,
)
from .storage import (
    MonthlyStorage,
    QueryFilters,
    RequestMetadata,
    decode_cursor,
)
from .token_resolver import ReadOnlyTokenResolver

LOGGER = logger.bind(component="app")
STATIC_DIR = Path(__file__).with_name("static")
STATIC_CONTENT = {
    "index.html": (STATIC_DIR / "index.html").read_bytes(),
    "app.js": (STATIC_DIR / "app.js").read_bytes(),
    "styles.css": (STATIC_DIR / "styles.css").read_bytes(),
}
INGEST_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
ADMIN_AUDIT_PREFIX = "/admin/audit"
PERSONAL_AUDIT_PREFIX = "/audit"
AUDIT_PREFIXES = (ADMIN_AUDIT_PREFIX, PERSONAL_AUDIT_PREFIX)


@dataclass(frozen=True, slots=True)
class AuditPrincipal:
    username: str
    can_view_all: bool

    @property
    def required_username(self) -> str | None:
        return None if self.can_view_all else self.username


class AuditPreferenceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


def _path_uses_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(f"{prefix}/")


def _preference_payload(preference: AuditPreference) -> dict[str, object]:
    return {
        "enabled": preference.enabled,
        "default_enabled": False,
        "updated_at": preference.updated_at,
    }


def _safe_header(
    request: Request, name: str, maximum: int, default: str | None = None
) -> str | None:
    value = request.headers.get(name, default)
    if value is None:
        return None
    value = value.replace("\r", "").replace("\n", "")
    return value[:maximum]


def _parse_datetime(value: str | None, fallback: datetime, settings: Settings) -> datetime:
    if value is None:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(400, "invalid date/time") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=settings.timezone)
    return parsed.astimezone(settings.timezone)


def create_app(settings: Settings | None = None) -> FastAPI:
    configured_settings = settings

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            active_settings = configured_settings or Settings.from_env()
        except ConfigError:
            LOGGER.critical("invalid recorder configuration")
            raise
        active_settings.data_dir.mkdir(parents=True, exist_ok=True)
        active_settings.temp_dir.mkdir(parents=True, exist_ok=True)
        log_handler_id, log_path = configure_file_logging(active_settings.data_dir)
        LOGGER.info("recorder starting; log_file={}", log_path)

        archive: ArchiveManager | None = None
        storage: MonthlyStorage | None = None
        preferences: AuditPreferenceStore | None = None
        try:
            archive = ArchiveManager(active_settings.data_dir, active_settings.archive)
            storage = MonthlyStorage(
                active_settings.data_dir,
                active_settings.sqlite_busy_timeout_ms,
                active_settings.timezone,
                on_sealed=archive.enqueue,
                read_workers=active_settings.read_workers,
                cache_bytes=active_settings.cache_bytes,
                full_cache_ttl_seconds=active_settings.full_cache_ttl_seconds,
            )
            resolver = ReadOnlyTokenResolver(
                active_settings.postgres_dsn,
                active_settings.postgres_timeout_seconds,
                active_settings.token_cache_seconds,
            )
            preferences = AuditPreferenceStore(
                active_settings.data_dir,
                active_settings.sqlite_busy_timeout_ms,
                active_settings.timezone,
            )
            preferences.start()
            await storage.start()
            archive.start(storage.current_month)
            app.state.settings = active_settings
            app.state.storage = storage
            app.state.resolver = resolver
            app.state.archive = archive
            app.state.preferences = preferences
            LOGGER.info(
                "recorder started; archive_enabled={}",
                active_settings.archive.enabled,
            )
            yield
        finally:
            LOGGER.info("recorder stopping")
            try:
                if archive is not None:
                    await archive.stop()
            finally:
                try:
                    if storage is not None:
                        await storage.close()
                finally:
                    try:
                        if preferences is not None:
                            preferences.close()
                        LOGGER.info("recorder stopped")
                    finally:
                        remove_file_logging(log_handler_id)

    app = FastAPI(
        title="Sub2API Audit Recorder",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def audit_security_headers(request: Request, call_next):
        response = await call_next(request)
        if any(_path_uses_prefix(request.url.path, prefix) for prefix in AUDIT_PREFIXES):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; "
                "base-uri 'none'; frame-ancestors 'self'; form-action 'self'"
            )
        return response

    async def require_proxy(request: Request) -> Settings:
        active_settings: Settings = request.app.state.settings
        supplied = request.headers.get("x-audit-proxy-secret")
        if not secrets_equal(supplied, active_settings.proxy_secret):
            raise HTTPException(403, "trusted proxy required")
        return active_settings

    async def require_audit_user(
        request: Request,
        active_settings: Settings = Depends(require_proxy),
    ) -> AuditPrincipal:
        username = _safe_header(request, "x-authentik-username", 512)
        if not username:
            raise HTTPException(
                401,
                "Authentik identity required",
                headers={"WWW-Authenticate": "Authentik"},
            )
        admin_scope = _path_uses_prefix(request.url.path, ADMIN_AUDIT_PREFIX)
        if admin_scope and username not in active_settings.username_allowlist:
            raise HTTPException(403, "audit administrator access required")
        return AuditPrincipal(username=username, can_view_all=admin_scope)

    @app.api_route("/_audit_ingest", methods=INGEST_METHODS, include_in_schema=False)
    async def ingest_request(
        request: Request,
        active_settings: Settings = Depends(require_proxy),
    ) -> Response:
        started_at = time.monotonic()
        received_at = datetime.now(active_settings.timezone)
        method = _safe_header(
            request, "x-audit-original-method", 32, request.method
        ) or request.method
        uri = _safe_header(request, "x-audit-original-uri", 16 * 1024)
        if not uri:
            raise HTTPException(400, "original URI is required")
        content_type = _safe_header(request, "content-type", 512)
        client_ip = _safe_header(request, "x-audit-original-client-ip", 512)
        user_agent = _safe_header(request, "user-agent", 4096)

        body_path: Path | None = None
        body_size = 0
        digest = hashlib.sha256()
        try:
            plaintext_token, token_source = extract_token(request.headers)
            if plaintext_token is None or token_source is None:
                return Response(status_code=204)
            token_fingerprint = fingerprint_token(
                plaintext_token,
                token_source,
                active_settings.token_hmac_key,
            )
            resolver: ReadOnlyTokenResolver = request.app.state.resolver
            if active_settings.postgres_dsn:
                resolution = await asyncio.to_thread(
                    resolver.resolve,
                    plaintext_token,
                    token_fingerprint.fingerprint,
                )
            else:
                resolution = resolver.resolve(
                    plaintext_token,
                    token_fingerprint.fingerprint,
                )
            del plaintext_token
            if resolution.status != "resolved" or not resolution.username:
                return Response(status_code=204)
            preferences: AuditPreferenceStore = request.app.state.preferences
            if not preferences.is_enabled(resolution.username):
                return Response(status_code=204)

            with tempfile.NamedTemporaryFile(
                dir=active_settings.temp_dir,
                prefix="ingest-",
                suffix=".body",
                delete=False,
            ) as body_stream:
                body_path = Path(body_stream.name)
                async for chunk in request.stream():
                    body_size += len(chunk)
                    if body_size > active_settings.max_body_bytes:
                        raise BodyTooLargeError
                    digest.update(chunk)
                    for offset in range(0, len(chunk), active_settings.body_chunk_bytes):
                        body_stream.write(
                            chunk[offset : offset + active_settings.body_chunk_bytes]
                        )
                body_stream.flush()

            metadata = RequestMetadata(
                occurred_at=received_at,
                method=method,
                uri=uri,
                client_ip=client_ip,
                user_agent=user_agent,
                content_type=content_type,
                body_size=body_size,
                body_sha256=digest.hexdigest(),
            )
            storage: MonthlyStorage = request.app.state.storage
            await storage.ingest(
                body_path, metadata, token_fingerprint, resolution
            )
            LOGGER.info(
                "audit request recorded; method={} body_size={} duration_ms={:.1f}",
                method,
                body_size,
                (time.monotonic() - started_at) * 1000,
            )
            return Response(status_code=204)
        except BodyTooLargeError:
            LOGGER.warning(
                "audit request rejected; reason=body_too_large method={} "
                "body_size={} limit={}",
                method,
                body_size,
                active_settings.max_body_bytes,
            )
            return Response(status_code=413)
        except Exception as exc:
            LOGGER.error(
                "audit ingestion failed; error_type={}",
                type(exc).__name__,
            )
            return Response(status_code=503)
        finally:
            if body_path is not None:
                try:
                    body_path.unlink()
                except FileNotFoundError:
                    pass

    @app.get(f"{ADMIN_AUDIT_PREFIX}/", include_in_schema=False)
    @app.get(f"{PERSONAL_AUDIT_PREFIX}/", include_in_schema=False)
    async def audit_page(audit_user: AuditPrincipal = Depends(require_audit_user)):
        return Response(STATIC_CONTENT["index.html"], media_type="text/html")

    @app.get(f"{ADMIN_AUDIT_PREFIX}/static/app.js", include_in_schema=False)
    @app.get(f"{PERSONAL_AUDIT_PREFIX}/static/app.js", include_in_schema=False)
    async def audit_script(audit_user: AuditPrincipal = Depends(require_audit_user)):
        return Response(
            STATIC_CONTENT["app.js"], media_type="application/javascript"
        )

    @app.get(f"{ADMIN_AUDIT_PREFIX}/static/styles.css", include_in_schema=False)
    @app.get(f"{PERSONAL_AUDIT_PREFIX}/static/styles.css", include_in_schema=False)
    async def audit_styles(audit_user: AuditPrincipal = Depends(require_audit_user)):
        return Response(STATIC_CONTENT["styles.css"], media_type="text/css")

    @app.get(f"{ADMIN_AUDIT_PREFIX}/api/requests", include_in_schema=False)
    @app.get(f"{PERSONAL_AUDIT_PREFIX}/api/requests", include_in_schema=False)
    async def audit_requests(
        request: Request,
        audit_user: AuditPrincipal = Depends(require_audit_user),
        start: str | None = None,
        end: str | None = None,
        model: str | None = Query(None, max_length=512),
        uri: str | None = Query(None, max_length=4096),
        token: str | None = Query(None, max_length=256),
        key_name: str | None = Query(None, max_length=512),
        username: str | None = Query(None, max_length=512),
        cursor: str | None = Query(None, max_length=1024),
        limit: int = Query(50, ge=1, le=200),
    ):
        active_settings: Settings = request.app.state.settings
        now = datetime.now(active_settings.timezone)
        end_at = _parse_datetime(end, now, active_settings)
        start_at = _parse_datetime(start, end_at - timedelta(days=1), active_settings)
        if end_at <= start_at:
            raise HTTPException(400, "end must be later than start")
        if end_at - start_at > timedelta(days=active_settings.query_max_days):
            raise HTTPException(
                400,
                f"date range cannot exceed {active_settings.query_max_days} days",
            )
        try:
            decoded_cursor = decode_cursor(cursor)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        filters = QueryFilters(
            start_ms=int(start_at.timestamp() * 1000),
            end_ms=int(end_at.timestamp() * 1000),
            model=model or None,
            uri=uri or None,
            token=token or None,
            key_name=key_name or None,
            username=(
                (username or None)
                if audit_user.can_view_all
                else audit_user.username
            ),
        )
        storage: MonthlyStorage = request.app.state.storage
        return await storage.query(filters, decoded_cursor, limit)

    @app.get(
        f"{ADMIN_AUDIT_PREFIX}/api/requests/{{month}}/{{request_id}}",
        include_in_schema=False,
    )
    @app.get(
        f"{PERSONAL_AUDIT_PREFIX}/api/requests/{{month}}/{{request_id}}",
        include_in_schema=False,
    )
    async def audit_request_detail(
        month: str,
        request_id: int,
        request: Request,
        audit_user: AuditPrincipal = Depends(require_audit_user),
        view: Literal["compact", "full"] = "full",
    ):
        if request_id < 1:
            raise HTTPException(404, "request not found")
        storage: MonthlyStorage = request.app.state.storage
        try:
            payload = await storage.detail_json(
                month,
                request_id,
                view,
                required_username=audit_user.required_username,
            )
        except ValueError:
            raise HTTPException(404, "request not found") from None
        if payload is None:
            raise HTTPException(404, "request not found")
        return Response(content=payload, media_type="application/json")

    @app.get(f"{ADMIN_AUDIT_PREFIX}/api/months", include_in_schema=False)
    @app.get(f"{PERSONAL_AUDIT_PREFIX}/api/months", include_in_schema=False)
    async def audit_months(
        request: Request,
        audit_user: AuditPrincipal = Depends(require_audit_user),
    ):
        storage: MonthlyStorage = request.app.state.storage
        return {
            "items": await storage.months(
                required_username=audit_user.required_username
            )
        }

    @app.get(f"{ADMIN_AUDIT_PREFIX}/api/context", include_in_schema=False)
    @app.get(f"{PERSONAL_AUDIT_PREFIX}/api/context", include_in_schema=False)
    async def audit_context(
        request: Request,
        audit_user: AuditPrincipal = Depends(require_audit_user),
    ):
        active_settings: Settings = request.app.state.settings
        preferences: AuditPreferenceStore = request.app.state.preferences
        return {
            "timezone": str(active_settings.timezone),
            "now": datetime.now(active_settings.timezone).isoformat(),
            "viewer": {
                "username": audit_user.username,
                "can_view_all": audit_user.can_view_all,
                "scope": "all" if audit_user.can_view_all else "personal",
                "audit_enabled": preferences.is_enabled(audit_user.username),
            },
        }

    @app.get(f"{PERSONAL_AUDIT_PREFIX}/api/preference", include_in_schema=False)
    async def audit_preference(
        request: Request,
        audit_user: AuditPrincipal = Depends(require_audit_user),
    ):
        preferences: AuditPreferenceStore = request.app.state.preferences
        return _preference_payload(preferences.get(audit_user.username))

    @app.put(f"{PERSONAL_AUDIT_PREFIX}/api/preference", include_in_schema=False)
    async def update_audit_preference(
        update: AuditPreferenceUpdate,
        request: Request,
        audit_user: AuditPrincipal = Depends(require_audit_user),
    ):
        preferences: AuditPreferenceStore = request.app.state.preferences
        return _preference_payload(
            preferences.set_enabled(audit_user.username, update.enabled)
        )

    @app.get("/healthz", include_in_schema=False)
    async def health(
        request: Request,
        active_settings: Settings = Depends(require_proxy),
    ):
        storage: MonthlyStorage = request.app.state.storage
        resolver: ReadOnlyTokenResolver = request.app.state.resolver
        archive: ArchiveManager = request.app.state.archive
        if request.app.state.settings.postgres_dsn:
            postgres_ok, postgres_error = await asyncio.to_thread(resolver.health)
        else:
            postgres_ok, postgres_error = resolver.health()
        payload = {
            "status": "ok",
            "storage": storage.storage_health(),
            "postgres_readonly": {
                "ok": postgres_ok,
                "status": postgres_error,
            },
            "archive": archive.last_status,
            "preferences": request.app.state.preferences.health(),
        }
        return JSONResponse(payload)

    return app


app = create_app()
