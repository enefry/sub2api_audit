from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import sqlite3
import struct
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import boto3
except ImportError:
    boto3 = None

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from loguru import logger

from .compression import compress_stream, decompress_stream
from .config import ArchiveConfig
from .storage import MONTH_RE, SCHEMA_VERSION, file_sha256


MAGIC = b"S2AUDIT1"
TAG_SIZE = 16
LOGGER = logger.bind(component="archive")


@dataclass(frozen=True, slots=True)
class ArchivePaths:
    object_key: str
    manifest_key: str


def archive_keys(prefix: str, month: str) -> ArchivePaths:
    year, month_number = month.split("-", 1)
    base = f"{prefix.strip('/')}/{year}/{month_number}/audit-{month}.sqlite3"
    return ArchivePaths(f"{base}.zst.aes", f"{base}.manifest.json")


def _s3_client(config: ArchiveConfig):
    if boto3 is None:
        raise RuntimeError("boto3 is required for archive operations")
    kwargs: dict[str, Any] = {}
    if config.endpoint_url:
        kwargs["endpoint_url"] = config.endpoint_url
    if config.region:
        kwargs["region_name"] = config.region
    if config.access_key_id:
        kwargs["aws_access_key_id"] = config.access_key_id
    if config.secret_access_key:
        kwargs["aws_secret_access_key"] = config.secret_access_key
    return boto3.client("s3", **kwargs)


def _sqlite_metadata(path: Path) -> tuple[int, int]:
    uri = f"file:{path}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise RuntimeError("SQLite integrity check failed")
        records = int(connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0])
        schema = connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        version = int(schema[0]) if schema is not None else 0
        return records, version
    finally:
        connection.close()


def _encrypt_file(
    source: Path,
    destination: Path,
    key: bytes,
    key_id: str,
    compression: str,
) -> dict[str, Any]:
    nonce = os.urandom(12)
    header = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "compression": compression,
        "key_id": key_id,
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    header_bytes = json.dumps(
        header, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(header_bytes)
    with source.open("rb") as input_stream, destination.open("wb") as output_stream:
        output_stream.write(MAGIC)
        output_stream.write(struct.pack(">I", len(header_bytes)))
        output_stream.write(header_bytes)
        while chunk := input_stream.read(1024 * 1024):
            output_stream.write(encryptor.update(chunk))
        output_stream.write(encryptor.finalize())
        output_stream.write(encryptor.tag)
        output_stream.flush()
        os.fsync(output_stream.fileno())
    return header


def _read_encrypted_header(stream) -> tuple[dict[str, Any], bytes, int]:
    if stream.read(len(MAGIC)) != MAGIC:
        raise ValueError("invalid archive magic")
    length_bytes = stream.read(4)
    if len(length_bytes) != 4:
        raise ValueError("truncated archive header")
    header_length = struct.unpack(">I", length_bytes)[0]
    if header_length < 2 or header_length > 64 * 1024:
        raise ValueError("invalid archive header length")
    header_bytes = stream.read(header_length)
    if len(header_bytes) != header_length:
        raise ValueError("truncated archive header")
    header = json.loads(header_bytes)
    if (
        header.get("version") != 1
        or header.get("algorithm") != "AES-256-GCM"
        or header.get("compression") not in {"zstd", "zlib"}
    ):
        raise ValueError("unsupported archive format")
    return header, header_bytes, len(MAGIC) + 4 + header_length


def _decrypt_file(source: Path, destination: Path, key: bytes) -> dict[str, Any]:
    size = source.stat().st_size
    with source.open("rb") as input_stream:
        header, header_bytes, payload_offset = _read_encrypted_header(input_stream)
        ciphertext_size = size - payload_offset - TAG_SIZE
        if ciphertext_size < 0:
            raise ValueError("truncated archive")
        input_stream.seek(size - TAG_SIZE)
        tag = input_stream.read(TAG_SIZE)
        nonce = base64.b64decode(header["nonce"], validate=True)
        if len(nonce) != 12:
            raise ValueError("invalid archive nonce")
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header_bytes)
        input_stream.seek(payload_offset)
        remaining = ciphertext_size
        with destination.open("wb") as output_stream:
            while remaining:
                chunk = input_stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("truncated archive ciphertext")
                remaining -= len(chunk)
                output_stream.write(decryptor.update(chunk))
            output_stream.write(decryptor.finalize())
            output_stream.flush()
            os.fsync(output_stream.fileno())
    return header


class ArchiveManager:
    def __init__(self, data_dir: Path, config: ArchiveConfig):
        self.data_dir = data_dir
        self.config = config
        self.temp_dir = data_dir / ".archive-tmp"
        self._queue: asyncio.PriorityQueue[
            tuple[float, int, Path, int]
        ] = asyncio.PriorityQueue()
        self._queued: set[Path] = set()
        self._counter = 0
        self._task: asyncio.Task[None] | None = None
        self._stopping = False
        self.last_status: dict[str, Any] = {"status": "disabled"}

    def start(self, current_month: str | None) -> None:
        if not self.config.enabled:
            return
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name="archive-worker")
        for path in sorted(self.data_dir.glob("audit-*.sqlite3")):
            match = MONTH_RE.match(path.name)
            if not match or match.group(1) == current_month:
                continue
            sidecar = path.with_suffix(".archive.json")
            if self._sidecar_succeeded(sidecar):
                continue
            self.enqueue(path)

    @staticmethod
    def _sidecar_succeeded(path: Path) -> bool:
        try:
            return json.loads(path.read_text(encoding="utf-8")).get("status") == "success"
        except (OSError, json.JSONDecodeError):
            return False

    def enqueue(self, path: Path) -> None:
        if not self.config.enabled or path in self._queued:
            return
        self._queued.add(path)
        self._counter += 1
        self._queue.put_nowait((time.monotonic(), self._counter, path, 0))

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        while not self._stopping:
            ready_at, counter, path, attempt = await self._queue.get()
            wait_seconds = ready_at - time.monotonic()
            if wait_seconds > 0:
                await self._queue.put((ready_at, counter, path, attempt))
                self._queue.task_done()
                await asyncio.sleep(min(wait_seconds, 1.0))
                continue
            try:
                manifest = await asyncio.to_thread(self.archive_file, path)
                self.last_status = {
                    "status": "success",
                    "month": manifest["month"],
                    "at": manifest["archived_at"],
                }
                LOGGER.info(
                    "archive uploaded; month={} records={}",
                    manifest["month"],
                    manifest["records"],
                )
                self._queued.discard(path)
            except Exception:
                delay = min(
                    self.config.retry_initial_seconds * (2**attempt),
                    self.config.retry_max_seconds,
                )
                self.last_status = {
                    "status": "retrying",
                    "month": path.stem.removeprefix("audit-"),
                    "retry_seconds": delay,
                }
                LOGGER.warning(
                    "archive upload failed; month={} retry_in_seconds={}",
                    path.stem.removeprefix("audit-"),
                    delay,
                )
                retry_at = datetime.fromtimestamp(
                    time.time() + delay, tz=UTC
                ).isoformat()
                try:
                    self._write_sidecar(
                        path.with_suffix(".archive.json"),
                        {
                            "status": "retrying",
                            "month": path.stem.removeprefix("audit-"),
                            "attempt": attempt + 1,
                            "retry_at": retry_at,
                        },
                    )
                except OSError:
                    pass
                self._counter += 1
                await self._queue.put(
                    (time.monotonic() + delay, self._counter, path, attempt + 1)
                )
            finally:
                self._queue.task_done()

    def archive_file(self, path: Path) -> dict[str, Any]:
        if not self.config.enabled:
            raise RuntimeError("archiving is disabled")
        match = MONTH_RE.match(path.name)
        if not match:
            raise ValueError("invalid monthly database filename")
        month = match.group(1)
        if not path.is_file():
            raise FileNotFoundError(path)
        assert self.config.encryption_key is not None
        assert self.config.key_id is not None
        assert self.config.bucket is not None

        records, schema_version = _sqlite_metadata(path)
        original_hash = file_sha256(path)
        original_size = path.stat().st_size
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        compressed_name: str | None = None
        encrypted_name: str | None = None
        manifest_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.temp_dir, prefix=f"{path.name}.", suffix=".compressed", delete=False
            ) as compressed_stream:
                compressed_name = compressed_stream.name
                with path.open("rb") as source:
                    compression = compress_stream(source, compressed_stream)
                compressed_stream.flush()
                os.fsync(compressed_stream.fileno())
            compressed_path = Path(compressed_name)
            with tempfile.NamedTemporaryFile(
                dir=self.temp_dir, prefix=f"{path.name}.", suffix=".encrypted", delete=False
            ) as encrypted_stream:
                encrypted_name = encrypted_stream.name
            encrypted_path = Path(encrypted_name)
            header = _encrypt_file(
                compressed_path,
                encrypted_path,
                self.config.encryption_key,
                self.config.key_id,
                compression,
            )
            encrypted_hash = file_sha256(encrypted_path)
            archived_at = datetime.now(UTC).isoformat()
            keys = archive_keys(self.config.prefix, month)
            manifest = {
                "format_version": 1,
                "month": month,
                "schema_version": schema_version,
                "records": records,
                "original_size": original_size,
                "original_sha256": original_hash,
                "encrypted_size": encrypted_path.stat().st_size,
                "encrypted_sha256": encrypted_hash,
                "archive_key_id": self.config.key_id,
                "archive_header": header,
                "object_key": keys.object_key,
                "manifest_key": keys.manifest_key,
                "archived_at": archived_at,
            }
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.temp_dir,
                prefix=f"{path.name}.",
                suffix=".manifest",
                delete=False,
            ) as manifest_stream:
                manifest_name = manifest_stream.name
                json.dump(manifest, manifest_stream, ensure_ascii=False, sort_keys=True)
                manifest_stream.flush()
                os.fsync(manifest_stream.fileno())

            client = _s3_client(self.config)
            client.upload_file(
                str(encrypted_path),
                self.config.bucket,
                keys.object_key,
                ExtraArgs={"Metadata": {"sha256": encrypted_hash}},
            )
            client.upload_file(
                manifest_name,
                self.config.bucket,
                keys.manifest_key,
                ExtraArgs={"ContentType": "application/json"},
            )
            head = client.head_object(Bucket=self.config.bucket, Key=keys.object_key)
            if int(head["ContentLength"]) != encrypted_path.stat().st_size:
                raise RuntimeError("uploaded archive size mismatch")
            remote_hash = (head.get("Metadata") or {}).get("sha256")
            if remote_hash != encrypted_hash:
                raise RuntimeError("uploaded archive hash metadata mismatch")
            self._write_sidecar(path.with_suffix(".archive.json"), {
                "status": "success",
                **manifest,
            })
            return manifest
        finally:
            for filename in (compressed_name, encrypted_name, manifest_name):
                if filename:
                    try:
                        Path(filename).unlink()
                    except FileNotFoundError:
                        pass

    @staticmethod
    def _write_sidecar(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    def restore(self, month: str, destination: Path, overwrite: bool = False) -> Path:
        if not self.config.enabled:
            raise RuntimeError("archive configuration is required for restore")
        if not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", month):
            raise ValueError("invalid month")
        if destination.exists() and not overwrite:
            raise FileExistsError(destination)
        assert self.config.bucket is not None
        assert self.config.encryption_key is not None
        keys = archive_keys(self.config.prefix, month)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        client = _s3_client(self.config)
        encrypted_name: str | None = None
        manifest_name: str | None = None
        compressed_name: str | None = None
        restored_name: str | None = None
        try:
            for suffix, key in (
                (".download", keys.object_key),
                (".manifest", keys.manifest_key),
            ):
                handle = tempfile.NamedTemporaryFile(
                    dir=self.temp_dir, suffix=suffix, delete=False
                )
                handle.close()
                if suffix == ".download":
                    encrypted_name = handle.name
                else:
                    manifest_name = handle.name
                client.download_file(self.config.bucket, key, handle.name)
            assert encrypted_name and manifest_name
            manifest = json.loads(Path(manifest_name).read_text(encoding="utf-8"))
            if manifest.get("month") != month:
                raise ValueError("archive manifest month mismatch")
            if file_sha256(Path(encrypted_name)) != manifest.get("encrypted_sha256"):
                raise ValueError("encrypted archive hash mismatch")

            compressed = tempfile.NamedTemporaryFile(
                dir=self.temp_dir, suffix=".decrypted", delete=False
            )
            compressed_name = compressed.name
            compressed.close()
            header = _decrypt_file(
                Path(encrypted_name),
                Path(compressed_name),
                self.config.encryption_key,
            )
            if header.get("key_id") != manifest.get("archive_key_id"):
                raise ValueError("archive key ID mismatch")

            restored = tempfile.NamedTemporaryFile(
                dir=self.temp_dir, suffix=".sqlite3", delete=False
            )
            restored_name = restored.name
            restored.close()
            with Path(compressed_name).open("rb") as source, Path(restored_name).open(
                "wb"
            ) as output:
                decompress_stream(source, output, header["compression"])
                output.flush()
                os.fsync(output.fileno())
            restored_path = Path(restored_name)
            if file_sha256(restored_path) != manifest.get("original_sha256"):
                raise ValueError("restored database hash mismatch")
            _sqlite_metadata(restored_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(restored_path, destination)
            restored_name = None
            return destination
        finally:
            for filename in (
                encrypted_name,
                manifest_name,
                compressed_name,
                restored_name,
            ):
                if filename:
                    try:
                        Path(filename).unlink()
                    except FileNotFoundError:
                        pass
