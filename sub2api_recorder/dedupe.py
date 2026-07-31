from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator

from .compression import compress_bytes, compress_file_to_bytes

try:
    import ijson
    from ijson.common import JSONError as IjsonError
except ImportError:  # Small-request fallback used only before dependencies are installed.
    ijson = None
    IjsonError = ValueError


ContentKey = tuple[str, str]
StoreContent = Callable[[str, str, str, str, bytes, int], ContentKey]

COLLECTION_FIELDS = frozenset({"messages", "contents"})
SEMANTIC_FIELDS = frozenset({"input", "system", "instructions", "prompt"})
NESTED_BLOCK_FIELDS = frozenset({"content", "contents"})


@dataclass(frozen=True, slots=True)
class ContentReference:
    pointer: str
    ordinal: int
    role: str
    object_hash: str
    object_kind: str


@dataclass(slots=True)
class ProcessedBody:
    root_hash: str | None
    root_kind: str | None
    parse_status: str
    model: str | None
    references: list[ContentReference] = field(default_factory=list)


def canonical_json(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if isinstance(item, Decimal):
            return int(item) if item == item.to_integral_value() else float(item)
        if isinstance(item, dict):
            return {str(key): normalize(child) for key, child in item.items()}
        if isinstance(item, list):
            return [normalize(child) for child in item]
        return item

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def content_record(
    value: Any, kind: str, media_type: str = "application/json"
) -> tuple[str, str, str, str, bytes, int]:
    canonical = canonical_json(value)
    digest = hashlib.sha256(canonical).hexdigest()
    encoding, compressed = compress_bytes(canonical)
    return digest, kind, media_type, encoding, compressed, len(canonical)


def _pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


class _EventReader:
    def __init__(self, stream: BinaryIO):
        if ijson is None:
            raise RuntimeError("ijson is not installed")
        self._events: Iterator[tuple[str, Any]] = iter(
            ijson.basic_parse(stream, use_float=True)
        )

    def next(self) -> tuple[str, Any]:
        return next(self._events)

    def value(self, first: tuple[str, Any] | None = None) -> Any:
        event, value = first if first is not None else self.next()
        if event in {"null", "boolean", "number", "string"}:
            return value
        if event == "start_array":
            result: list[Any] = []
            while True:
                child = self.next()
                if child[0] == "end_array":
                    return result
                result.append(self.value(child))
        if event == "start_map":
            result_map: dict[str, Any] = {}
            while True:
                child_event, child_value = self.next()
                if child_event == "end_map":
                    return result_map
                if child_event != "map_key":
                    raise ValueError(f"expected map_key, got {child_event}")
                result_map[str(child_value)] = self.value()
        raise ValueError(f"unexpected JSON event: {event}")


class BodyProcessor:
    """Turns one request body into content-addressed objects and references."""

    def __init__(self, store_content: StoreContent):
        self.store_content = store_content
        self.references: list[ContentReference] = []
        self._ordinal = 0

    def _store(
        self, value: Any, kind: str, pointer: str, role: str
    ) -> dict[str, list[str]]:
        key = self.store_content(*content_record(value, kind))
        self.references.append(
            ContentReference(
                pointer=pointer,
                ordinal=self._ordinal,
                role=role,
                object_hash=key[0],
                object_kind=key[1],
            )
        )
        self._ordinal += 1
        return {"ref": [key[0], key[1]]}

    def _structured_item(self, value: Any, pointer: str, role: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            return self._store(value, "raw_json", pointer, role)
        changed = False
        fields: list[list[Any]] = []
        for key, child in value.items():
            child_pointer = f"{pointer}/{_pointer_escape(str(key))}"
            if key in NESTED_BLOCK_FIELDS and isinstance(child, list):
                changed = True
                items = [
                    self._structured_item(
                        item, f"{child_pointer}/{index}", "content_block"
                    )
                    for index, item in enumerate(child)
                ]
                fields.append([key, {"array": items}])
            else:
                fields.append([key, {"value": child}])
        if not changed:
            return self._store(value, "raw_json", pointer, role)
        template = {"format": "object_v1", "fields": fields}
        return self._store(template, "template_json", pointer, role)

    def _root_field(self, key: str, value: Any) -> dict[str, Any]:
        pointer = f"/{_pointer_escape(key)}"
        if key in COLLECTION_FIELDS and isinstance(value, list):
            return {
                "array": [
                    self._structured_item(item, f"{pointer}/{index}", key)
                    for index, item in enumerate(value)
                ]
            }
        if key in SEMANTIC_FIELDS and isinstance(value, list):
            return {
                "array": [
                    self._structured_item(item, f"{pointer}/{index}", key)
                    for index, item in enumerate(value)
                ]
            }
        if key in SEMANTIC_FIELDS:
            return self._structured_item(value, pointer, key)
        return self._store(value, "raw_json", pointer, "field")

    def _finish_root(
        self, fields: list[list[Any]], parse_status: str, model: str | None
    ) -> ProcessedBody:
        root = {"format": "object_v1", "fields": fields}
        root_ref = self._store(root, "template_json", "", "root")
        return ProcessedBody(
            root_hash=root_ref["ref"][0],
            root_kind=root_ref["ref"][1],
            parse_status=parse_status,
            model=model,
            references=self.references,
        )

    def _stream_json_object(self, stream: BinaryIO) -> ProcessedBody:
        reader = _EventReader(stream)
        first = reader.next()
        if first[0] != "start_map":
            value = reader.value(first)
            try:
                reader.next()
            except StopIteration:
                pass
            else:
                raise ValueError("trailing JSON data")
            root_ref = self._store(value, "raw_json", "", "root")
            return ProcessedBody(
                root_hash=root_ref["ref"][0],
                root_kind=root_ref["ref"][1],
                parse_status="json_stream",
                model=None,
                references=self.references,
            )

        fields: list[list[Any]] = []
        model: str | None = None
        while True:
            event, key = reader.next()
            if event == "end_map":
                break
            if event != "map_key":
                raise ValueError(f"expected map_key, got {event}")
            key = str(key)
            first_value = reader.next()
            if (
                key in (COLLECTION_FIELDS | SEMANTIC_FIELDS)
                and first_value[0] == "start_array"
            ):
                items: list[dict[str, Any]] = []
                index = 0
                pointer = f"/{_pointer_escape(key)}"
                while True:
                    item_event = reader.next()
                    if item_event[0] == "end_array":
                        break
                    item = reader.value(item_event)
                    items.append(
                        self._structured_item(item, f"{pointer}/{index}", key)
                    )
                    index += 1
                descriptor = {"array": items}
                value_for_model = None
            else:
                value = reader.value(first_value)
                descriptor = self._root_field(key, value)
                value_for_model = value
            if key == "model" and isinstance(value_for_model, str):
                model = value_for_model[:512]
            fields.append([key, descriptor])
        try:
            reader.next()
        except StopIteration:
            pass
        else:
            raise ValueError("trailing JSON data")
        return self._finish_root(fields, "json_stream", model)

    def _fallback_json(self, stream: BinaryIO) -> ProcessedBody:
        value = json.load(stream)
        if not isinstance(value, dict):
            root_ref = self._store(value, "raw_json", "", "root")
            return ProcessedBody(
                root_hash=root_ref["ref"][0],
                root_kind=root_ref["ref"][1],
                parse_status="json_fallback",
                model=None,
                references=self.references,
            )
        fields = [[key, self._root_field(key, child)] for key, child in value.items()]
        model = value.get("model")
        return self._finish_root(
            fields,
            "json_fallback",
            str(model)[:512] if isinstance(model, str) else None,
        )

    def process(self, body_path: Path, content_type: str | None) -> ProcessedBody:
        if body_path.stat().st_size == 0:
            return ProcessedBody(None, None, "empty", None, [])
        is_json = bool(content_type and ("json" in content_type.lower()))
        if is_json:
            try:
                with body_path.open("rb") as stream:
                    if ijson is not None:
                        return self._stream_json_object(stream)
                    return self._fallback_json(stream)
            except (
                ValueError,
                TypeError,
                json.JSONDecodeError,
                UnicodeDecodeError,
                IjsonError,
            ):
                # Preserve malformed JSON exactly as an opaque body.
                self.references.clear()
                self._ordinal = 0
        with body_path.open("rb") as stream:
            digest = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            stream.seek(0)
            encoding, compressed = compress_file_to_bytes(stream)
        key = self.store_content(
            digest.hexdigest(),
            "binary",
            content_type or "application/octet-stream",
            encoding,
            compressed,
            body_path.stat().st_size,
        )
        self.references.append(
            ContentReference("", 0, "root", key[0], key[1])
        )
        return ProcessedBody(
            key[0], key[1], "invalid_json" if is_json else "binary", None, self.references
        )


def describe_binary(media_type: str, value: bytes) -> dict[str, Any]:
    return {
        "media_type": media_type,
        "encoding": "base64",
        "data": base64.b64encode(value).decode("ascii"),
    }
