from __future__ import annotations

from typing import Any


SEQUENCE_FIELDS = ("input", "messages", "contents")
SEMANTIC_FIELDS = ("prompt", "instructions", "system")
MAX_SEQUENCE_ITEMS = 8
MAX_COLLECTION_ITEMS = 20
MAX_STRING_CHARS = 4000
MAX_DEPTH = 10


def _truncate_text(value: str) -> str:
    if len(value) <= MAX_STRING_CHARS:
        return value
    head_size = MAX_STRING_CHARS - 700
    tail_size = 500
    omitted = len(value) - head_size - tail_size
    return (
        f"{value[:head_size]}\n"
        f"... [省略 {omitted} 个字符] ...\n"
        f"{value[-tail_size:]}"
    )


def _compact_value(value: Any, depth: int = 0) -> Any:
    if depth >= MAX_DEPTH:
        return "[已省略过深的嵌套内容]"
    if isinstance(value, str):
        return _truncate_text(value)
    if isinstance(value, list):
        items = value
        omitted = max(0, len(items) - MAX_COLLECTION_ITEMS)
        if omitted:
            items = items[-MAX_COLLECTION_ITEMS:]
        result = [_compact_value(item, depth + 1) for item in items]
        if omitted:
            result.insert(0, f"[已省略前面的 {omitted} 项]")
        return result
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if key == "encrypted_content" and isinstance(child, str):
                result[key] = f"[已省略 {len(child)} 个字符的加密内容]"
            else:
                result[key] = _compact_value(child, depth + 1)
        return result
    return value


def compact_request_body(
    body: Any,
    *,
    sequence_total: int | None = None,
    top_level_fields: list[str] | None = None,
) -> Any:
    if not isinstance(body, dict):
        return {
            "_audit_view": {"mode": "compact"},
            "body": _compact_value(body),
        }

    result: dict[str, Any] = {}
    if "model" in body:
        result["model"] = _compact_value(body["model"])

    sequence_field = next(
        (
            field
            for field in SEQUENCE_FIELDS
            if isinstance(body.get(field), list)
        ),
        None,
    )
    selected_fields = {"model"}
    view: dict[str, Any] = {"mode": "compact"}

    if sequence_field is not None:
        sequence = body[sequence_field]
        shown = sequence[-MAX_SEQUENCE_ITEMS:]
        total_items = max(len(sequence), sequence_total or 0)
        result[sequence_field] = [
            _compact_value(item, 1) for item in shown
        ]
        selected_fields.add(sequence_field)
        view.update(
            {
                "sequence_field": sequence_field,
                "shown_items": len(shown),
                "total_items": total_items,
                "omitted_items": total_items - len(shown),
            }
        )
    else:
        for field in SEMANTIC_FIELDS:
            if field in body:
                result[field] = _compact_value(body[field])
                selected_fields.add(field)

    available_fields = top_level_fields if top_level_fields is not None else list(body)
    omitted_fields = [key for key in available_fields if key not in selected_fields]
    if omitted_fields:
        view["omitted_top_level_fields"] = omitted_fields
    return {"_audit_view": view, **result}
