from sub2api_recorder.preview import (
    MAX_SEQUENCE_ITEMS,
    MAX_STRING_CHARS,
    compact_request_body,
)


def test_compact_request_body_keeps_recent_items_and_limits_bulk_content() -> None:
    body = {
        "model": "gpt-test",
        "input": [
            {"type": "message", "role": "user", "content": f"message-{index}"}
            for index in range(MAX_SEQUENCE_ITEMS + 3)
        ]
        + [
            {
                "type": "reasoning",
                "encrypted_content": "x" * (MAX_STRING_CHARS + 100),
            }
        ],
        "tools": [{"name": "lookup"}],
        "stream": True,
    }

    compact = compact_request_body(body)

    assert compact["model"] == "gpt-test"
    assert len(compact["input"]) == MAX_SEQUENCE_ITEMS
    assert compact["input"][0]["content"] == "message-4"
    assert compact["input"][-1]["encrypted_content"].startswith("[已省略")
    view = compact["_audit_view"]
    assert view["total_items"] == MAX_SEQUENCE_ITEMS + 4
    assert view["omitted_items"] == 4
    assert view["omitted_top_level_fields"] == ["tools", "stream"]
