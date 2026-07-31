from __future__ import annotations

from sub2api_recorder.cache import WeightedLRUCache, deep_sizeof


def test_weighted_lru_evicts_by_bytes_and_rejects_oversized_items() -> None:
    cache = WeightedLRUCache(max_bytes=10, max_item_bytes=6)
    assert cache.put("first", b"123456", 6)
    assert cache.put("second", b"7890", 4)
    assert cache.get("first") == b"123456"

    assert cache.put("third", b"abc", 3)
    assert cache.get("second") is None
    assert cache.get("first") == b"123456"
    assert cache.get("third") == b"abc"
    assert not cache.put("oversized", b"x" * 7, 7)


def test_weighted_lru_limits_full_result_group_and_expires(
    monkeypatch,
) -> None:
    now = 100.0
    monkeypatch.setattr(
        "sub2api_recorder.cache.time.monotonic",
        lambda: now,
    )
    cache = WeightedLRUCache(max_bytes=100)
    cache.put("one", b"1", 1, ttl_seconds=2, group="full", max_group_entries=2)
    cache.put("two", b"2", 1, ttl_seconds=2, group="full", max_group_entries=2)
    cache.put("three", b"3", 1, ttl_seconds=2, group="full", max_group_entries=2)
    assert cache.get("one") is None
    assert cache.get("two") == b"2"

    now = 103.0
    assert cache.get("two") is None
    assert cache.get("three") is None


def test_deep_sizeof_counts_nested_json_values() -> None:
    value = {"items": ["x" * 100, {"enabled": True}]}
    assert deep_sizeof(value) > deep_sizeof({})
