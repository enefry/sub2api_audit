from __future__ import annotations

import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Hashable


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    value: Any
    weight: int
    expires_at: float | None
    group: str | None


class WeightedLRUCache:
    """Thread-safe LRU with a shared byte budget and optional TTL/group limits."""

    def __init__(self, max_bytes: int, max_item_bytes: int | None = None):
        self.max_bytes = max(0, int(max_bytes))
        if max_item_bytes is None:
            max_item_bytes = self.max_bytes
        self.max_item_bytes = max(0, min(int(max_item_bytes), self.max_bytes))
        self._items: OrderedDict[Hashable, _CacheEntry] = OrderedDict()
        self._weight = 0
        self._lock = threading.Lock()

    def _remove(self, key: Hashable) -> None:
        entry = self._items.pop(key, None)
        if entry is not None:
            self._weight -= entry.weight

    def _purge_expired(self, now: float) -> None:
        expired = [
            key
            for key, entry in self._items.items()
            if entry.expires_at is not None and entry.expires_at <= now
        ]
        for key in expired:
            self._remove(key)

    def get(self, key: Hashable) -> Any | None:
        now = time.monotonic()
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            if entry.expires_at is not None and entry.expires_at <= now:
                self._remove(key)
                return None
            self._items.move_to_end(key)
            return entry.value

    def put(
        self,
        key: Hashable,
        value: Any,
        weight: int,
        *,
        ttl_seconds: int | float | None = None,
        group: str | None = None,
        max_group_entries: int | None = None,
    ) -> bool:
        weight = max(0, int(weight))
        if (
            self.max_bytes == 0
            or weight > self.max_item_bytes
            or weight > self.max_bytes
            or (
                group is not None
                and max_group_entries is not None
                and max_group_entries < 1
            )
        ):
            return False
        now = time.monotonic()
        expires_at = (
            now + float(ttl_seconds)
            if ttl_seconds is not None and ttl_seconds > 0
            else None
        )
        with self._lock:
            self._purge_expired(now)
            self._remove(key)
            if group is not None and max_group_entries is not None:
                group_keys = [
                    existing_key
                    for existing_key, entry in self._items.items()
                    if entry.group == group
                ]
                while len(group_keys) >= int(max_group_entries):
                    self._remove(group_keys.pop(0))
            self._items[key] = _CacheEntry(value, weight, expires_at, group)
            self._weight += weight
            while self._weight > self.max_bytes and self._items:
                oldest = next(iter(self._items))
                self._remove(oldest)
            return key in self._items

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._weight = 0

    def stats(self) -> dict[str, int]:
        with self._lock:
            self._purge_expired(time.monotonic())
            return {
                "entries": len(self._items),
                "bytes": self._weight,
                "max_bytes": self.max_bytes,
                "max_item_bytes": self.max_item_bytes,
            }


def deep_sizeof(value: Any) -> int:
    """Estimate retained bytes for JSON-like values without double-counting aliases."""

    seen: set[int] = set()

    def measure(item: Any) -> int:
        item_id = id(item)
        if item_id in seen:
            return 0
        seen.add(item_id)
        size = sys.getsizeof(item)
        if isinstance(item, dict):
            size += sum(measure(key) + measure(child) for key, child in item.items())
        elif isinstance(item, (list, tuple, set, frozenset)):
            size += sum(measure(child) for child in item)
        return size

    return measure(value)
