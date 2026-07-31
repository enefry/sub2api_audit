from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Mapping


class BodyTooLargeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TokenFingerprint:
    fingerprint: str
    masked: str
    source: str


def secrets_equal(left: str | None, right: str) -> bool:
    if left is None:
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def extract_token(headers: Mapping[str, str]) -> tuple[str | None, str | None]:
    authorization = headers.get("authorization")
    if authorization:
        scheme, separator, value = authorization.partition(" ")
        if separator and scheme.lower() == "bearer" and value.strip():
            return value.strip(), "authorization"
    for key in ("x-api-key", "api-key", "x-goog-api-key"):
        value = headers.get(key)
        if value and value.strip():
            return value.strip(), key
    return None, None


def fingerprint_token(token: str, source: str, key: bytes) -> TokenFingerprint:
    digest = hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()
    suffix = token[-4:] if len(token) >= 8 else ""
    masked = f"…{suffix}" if suffix else "…"
    return TokenFingerprint(fingerprint=digest, masked=masked, source=source)
