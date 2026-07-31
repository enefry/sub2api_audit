from __future__ import annotations

import hashlib
import hmac

from sub2api_recorder.security import extract_token, fingerprint_token, secrets_equal


def test_bearer_token_is_fingerprinted_and_masked() -> None:
    token = "sk-super-secret-1234"
    key = b"audit-hmac-key"
    extracted, source = extract_token(
        {"authorization": f"Bearer {token}", "x-api-key": "secondary"}
    )
    assert extracted == token
    assert source == "authorization"

    result = fingerprint_token(extracted, source, key)
    assert result.fingerprint == hmac.new(
        key, token.encode(), hashlib.sha256
    ).hexdigest()
    assert result.masked == "…1234"
    assert token not in result.fingerprint


def test_api_key_fallback_and_constant_time_comparison() -> None:
    assert extract_token({"x-api-key": "abc"}) == ("abc", "x-api-key")
    assert extract_token({}) == (None, None)
    assert secrets_equal("same", "same")
    assert not secrets_equal("different", "same")
    assert not secrets_equal(None, "same")
    assert fingerprint_token("tiny", "x-api-key", b"k").masked == "…"
