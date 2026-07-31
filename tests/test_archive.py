from __future__ import annotations

from pathlib import Path

import pytest

from sub2api_recorder.archive import _decrypt_file, _encrypt_file
from sub2api_recorder.compression import compress_stream, decompress_stream


def test_archive_encryption_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    original = tmp_path / "original"
    compressed = tmp_path / "compressed"
    encrypted = tmp_path / "encrypted"
    decrypted = tmp_path / "decrypted"
    restored = tmp_path / "restored"
    original.write_bytes((b"sub2api-audit-data-" * 10000) + b"end")

    with original.open("rb") as source, compressed.open("wb") as destination:
        compression = compress_stream(source, destination)
    key = b"k" * 32
    _encrypt_file(compressed, encrypted, key, "test-key", compression)
    header = _decrypt_file(encrypted, decrypted, key)
    with decrypted.open("rb") as source, restored.open("wb") as destination:
        decompress_stream(source, destination, header["compression"])
    assert restored.read_bytes() == original.read_bytes()

    tampered = bytearray(encrypted.read_bytes())
    tampered[-1] ^= 1
    encrypted.write_bytes(tampered)
    with pytest.raises(Exception):
        _decrypt_file(encrypted, decrypted, key)

