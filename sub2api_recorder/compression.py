from __future__ import annotations

import io
import zlib
from typing import BinaryIO

try:
    import zstandard
except ImportError:  # Allows basic diagnostics before dependencies are installed.
    zstandard = None


def compress_bytes(value: bytes) -> tuple[str, bytes]:
    if zstandard is not None:
        return "zstd", zstandard.ZstdCompressor(level=7).compress(value)
    return "zlib", zlib.compress(value, level=6)


def decompress_bytes(
    encoding: str, value: bytes, expected_size: int | None = None
) -> bytes:
    if encoding == "zstd":
        if zstandard is None:
            raise RuntimeError("zstandard is required to read this content")
        if expected_size is not None:
            return zstandard.ZstdDecompressor().decompress(
                value, max_output_size=expected_size
            )
        return zstandard.ZstdDecompressor().decompress(value)
    if encoding == "zlib":
        return zlib.decompress(value)
    if encoding == "identity":
        return value
    raise ValueError(f"unsupported content encoding: {encoding}")


def compress_stream(source: BinaryIO, destination: BinaryIO) -> str:
    if zstandard is None:
        compressor = zlib.compressobj(level=9)
        while chunk := source.read(1024 * 1024):
            destination.write(compressor.compress(chunk))
        destination.write(compressor.flush())
        return "zlib"
    compressor = zstandard.ZstdCompressor(level=12)
    compressor.copy_stream(source, destination)
    return "zstd"


def decompress_stream(
    source: BinaryIO, destination: BinaryIO, encoding: str = "zstd"
) -> None:
    if encoding == "zlib":
        decompressor = zlib.decompressobj()
        while chunk := source.read(1024 * 1024):
            destination.write(decompressor.decompress(chunk))
        destination.write(decompressor.flush())
        return
    if encoding != "zstd":
        raise ValueError(f"unsupported stream encoding: {encoding}")
    if zstandard is None:
        raise RuntimeError("zstandard is required to decompress this archive")
    decompressor = zstandard.ZstdDecompressor()
    decompressor.copy_stream(source, destination)


def compress_file_to_bytes(source: BinaryIO) -> tuple[str, bytes]:
    output = io.BytesIO()
    compress_stream(source, output)
    return ("zstd" if zstandard is not None else "zlib"), output.getvalue()
