from __future__ import annotations

from pathlib import Path

from loguru import logger

from sub2api_recorder import logging_config


def test_file_logging_uses_bounded_rotation(
    tmp_path: Path, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def fake_add(sink, **options):
        captured["sink"] = sink
        captured.update(options)
        return 42

    monkeypatch.setattr(logging_config.logger, "add", fake_add)

    handler_id, log_path = logging_config.configure_file_logging(tmp_path)

    assert handler_id == 42
    assert log_path == tmp_path / "logs" / "sub2api-recorder.log"
    assert log_path.parent.is_dir()
    assert captured["sink"] == log_path
    assert captured["rotation"] == "10 MB"
    assert captured["retention"] == 5
    assert captured["retention"] + 1 == logging_config.MAX_LOG_FILES
    assert captured["enqueue"] is True
    assert captured["diagnose"] is False


def test_file_logging_writes_and_flushes(tmp_path: Path) -> None:
    handler_id, log_path = logging_config.configure_file_logging(tmp_path)
    try:
        logger.info("file logging smoke test")
    finally:
        logging_config.remove_file_logging(handler_id)

    text = log_path.read_text(encoding="utf-8")
    assert "file logging smoke test" in text
    assert " | INFO " in text


def test_file_logging_keeps_at_most_six_total_files(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(logging_config, "LOG_ROTATION", "1 KB")
    handler_id, log_path = logging_config.configure_file_logging(tmp_path)
    try:
        for index in range(12):
            logger.info("rotation-check-{} {}", index, "x" * 600)
    finally:
        logging_config.remove_file_logging(handler_id)

    log_files = list(log_path.parent.glob("sub2api-recorder*.log"))
    assert len(log_files) == logging_config.MAX_LOG_FILES
    assert all(path.stat().st_size <= 1_000 for path in log_files)
