from __future__ import annotations

from pathlib import Path

from loguru import logger


LOG_ROTATION = "10 MB"
MAX_LOG_FILES = 6
# Loguru retention counts rotated files but excludes the active file.
ROTATED_LOG_RETENTION = MAX_LOG_FILES - 1
LOG_FILENAME = "sub2api-recorder.log"
LOG_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS Z} | {level: <8} | "
    "{name}:{function}:{line} - {message}"
)


def configure_file_logging(data_dir: Path) -> tuple[int, Path]:
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / LOG_FILENAME
    handler_id = logger.add(
        log_path,
        rotation=LOG_ROTATION,
        retention=ROTATED_LOG_RETENTION,
        encoding="utf-8",
        enqueue=True,
        backtrace=False,
        diagnose=False,
        format=LOG_FORMAT,
    )
    return handler_id, log_path


def remove_file_logging(handler_id: int) -> None:
    logger.remove(handler_id)
