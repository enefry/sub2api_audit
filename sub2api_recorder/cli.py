from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .archive import ArchiveManager
from .config import ConfigError, Settings
from .storage import database_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sub2api-recorder")
    subcommands = parser.add_subparsers(dest="command", required=True)

    archive = subcommands.add_parser("archive", help="archive one sealed month")
    archive.add_argument("--month", required=True, help="month in YYYY-MM form")

    restore = subcommands.add_parser("restore", help="restore one month from S3")
    restore.add_argument("--month", required=True, help="month in YYYY-MM form")
    restore.add_argument("--destination", type=Path)
    restore.add_argument("--overwrite", action="store_true")
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        settings = Settings.from_env()
        manager = ArchiveManager(settings.data_dir, settings.archive)
        if args.command == "archive":
            if args.month == datetime.now(settings.timezone).strftime("%Y-%m"):
                raise ValueError("the current writable month cannot be archived")
            path = database_path(settings.data_dir, args.month)
            manifest = manager.archive_file(path)
            print(
                f"archived {manifest['month']}: "
                f"{manifest['records']} records, {manifest['object_key']}"
            )
        elif args.command == "restore":
            destination = args.destination or database_path(
                settings.data_dir, args.month
            )
            restored = manager.restore(args.month, destination, args.overwrite)
            print(f"restored {args.month} to {restored}")
    except (ConfigError, ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
