from __future__ import annotations

import argparse
import sys

from backend.archive import ArchiveError, extract_archive


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sparz",
        description="Extract and inspect PyInstaller executables.",
    )
    parser.add_argument("filename", help="Path to the PyInstaller executable")
    parser.add_argument(
        "-d",
        "--one-dir",
        action="store_true",
        help="Extract PYZ contents into the same directory as CArchive files",
    )
    parser.add_argument(
        "-i",
        "--info",
        action="store_true",
        help="Show archive information only (do not extract)",
    )
    parser.add_argument(
        "-o",
        "--out",
        default=None,
        help="Output directory (default: <exe>_extracted in the current directory)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        extract_archive(
            args.filename, out_dir=args.out, one_dir=args.one_dir, info_only=args.info
        )
    except ArchiveError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
