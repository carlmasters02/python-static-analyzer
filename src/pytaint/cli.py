"""Command-line interface for pytaint.

Follows the repo template's pattern: the argument-parsing plumbing
(`build_parser` / `main`) is kept separate from the analysis logic, which
lives in the rest of the package (parser -> signatures -> taint -> scanner).

Usage:
    pytaint samples/
    pytaint --format json path/to/repo > findings.json
    pytaint --no-taint-params path/to/repo

Exit codes:
    0  no findings
    1  findings were reported
    2  bad usage / path not found
"""

from __future__ import annotations

import argparse
import os
import sys

from pytaint import __version__
from pytaint.reporting import format_json, format_text
from pytaint.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser. Separated out so tests can inspect it."""
    parser = argparse.ArgumentParser(
        prog="pytaint",
        description="Detect SQL/command injection in Python via taint analysis.",
    )
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--no-taint-params",
        action="store_true",
        help="do NOT treat function parameters as tainted "
        "(higher precision, lower recall)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors in text output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code (0 = clean, 1 = findings).

    `argv` defaults to None so argparse reads real command-line args in
    production, but tests can pass a list like ["samples/"] directly.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    result = scan_path(args.path, assume_tainted_params=not args.no_taint_params)

    if args.format == "json":
        print(format_json(result))
    else:
        # Auto-disable color when piping to a file/pipe.
        use_color = not args.no_color and sys.stdout.isatty()
        print(format_text(result, use_color=use_color))

    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
