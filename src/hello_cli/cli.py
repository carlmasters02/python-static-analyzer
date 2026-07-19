"""Command-line interface for the hello tool.

Kept deliberately small: one pure function (`greet`) that is easy to test,
plus the argument-parsing plumbing (`build_parser` / `main`) around it.
"""

from __future__ import annotations

import argparse
import sys

from hello_cli import __version__


def greet(name: str = "World") -> str:
    """Return a friendly greeting.

    This is a *pure* function: same input -> same output, no printing,
    no file access, no network. Pure functions are the easiest things in
    the world to unit-test, which is why the real logic lives here.
    """
    return f"Hello, {name}!"


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser. Separated out so tests can inspect it."""
    parser = argparse.ArgumentParser(
        prog="hello",
        description="A tiny CLI that greets you.",
    )
    parser.add_argument(
        "-n",
        "--name",
        default="World",
        help="Name to greet (default: World).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code (0 = success).

    `argv` defaults to None so argparse reads real command-line args in
    production, but tests can pass a list like ["--name", "Ada"] directly.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    print(greet(args.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
