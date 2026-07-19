"""Enables `python -m pytaint ...` as an alias for the `pytaint` command."""

import sys

from pytaint.cli import main

if __name__ == "__main__":
    sys.exit(main())
