"""pytest bootstrap.

With the src/ layout, the ``pytaint`` package isn't importable until it's
installed. For the normal workflow you run ``pip install -e ".[dev]"`` first
(that's what CI does). This shim additionally puts ``src/`` on the path so
``pytest`` also works from a fresh checkout with no install, and makes the
repo root importable so the top-level ``benchmark`` package resolves.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
for _p in (_ROOT, os.path.join(_ROOT, "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
