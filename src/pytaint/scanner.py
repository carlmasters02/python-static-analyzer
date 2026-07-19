"""Milestone 4: scan files and whole directory trees.

The taint engine (Milestone 3) analyzes one parsed module. This layer
sits on top and deals with the messy real world:
  - finding all the .py files under a directory
  - reading + parsing each one, and *surviving* the ones that fail
    (syntax errors, Python 2 code, bad encodings)
  - collecting every Finding, plus a record of what we skipped
"""

from __future__ import annotations

import ast
import os
import warnings
from dataclasses import dataclass, field

from .taint import Finding, analyze_tree


@dataclass
class ScanResult:
    """Everything one scan produced."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    # (path, reason) for files we couldn't analyze — surfaced, never silent.
    skipped: list[tuple[str, str]] = field(default_factory=list)


def iter_python_files(root: str):
    """Yield every .py file at or under `root` (a file or a directory)."""
    if os.path.isfile(root):
        if root.endswith(".py"):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip common virtualenv / VCS / cache dirs — noise, not user code.
        dirnames[:] = [
            d
            for d in dirnames
            if d not in {".git", ".venv", "venv", "__pycache__", ".tox", "node_modules"}
        ]
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def scan_file(path: str, assume_tainted_params: bool = True) -> tuple[list[Finding], str | None]:
    """Analyze one file. Returns (findings, skip_reason).

    skip_reason is None on success, or a short string if the file couldn't
    be analyzed. We never raise — a bad file must not stop the whole scan.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except (UnicodeDecodeError, OSError) as e:
        return [], f"could not read: {e.__class__.__name__}"

    try:
        # Some files trigger SyntaxWarning (e.g. invalid escape sequences)
        # during parse — those are noise for us, not analysis results.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        return [], f"syntax error: line {e.lineno}"
    except (ValueError, RecursionError) as e:
        return [], f"parse failed: {e.__class__.__name__}"

    findings = analyze_tree(
        tree, filename=path, assume_tainted_params=assume_tainted_params
    )
    return findings, None


def scan_path(root: str, assume_tainted_params: bool = True) -> ScanResult:
    """Scan a file or directory tree and aggregate results."""
    result = ScanResult()
    for path in iter_python_files(root):
        findings, skip_reason = scan_file(
            path, assume_tainted_params=assume_tainted_params
        )
        if skip_reason is not None:
            result.skipped.append((path, skip_reason))
            continue
        result.files_scanned += 1
        result.findings.extend(findings)
    # Deterministic ordering: by file, then line.
    result.findings.sort(key=lambda f: (f.filename, f.lineno))
    return result
