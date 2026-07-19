"""Milestone 4: turn a ScanResult into human- or machine-readable output."""

from __future__ import annotations

import json

from .scanner import ScanResult

# ANSI colors (disabled automatically when output isn't a terminal).
_RED = "\033[31m"
_YELLOW = "\033[33m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def format_text(result: ScanResult, use_color: bool = True) -> str:
    """Human-readable report."""

    def c(code: str, s: str) -> str:
        return f"{code}{s}{_RESET}" if use_color else s

    lines: list[str] = []
    for f in result.findings:
        loc = c(_BOLD, f"{f.filename}:{f.lineno}")
        tag = c(_RED, f"[{f.vuln_class}]")
        lines.append(f"{loc} {tag}")
        lines.append(f"    {f.message}")
        lines.append("")

    n = len(result.findings)
    summary = c(_BOLD, f"{n} finding(s)") + f" across {result.files_scanned} file(s) scanned"
    lines.append(summary)

    if result.skipped:
        lines.append(
            c(_YELLOW, f"{len(result.skipped)} file(s) skipped (unparseable):")
        )
        for path, reason in result.skipped:
            lines.append(c(_DIM, f"    {path} — {reason}"))

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Machine-readable report — used by the benchmark scorer later."""
    payload = {
        "summary": {
            "findings": len(result.findings),
            "files_scanned": result.files_scanned,
            "files_skipped": len(result.skipped),
        },
        "findings": [
            {
                "file": f.filename,
                "line": f.lineno,
                "col": f.col,
                "vuln_class": f.vuln_class,
                "sink": f.sink_name,
                "message": f.message,
            }
            for f in result.findings
        ],
        "skipped": [{"file": p, "reason": r} for p, r in result.skipped],
    }
    return json.dumps(payload, indent=2)
