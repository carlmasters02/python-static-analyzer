#!/usr/bin/env python3
"""Benchmark scorer: measure precision / recall against labeled cases.

Ground truth lives inline in benchmark/cases/*.py as trailing markers:
    #@ VULN   this line is a real vulnerability   (positive)
    #@ SAFE   this line is safe                    (negative)

We run the analyzer over those files and compare its findings (by line
number) against the markers:

    TP  finding on a  VULN line
    FP  finding on a  SAFE line  (or any unmarked line)
    FN  VULN line with no finding
    TN  SAFE line with no finding

Run:
    python -m benchmark.score
    python -m benchmark.score --no-taint-params
    python -m benchmark.score --write-readme     # refresh the README table
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys

# Allow running standalone (python -m benchmark.score) without an editable
# install, by putting the src/ layout on the path.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from pytaint.scanner import scan_file  # noqa: E402

CASES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")
MARKER_RE = re.compile(r"#@\s*(VULN|SAFE)\b")


def load_ground_truth(path: str) -> dict[int, str]:
    """Return {line_number: 'VULN'|'SAFE'} for every marked *call* line.

    A marker only counts as ground truth when it's a trailing comment on a
    real call line — i.e. there's a '(' in the code before the '#@'. This
    stops prose inside docstrings that merely *mentions* the markers from
    being mistaken for ground truth.
    """
    truth: dict[int, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            m = MARKER_RE.search(line)
            if m and "(" in line[: m.start()]:
                truth[i] = m.group(1)
    return truth


class Counts:
    def __init__(self) -> None:
        self.tp = self.fp = self.fn = self.tn = 0

    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0


def score(assume_tainted_params: bool = True):
    counts = Counts()
    mismatches: list[str] = []

    for path in sorted(glob.glob(os.path.join(CASES_DIR, "*.py"))):
        truth = load_ground_truth(path)
        findings, skip = scan_file(path, assume_tainted_params=assume_tainted_params)
        if skip:
            print(f"WARNING: could not scan {path}: {skip}", file=sys.stderr)
            continue
        flagged = {f.lineno for f in findings}

        for line, label in truth.items():
            was_flagged = line in flagged
            rel = os.path.relpath(path)
            if label == "VULN" and was_flagged:
                counts.tp += 1
            elif label == "VULN" and not was_flagged:
                counts.fn += 1
                mismatches.append(f"  FN (missed vuln)  {rel}:{line}")
            elif label == "SAFE" and was_flagged:
                counts.fp += 1
                mismatches.append(f"  FP (false alarm)  {rel}:{line}")
            else:  # SAFE, not flagged
                counts.tn += 1

        # Findings on unmarked lines are unexpected false positives.
        for line in flagged:
            if line not in truth:
                counts.fp += 1
                mismatches.append(
                    f"  FP (unexpected)   {os.path.relpath(path)}:{line}"
                )

    return counts, mismatches


def print_report(counts: Counts, mismatches: list[str], mode: str) -> None:
    total = counts.tp + counts.fp + counts.fn + counts.tn
    print(f"\nBenchmark results  [{mode}]")
    print("=" * 44)
    print(f"  cases evaluated : {total}")
    print(f"  true positives  : {counts.tp}")
    print(f"  false positives : {counts.fp}")
    print(f"  false negatives : {counts.fn}")
    print(f"  true negatives  : {counts.tn}")
    print("-" * 44)
    print(f"  precision : {counts.precision():.2%}")
    print(f"  recall    : {counts.recall():.2%}")
    print(f"  F1        : {counts.f1():.2%}")
    if mismatches:
        print("\n  where we differ from ground truth:")
        for line in mismatches:
            print(line)
    print()


def readme_table() -> str:
    """Build the markdown block the README embeds (both modes)."""
    rows = []
    for label, kw in (
        ("default (params tainted)", {"assume_tainted_params": True}),
        ("--no-taint-params", {"assume_tainted_params": False}),
    ):
        c, _ = score(**kw)
        rows.append(
            f"| {label} | {c.tp} | {c.fp} | {c.fn} | {c.tn} | "
            f"{c.precision():.0%} | {c.recall():.0%} | {c.f1():.0%} |"
        )
    header = (
        "| Mode | TP | FP | FN | TN | Precision | Recall | F1 |\n"
        "|------|---:|---:|---:|---:|----------:|-------:|---:|\n"
    )
    return header + "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-taint-params", action="store_true")
    ap.add_argument(
        "--write-readme",
        action="store_true",
        help="print the markdown table for pasting into the README",
    )
    args = ap.parse_args()

    if args.write_readme:
        print(readme_table())
        return 0

    assume = not args.no_taint_params
    mode = "no-taint-params" if args.no_taint_params else "default (params tainted)"
    counts, mismatches = score(assume_tainted_params=assume)
    print_report(counts, mismatches, mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
