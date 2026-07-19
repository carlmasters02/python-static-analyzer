#!/usr/bin/env python3
"""Milestone 1 demo tool: show the AST work on a file.

Usage:
    python explore_ast.py samples/vuln_command_injection.py
    python explore_ast.py --dump samples/vuln_sql_injection.py

Without --dump it lists every function call and its line number.
With --dump it prints the full AST (great for building intuition).
"""

import argparse
import ast
import os
import sys

# Allow running standalone (python explore_ast.py) without an editable
# install, by putting the src/ layout on the path.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from pytaint.detector import classify_file  # noqa: E402
from pytaint.parser import find_calls_in_file, parse_file  # noqa: E402
from pytaint.taint import analyze_file  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="Explore the AST of a Python file.")
    ap.add_argument("path", help="Python file to analyze")
    ap.add_argument(
        "--dump",
        action="store_true",
        help="print the full indented AST instead of the call list",
    )
    ap.add_argument(
        "--classify",
        action="store_true",
        help="label each call as a source or a sink (Milestone 2)",
    )
    ap.add_argument(
        "--scan",
        action="store_true",
        help="run full taint analysis and report vulnerabilities (Milestone 3)",
    )
    ap.add_argument(
        "--no-taint-params",
        action="store_true",
        help="do NOT treat function parameters as tainted (higher precision)",
    )
    args = ap.parse_args()

    if args.scan:
        findings = analyze_file(
            args.path, assume_tainted_params=not args.no_taint_params
        )
        if not findings:
            print(f"No vulnerabilities found in {args.path}.")
            return
        print(f"Found {len(findings)} vulnerability(ies) in {args.path}:\n")
        for f in findings:
            print(f"  line {f.lineno:>3}: [{f.vuln_class}] {f.sink_name}(...)")
            print(f"             ↳ {f.message}")
        return

    if args.dump:
        tree = parse_file(args.path)
        # ast.dump with indent renders the tree structure readably.
        print(ast.dump(tree, indent=2))
        return

    if args.classify:
        results = classify_file(args.path)
        print(f"Found {len(results)} source(s)/sink(s) in {args.path}:\n")
        for c in results:
            if c.kind == "sink":
                tag = f"SINK [{c.vuln_class}]"
            else:
                tag = "SOURCE"
            print(f"  line {c.lineno:>3}: {tag:<26} {c.name}(...)")
            print(f"             ↳ {c.why}")
        return

    calls = find_calls_in_file(args.path)
    print(f"Found {len(calls)} function call(s) in {args.path}:\n")
    for c in calls:
        print(f"  line {c.lineno:>3}: {c.name}(...)")


if __name__ == "__main__":
    main()
