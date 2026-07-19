"""Milestone 1: turn Python source into an AST and explore it.

This module is intentionally simple. Its whole job is to answer one
question about a file: "what function calls happen in it, and where?"

Everything the analyzer does later is built on top of this — sources and
sinks are both just *specific kinds of function calls*, so we start by
learning to find calls at all.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass
class CallSite:
    """A single function call found in the source code.

    Attributes:
        name: The dotted name being called, as written in the source.
              e.g. ``os.system`` or ``cursor.execute`` or ``input``.
        lineno: 1-based line number where the call appears.
        col: 0-based column offset (handy for pointing at the exact spot).
        node: The raw ``ast.Call`` node, in case we need more detail later.
    """

    name: str
    lineno: int
    col: int
    node: ast.Call


def parse_source(source: str, filename: str = "<unknown>") -> ast.Module:
    """Parse Python source text into an AST.

    ``ast.parse`` is the front door to the whole ``ast`` module. It takes
    a string of Python code and hands back the root of the tree (a
    ``Module`` node). If the code has a syntax error, it raises
    ``SyntaxError`` — we pass ``filename`` through so that error message
    tells you *which* file was bad.
    """
    return ast.parse(source, filename=filename)


def parse_file(path: str) -> ast.Module:
    """Read a file from disk and parse it into an AST."""
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    return parse_source(source, filename=path)


def dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted name from the AST node in a call's ``func`` slot.

    When you write ``os.system(...)`` the parser stores the ``os.system``
    part as a nested structure:

        Attribute(attr="system", value=Name(id="os"))

    We want the flat string ``"os.system"`` back. This function walks that
    nesting and rebuilds it. For a bare call like ``input(...)`` the func is
    just ``Name(id="input")`` and we return ``"input"``.

    Anything we don't understand (e.g. calling the result of another call,
    like ``get_conn().execute(...)``) collapses to ``"<expr>"`` for the
    unknown part — good enough for now.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted_name(node.value)}.{node.attr}"
    return "<expr>"


def find_calls(tree: ast.Module) -> list[CallSite]:
    """Walk the whole tree and collect every function call.

    ``ast.walk`` yields every node in the tree in no particular order.
    We keep only the ``Call`` nodes — those are function/method calls.
    """
    calls: list[CallSite] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.append(
                CallSite(
                    name=dotted_name(node.func),
                    lineno=node.lineno,
                    col=node.col_offset,
                    node=node,
                )
            )
    return calls


def find_calls_in_file(path: str) -> list[CallSite]:
    """Convenience wrapper: parse a file and list its calls."""
    return find_calls(parse_file(path))
