"""Tests for Milestone 1: parsing and call discovery.

Run from the project root with:  python -m pytest -q
(or just: python -m unittest)
"""

import ast
import unittest

from pytaint.parser import (
    CallSite,
    dotted_name,
    find_calls,
    parse_source,
)


class TestDottedName(unittest.TestCase):
    def _first_call_func(self, code: str) -> ast.AST:
        tree = parse_source(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                return node.func
        raise AssertionError("no call found in test code")

    def test_bare_name(self):
        # input(...) -> "input"
        self.assertEqual(dotted_name(self._first_call_func("input()")), "input")

    def test_single_attribute(self):
        # os.system(...) -> "os.system"
        self.assertEqual(
            dotted_name(self._first_call_func("os.system(x)")), "os.system"
        )

    def test_nested_attribute(self):
        # a.b.c(...) -> "a.b.c"
        self.assertEqual(dotted_name(self._first_call_func("a.b.c(x)")), "a.b.c")

    def test_unknown_receiver_collapses(self):
        # get_conn().execute(...) -> the receiver is itself a call, so the
        # left part is unknown and collapses to "<expr>".
        self.assertEqual(
            dotted_name(self._first_call_func("get_conn().execute(q)")),
            "<expr>.execute",
        )


class TestFindCalls(unittest.TestCase):
    def test_counts_and_names(self):
        code = "import os\nos.system('ls')\ninput('x')\n"
        calls = find_calls(parse_source(code))
        names = sorted(c.name for c in calls)
        self.assertEqual(names, ["input", "os.system"])

    def test_line_numbers(self):
        code = "\n\nos.system('ls')\n"  # call is on line 3
        calls = find_calls(parse_source(code))
        self.assertEqual(len(calls), 1)
        self.assertIsInstance(calls[0], CallSite)
        self.assertEqual(calls[0].lineno, 3)

    def test_nested_calls_all_found(self):
        # os.system(input()) contains TWO calls; both should be found.
        code = "os.system(input())"
        calls = find_calls(parse_source(code))
        names = sorted(c.name for c in calls)
        self.assertEqual(names, ["input", "os.system"])


if __name__ == "__main__":
    unittest.main()
