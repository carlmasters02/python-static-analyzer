"""Tests for Milestone 2: source/sink classification."""

import unittest

from pytaint.detector import classify_calls
from pytaint.parser import find_calls, parse_source
from pytaint.signatures import (
    is_source_call,
    is_source_name,
    sink_for,
)


def classify_code(code: str):
    """Helper: parse code and return its classifications."""
    return classify_calls(find_calls(parse_source(code)))


class TestSinkLookup(unittest.TestCase):
    def test_exact_command_sink(self):
        s = sink_for("os.system")
        self.assertIsNotNone(s)
        self.assertEqual(s.vuln_class, "command-injection")

    def test_subprocess_sink(self):
        self.assertEqual(sink_for("subprocess.Popen").vuln_class, "command-injection")

    def test_execute_suffix_any_receiver(self):
        # The receiver name varies in real code; all should match .execute.
        for name in ("cursor.execute", "db.execute", "self.conn.execute", "c.execute"):
            with self.subTest(name=name):
                s = sink_for(name)
                self.assertIsNotNone(s, name)
                self.assertEqual(s.vuln_class, "sql-injection")

    def test_non_sink_returns_none(self):
        self.assertIsNone(sink_for("os.path.join"))
        self.assertIsNone(sink_for("print"))

    def test_execute_as_full_name_not_falsely_exact(self):
        # A bare 'execute()' with no receiver still matches by suffix.
        self.assertIsNotNone(sink_for("execute"))


class TestSourceLookup(unittest.TestCase):
    def test_input_is_source_call(self):
        self.assertTrue(is_source_call("input"))

    def test_flask_getters_are_source_calls(self):
        self.assertTrue(is_source_call("request.args.get"))

    def test_request_args_is_source_name(self):
        self.assertTrue(is_source_name("request.args"))
        self.assertTrue(is_source_name("request.form"))

    def test_sys_argv_is_source_name(self):
        self.assertTrue(is_source_name("sys.argv"))

    def test_ordinary_name_is_not_source(self):
        self.assertFalse(is_source_name("my_config.value"))
        self.assertFalse(is_source_call("compute_total"))


class TestClassifyCalls(unittest.TestCase):
    def test_command_injection_shape(self):
        results = classify_code("import os\nhost = input()\nos.system('ping ' + host)\n")
        kinds = {(c.name, c.kind, c.vuln_class) for c in results}
        self.assertIn(("input", "source", None), kinds)
        self.assertIn(("os.system", "sink", "command-injection"), kinds)

    def test_sql_injection_shape(self):
        results = classify_code("cursor.execute('SELECT ' + x)\n")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].kind, "sink")
        self.assertEqual(results[0].vuln_class, "sql-injection")

    def test_neither_dropped(self):
        # print() and len() are neither sources nor sinks.
        self.assertEqual(classify_code("print(len('hi'))"), [])


if __name__ == "__main__":
    unittest.main()
