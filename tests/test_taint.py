"""Tests for Milestone 3: the taint engine.

These are the most important tests in the project — they pin down exactly
which flows are vulnerabilities and which are safe.
"""

import ast
import os
import unittest

from pytaint.taint import analyze_file, analyze_tree, is_tainted


def scan(code: str, **kw):
    tree = ast.parse(code)
    return analyze_tree(tree, filename="<test>", **kw)


def vuln_classes(code: str, **kw):
    return sorted(f.vuln_class for f in scan(code, **kw))


SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


class TestTaintPropagation(unittest.TestCase):
    def test_input_taints_variable_reaching_shell(self):
        code = "import os\nh = input()\nos.system('ping ' + h)\n"
        self.assertEqual(vuln_classes(code), ["command-injection"])

    def test_fstring_propagates_taint(self):
        code = "import os\nh = input()\nos.system(f'ping {h}')\n"
        self.assertEqual(vuln_classes(code), ["command-injection"])

    def test_format_propagates_taint(self):
        code = "import os\nh = input()\nos.system('ping {}'.format(h))\n"
        self.assertEqual(vuln_classes(code), ["command-injection"])

    def test_percent_propagates_taint(self):
        code = "import os\nh = input()\nos.system('ping %s' % h)\n"
        self.assertEqual(vuln_classes(code), ["command-injection"])

    def test_multi_hop_propagation(self):
        code = (
            "import os\n"
            "a = input()\n"
            "b = 'x' + a\n"
            "c = b\n"
            "os.system(c)\n"
        )
        self.assertEqual(vuln_classes(code), ["command-injection"])

    def test_sql_concat_flagged(self):
        code = "u = input()\ncursor.execute('SELECT * FROM t WHERE n=' + u)\n"
        self.assertEqual(vuln_classes(code), ["sql-injection"])


class TestSafeCases(unittest.TestCase):
    def test_constant_command_is_safe(self):
        code = "import os\nos.system('ls -la')\n"
        self.assertEqual(scan(code), [])

    def test_constant_sql_is_safe(self):
        code = "cursor.execute('SELECT COUNT(*) FROM t')\n"
        self.assertEqual(scan(code), [])

    def test_parameterized_sql_is_safe(self):
        # tainted value goes in the params tuple, not the query string.
        code = "u = input()\ncursor.execute('SELECT * FROM t WHERE n=?', (u,))\n"
        self.assertEqual(scan(code), [])

    def test_subprocess_list_no_shell_is_safe(self):
        code = "import subprocess\nh = input()\nsubprocess.run(['ping', h], shell=False)\n"
        self.assertEqual(scan(code), [])

    def test_subprocess_shell_true_is_flagged(self):
        code = "import subprocess\nh = input()\nsubprocess.call('ping ' + h, shell=True)\n"
        self.assertEqual(vuln_classes(code), ["command-injection"])

    def test_shlex_quote_sanitizes(self):
        code = (
            "import os, shlex\n"
            "h = input()\n"
            "os.system('ping ' + shlex.quote(h))\n"
        )
        self.assertEqual(scan(code), [])

    def test_int_sanitizes(self):
        code = "import os\nh = input()\nos.system('sleep ' + str(int(h)))\n"
        self.assertEqual(scan(code), [])


class TestTaintedParams(unittest.TestCase):
    def test_param_tainted_by_default(self):
        code = "import os\ndef f(name):\n    os.system('echo ' + name)\n"
        self.assertEqual(vuln_classes(code), ["command-injection"])

    def test_param_not_tainted_when_disabled(self):
        code = "import os\ndef f(name):\n    os.system('echo ' + name)\n"
        self.assertEqual(scan(code, assume_tainted_params=False), [])

    def test_self_is_not_tainted(self):
        code = "import os\nclass C:\n    def m(self):\n        os.system('ls')\n"
        self.assertEqual(scan(code), [])


class TestAgainstSampleFiles(unittest.TestCase):
    """Ground-truth check: our labeled samples should yield exactly the
    vulnerabilities marked VULNERABLE and nothing marked SAFE."""

    def test_command_injection_sample(self):
        path = os.path.join(SAMPLES_DIR, "vuln_command_injection.py")
        findings = analyze_file(path)
        lines = sorted(f.lineno for f in findings)
        # VULNERABLE functions: ping_host_vulnerable (os.system line 15),
        # backup_vulnerable (subprocess.call shell=True line 20).
        self.assertEqual(lines, [15, 20])
        self.assertTrue(all(f.vuln_class == "command-injection" for f in findings))

    def test_sql_injection_sample(self):
        path = os.path.join(SAMPLES_DIR, "vuln_sql_injection.py")
        findings = analyze_file(path)
        lines = sorted(f.lineno for f in findings)
        # VULNERABLE: get_user_vulnerable (line 12), search_vulnerable (line 20).
        self.assertEqual(lines, [12, 20])
        self.assertTrue(all(f.vuln_class == "sql-injection" for f in findings))


class TestIsTaintedUnit(unittest.TestCase):
    def test_plain_constant_not_tainted(self):
        node = ast.parse("'hello'", mode="eval").body
        self.assertFalse(is_tainted(node, set()))

    def test_name_in_set_tainted(self):
        node = ast.parse("x", mode="eval").body
        self.assertTrue(is_tainted(node, {"x"}))


if __name__ == "__main__":
    unittest.main()
