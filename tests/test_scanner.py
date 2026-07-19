"""Tests for Milestone 4: directory scanning, robustness, and reporting."""

import json
import os
import tempfile
import unittest

from pytaint.reporting import format_json, format_text
from pytaint.scanner import iter_python_files, scan_file, scan_path


class TestScanRobustness(unittest.TestCase):
    def test_survives_syntax_error(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "good.py")
            bad = os.path.join(d, "bad.py")
            with open(good, "w") as f:
                f.write("import os\nh = input()\nos.system('ping ' + h)\n")
            with open(bad, "w") as f:
                f.write("def broken(:\n    this is not valid python\n")

            result = scan_path(d)
            # The good file was analyzed and produced a finding...
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.files_scanned, 1)
            # ...and the bad file was skipped, not fatal, and surfaced.
            self.assertEqual(len(result.skipped), 1)
            self.assertIn("syntax error", result.skipped[0][1])

    def test_scan_file_returns_reason_on_bad_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("def x(:\n")
            path = f.name
        try:
            findings, reason = scan_file(path)
            self.assertEqual(findings, [])
            self.assertIsNotNone(reason)
        finally:
            os.unlink(path)


class TestFileDiscovery(unittest.TestCase):
    def test_skips_noise_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".git"))
            os.makedirs(os.path.join(d, "pkg"))
            with open(os.path.join(d, ".git", "hook.py"), "w") as f:
                f.write("import os\nos.system(input())\n")
            with open(os.path.join(d, "pkg", "app.py"), "w") as f:
                f.write("x = 1\n")
            files = list(iter_python_files(d))
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].endswith("app.py"))

    def test_single_file_path(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("x = 1\n")
            path = f.name
        try:
            self.assertEqual(list(iter_python_files(path)), [path])
        finally:
            os.unlink(path)


class TestReporting(unittest.TestCase):
    def _sample_result(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "v.py")
            with open(p, "w") as f:
                f.write("import os\nh = input()\nos.system('ping ' + h)\n")
            return scan_path(d)

    def test_json_is_valid_and_structured(self):
        result = self._sample_result()
        data = json.loads(format_json(result))
        self.assertEqual(data["summary"]["findings"], 1)
        self.assertEqual(data["findings"][0]["vuln_class"], "command-injection")
        self.assertIn("line", data["findings"][0])

    def test_text_has_no_color_when_disabled(self):
        result = self._sample_result()
        text = format_text(result, use_color=False)
        self.assertNotIn("\033[", text)
        self.assertIn("command-injection", text)


if __name__ == "__main__":
    unittest.main()
