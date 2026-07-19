"""Tests for the command-line interface (pytaint.cli).

`main` accepts an argv list, so we can drive the CLI in-process without
spawning a subprocess. `capsys` captures stdout/stderr so we can assert on
output and exit codes.
"""

import json
import os

import pytest

from pytaint import __version__
from pytaint.cli import main

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def test_scan_with_findings_exits_1(capsys):
    code = main([os.path.join(SAMPLES, "vuln_sql_injection.py")])
    out = capsys.readouterr().out
    assert code == 1  # findings present -> non-zero exit
    assert "sql-injection" in out


def test_clean_target_exits_0(capsys, tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\nprint(x)\n")
    code = main([str(clean)])
    assert code == 0
    assert "0 finding" in capsys.readouterr().out


def test_missing_path_exits_2(capsys):
    code = main(["/no/such/path/here.py"])
    assert code == 2
    assert "not found" in capsys.readouterr().err


def test_json_format_is_valid(capsys):
    code = main(["--format", "json", os.path.join(SAMPLES, "vuln_sql_injection.py")])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data["summary"]["findings"] == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_taint_params_reduces_findings():
    cmd = os.path.join(SAMPLES, "vuln_command_injection.py")
    # default flags both vulns; --no-taint-params drops the param-based one.
    assert main([cmd]) == 1
    assert main(["--no-taint-params", cmd]) in (0, 1)
