"""Tests for the command-line behavior (argument parsing + output).

`main` accepts an argv list, so we can drive the CLI in-process without
spawning a subprocess. `capsys` is a built-in pytest fixture that captures
anything printed to stdout/stderr so we can assert on it.
"""

import pytest

from hello_cli.cli import main


def test_main_default_prints_hello_world(capsys):
    exit_code = main([])
    assert capsys.readouterr().out.strip() == "Hello, World!"
    assert exit_code == 0  # 0 = success, the Unix convention


def test_main_with_name(capsys):
    exit_code = main(["--name", "Ada"])
    assert capsys.readouterr().out.strip() == "Hello, Ada!"
    assert exit_code == 0


def test_main_short_flag(capsys):
    main(["-n", "Bob"])
    assert capsys.readouterr().out.strip() == "Hello, Bob!"


def test_version_flag_exits_zero(capsys):
    # argparse's --version prints the version and raises SystemExit(0).
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "1.0.0" in capsys.readouterr().out


def test_unknown_flag_exits_nonzero():
    # A bad flag should fail loudly with a non-zero exit code, not
    # silently succeed. "Fail loud" is a habit worth building early.
    with pytest.raises(SystemExit) as exc:
        main(["--does-not-exist"])
    assert exc.value.code != 0
