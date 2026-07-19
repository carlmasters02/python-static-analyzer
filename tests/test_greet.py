"""Unit tests for the pure `greet` function.

These are the simplest kind of test: call a function with an input,
assert on its output. No files, no processes, no mocking needed —
which is the payoff of keeping `greet` pure.
"""

from hello_cli.cli import greet


def test_greet_default():
    assert greet() == "Hello, World!"


def test_greet_named():
    assert greet("Ada") == "Hello, Ada!"


def test_greet_empty_string():
    # An edge case: empty name shouldn't crash, just greets nobody.
    assert greet("") == "Hello, !"
