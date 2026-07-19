"""Milestone 2: classify each call as a source, a sink, or neither.

This is a pure *labeling* pass. It does NOT decide whether anything is a
real vulnerability — it only answers "what kind of interesting thing is
this call?" Connecting sources to sinks (the actual bug detection) is
Milestone 3.
"""

from __future__ import annotations

from dataclasses import dataclass

from .parser import CallSite, find_calls, parse_file
from .signatures import Sink, is_source_call, sink_for


@dataclass
class Classification:
    """The label we attach to one call site."""

    callsite: CallSite
    kind: str            # "source" or "sink"
    vuln_class: str | None = None  # set for sinks: "sql-injection" / "command-injection"
    why: str | None = None         # human explanation

    @property
    def lineno(self) -> int:
        return self.callsite.lineno

    @property
    def name(self) -> str:
        return self.callsite.name


def classify_call(call: CallSite) -> Classification | None:
    """Label a single call, or return None if it's neither source nor sink."""
    sink: Sink | None = sink_for(call.name)
    if sink is not None:
        return Classification(
            callsite=call,
            kind="sink",
            vuln_class=sink.vuln_class,
            why=sink.why,
        )
    if is_source_call(call.name):
        return Classification(
            callsite=call,
            kind="source",
            why="returns untrusted, attacker-controllable input",
        )
    return None


def classify_calls(calls: list[CallSite]) -> list[Classification]:
    """Classify a list of calls, dropping the uninteresting ones."""
    out: list[Classification] = []
    for call in calls:
        c = classify_call(call)
        if c is not None:
            out.append(c)
    return out


def classify_file(path: str) -> list[Classification]:
    """Parse a file and return all source/sink classifications in it."""
    calls = find_calls(parse_file(path))
    return classify_calls(calls)
