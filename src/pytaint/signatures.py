"""Milestone 2: the knowledge base of sources and sinks.

A real analyzer's "intelligence" is mostly a big, carefully curated list
of which functions are dangerous and which functions return untrusted
data. That list lives here so it's easy to read and extend.

Two vulnerability classes for now:
    - "command-injection": attacker data reaching a shell/exec call
    - "sql-injection":     attacker data reaching a database query call

Matching functions come in two flavors:
    - Exact dotted name:   "os.system"        matches os.system(...)
    - Method suffix (".X"): ".execute"         matches ANY receiver, e.g.
                            cursor.execute(...), db.execute(...), conn.execute(...)

We need the suffix form because in real code the database cursor could be
named anything (cursor, cur, db, c, self.conn ...). We usually can't know
its type from syntax alone, so we match on the method name and accept that
this trades some precision for recall. (More on that trade-off in the README.)
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# SINKS: dangerous operations, keyed by the name we match against.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Sink:
    vuln_class: str  # "command-injection" or "sql-injection"
    why: str         # human explanation of why this call is dangerous


# Exact dotted-name sinks.
_EXACT_SINKS: dict[str, Sink] = {
    # --- Command injection: these run strings through a shell / OS exec ---
    "os.system": Sink(
        "command-injection",
        "os.system() passes its string argument to the system shell",
    ),
    "os.popen": Sink(
        "command-injection",
        "os.popen() runs its string argument through the shell",
    ),
    "subprocess.call": Sink(
        "command-injection",
        "subprocess.call() runs a command; dangerous with a string + shell=True",
    ),
    "subprocess.run": Sink(
        "command-injection",
        "subprocess.run() runs a command; dangerous with a string + shell=True",
    ),
    "subprocess.Popen": Sink(
        "command-injection",
        "subprocess.Popen() runs a command; dangerous with a string + shell=True",
    ),
    "subprocess.check_call": Sink(
        "command-injection",
        "subprocess.check_call() runs a command; dangerous with a string + shell=True",
    ),
    "subprocess.check_output": Sink(
        "command-injection",
        "subprocess.check_output() runs a command; dangerous with a string + shell=True",
    ),
    "os.execl": Sink("command-injection", "os.execl() executes a program"),
    "os.execv": Sink("command-injection", "os.execv() executes a program"),
    "commands.getoutput": Sink(
        "command-injection", "commands.getoutput() runs a shell command"
    ),
}

# Method-suffix sinks: match the final attribute regardless of receiver.
# Stored WITHOUT the leading dot; we compare against the last name segment.
_SUFFIX_SINKS: dict[str, Sink] = {
    # --- SQL injection: DB-API cursor/connection query methods ---
    "execute": Sink(
        "sql-injection",
        "a DB cursor .execute() runs its string as SQL",
    ),
    "executemany": Sink(
        "sql-injection",
        "a DB cursor .executemany() runs its string as SQL",
    ),
    "executescript": Sink(
        "sql-injection",
        "a DB cursor .executescript() runs its string as SQL",
    ),
}


# ---------------------------------------------------------------------------
# SOURCES: places untrusted data enters the program.
#
# Sources aren't only calls — request.args is an attribute, sys.argv is a
# subscript. So we describe sources as name *prefixes/exacts* and let the
# taint stage (Milestone 3) decide how they're used. For now we expose the
# raw data so both the classifier and the taint engine can share it.
# ---------------------------------------------------------------------------

# Calls that RETURN untrusted data.
_SOURCE_CALLS: set[str] = {
    "input",                 # input(...) -> whatever the user typed
    "request.get_json",      # Flask
    "request.args.get",      # Flask
    "request.form.get",      # Flask
    "request.values.get",    # Flask
    "request.cookies.get",   # Flask
    "request.headers.get",   # Flask
}

# Names/attributes that ARE untrusted data (not necessarily called).
# Matched as "starts with this dotted prefix".
_SOURCE_PREFIXES: tuple[str, ...] = (
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.data",
    "request.cookies",
    "request.headers",
    "request.files",
    "sys.argv",
    "os.environ",
    "flask.request",
)


# ---------------------------------------------------------------------------
# Lookup helpers — the public API of this module.
# ---------------------------------------------------------------------------

def sink_for(name: str) -> Sink | None:
    """Return the Sink metadata for a call name, or None if it isn't a sink.

    Tries an exact dotted-name match first, then falls back to matching the
    final ``.method`` segment against the suffix table.
    """
    if name in _EXACT_SINKS:
        return _EXACT_SINKS[name]
    last_segment = name.rsplit(".", 1)[-1]
    return _SUFFIX_SINKS.get(last_segment)


def is_source_call(name: str) -> bool:
    """True if calling this name returns untrusted data (e.g. ``input``)."""
    return name in _SOURCE_CALLS


def is_source_name(name: str) -> bool:
    """True if this name/attribute *is* untrusted data (e.g. ``request.args``)."""
    return any(
        name == p or name.startswith(p + ".") or name.startswith(p + "[")
        for p in _SOURCE_PREFIXES
    )
