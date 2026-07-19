"""Milestone 3: the taint engine — the heart of the analyzer.

Given a parsed file, we:
  1. Break it into *scopes* (each function/method, plus module top-level).
  2. In each scope, build the set of *tainted* variables:
       - a variable becomes tainted when a source flows into it
       - function parameters are optionally seeded as tainted
       - taint propagates through assignments to a fixpoint
  3. For each sink call in the scope, ask whether tainted data reaches
     the specific argument that matters (respecting sanitizers, shell=,
     and SQL parameterization).
  4. Emit a Finding for each tainted-data-reaches-sink case.

This is deliberately *flow-insensitive within a scope*: we don't model
statement order, we just ask "is this variable ever tainted in this
function?" That's simpler and slightly over-approximates (it can flag a
case where a variable is reassigned to something clean before the sink).
Real tools use flow-sensitive analysis; we note the tradeoff and move on.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from .parser import dotted_name
from .signatures import Sink, is_source_call, is_source_name, sink_for


# Calls that *clean* their argument, removing taint.
SANITIZERS: frozenset[str] = frozenset(
    {
        "shlex.quote",    # shell-escapes a string
        "pipes.quote",    # older alias of shlex.quote
        "shlex.split",    # returns a list of args, not a shell string
        "int",            # forces a number — no shell/SQL metacharacters survive
        "float",
    }
)


@dataclass
class Finding:
    """One reported vulnerability."""

    filename: str
    lineno: int
    col: int
    vuln_class: str      # "sql-injection" or "command-injection"
    sink_name: str       # e.g. "os.system"
    message: str         # human explanation of the flow

    def __str__(self) -> str:
        return (
            f"{self.filename}:{self.lineno}: [{self.vuln_class}] "
            f"{self.message}"
        )


# ---------------------------------------------------------------------------
# Taint checking on a single expression.
# ---------------------------------------------------------------------------

def is_tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    """Does this expression carry taint, given the set of tainted variables?

    Recursive over the expression's structure. We stop at sanitizer calls —
    their result is considered clean no matter what went in.
    """
    if node is None:
        return False

    if isinstance(node, ast.Name):
        return node.id in tainted

    if isinstance(node, ast.Constant):
        return False

    if isinstance(node, ast.Call):
        fname = dotted_name(node.func)
        if is_source_call(fname):
            return True            # e.g. input()
        if fname in SANITIZERS:
            return False           # sanitized -> clean, stop here
        # An unknown call is tainted if any argument (or its receiver, for
        # method calls like tainted.format(...)) is tainted.
        if any(is_tainted(a, tainted) for a in node.args):
            return True
        if any(is_tainted(kw.value, tainted) for kw in node.keywords):
            return True
        return is_tainted(node.func, tainted)

    if isinstance(node, ast.Attribute):
        if is_source_name(dotted_name(node)):
            return True            # e.g. request.args
        return is_tainted(node.value, tainted)

    if isinstance(node, ast.Subscript):
        base = dotted_name(node.value)
        if is_source_name(base) or is_source_name(base + "[]"):
            return True            # e.g. request.args['id'], sys.argv[1]
        return is_tainted(node.value, tainted) or is_tainted(node.slice, tainted)

    if isinstance(node, ast.BinOp):
        # covers "a" + host  and  "fmt %s" % host
        return is_tainted(node.left, tainted) or is_tainted(node.right, tainted)

    if isinstance(node, ast.BoolOp):
        return any(is_tainted(v, tainted) for v in node.values)

    if isinstance(node, ast.JoinedStr):        # f-string
        return any(is_tainted(v, tainted) for v in node.values)

    if isinstance(node, ast.FormattedValue):   # the {expr} inside an f-string
        return is_tainted(node.value, tainted)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(is_tainted(e, tainted) for e in node.elts)

    # Fallback: taint if any child expression is tainted.
    return any(is_tainted(c, tainted) for c in ast.iter_child_nodes(node))


def describe_taint(node: ast.AST, tainted: set[str]) -> str:
    """Best-effort human description of where the taint comes from."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return f"variable '{sub.id}'"
        if isinstance(sub, ast.Call) and is_source_call(dotted_name(sub.func)):
            return f"{dotted_name(sub.func)}()"
        if isinstance(sub, ast.Attribute) and is_source_name(dotted_name(sub)):
            return dotted_name(sub)
    return "user-controlled input"


# ---------------------------------------------------------------------------
# Deciding whether a specific sink *instance* is actually dangerous.
# ---------------------------------------------------------------------------

def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def dangerous_sink_arg(
    call: ast.Call, sink: Sink, tainted: set[str]
) -> ast.AST | None:
    """Return the tainted argument that makes this call dangerous, else None.

    This is where precision lives: we don't just say "it's a sink" — we
    check the *right* argument and respect shell=/parameterization.
    """
    name = dotted_name(call.func)
    args = call.args

    if sink.vuln_class == "sql-injection":
        # Only the query string (first positional arg) is the sink. Data in
        # the parameters tuple (2nd arg) is safe — that's the whole point of
        # parameterized queries.
        if args and is_tainted(args[0], tainted):
            return args[0]
        return None

    # command-injection
    if name.startswith("subprocess."):
        # Only dangerous when a shell interprets the string: shell=True.
        shell_true = any(
            kw.arg == "shell" and _is_true(kw.value) for kw in call.keywords
        )
        if not shell_true:
            return None
        if args and is_tainted(args[0], tainted):
            return args[0]
        return None

    # os.system / os.popen / commands.getoutput / os.exec* — always a shell/exec.
    if args and is_tainted(args[0], tainted):
        return args[0]
    return None


# ---------------------------------------------------------------------------
# Scope handling.
# ---------------------------------------------------------------------------

def _iter_scope(stmts: list[ast.stmt]):
    """Yield every node inside these statements, WITHOUT descending into
    nested function/class/lambda scopes (those are analyzed separately)."""
    for n in stmts:
        yield n
        if isinstance(
            n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        for child in ast.iter_child_nodes(n):
            yield from _iter_scope([child])


def _target_names(assign: ast.stmt) -> list[str]:
    """Names being assigned to (handles tuple unpacking, best-effort)."""
    names: list[str] = []
    targets: list[ast.AST] = []
    if isinstance(assign, ast.Assign):
        targets = list(assign.targets)
    elif isinstance(assign, (ast.AugAssign, ast.AnnAssign)):
        targets = [assign.target]
    for t in targets:
        for sub in ast.walk(t):
            if isinstance(sub, ast.Name):
                names.append(sub.id)
    return names


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = func.args
    names = [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    # 'self' / 'cls' are not attacker data.
    return [n for n in names if n not in ("self", "cls")]


def _build_taint_set(
    body: list[ast.stmt], seed: set[str]
) -> set[str]:
    """Fixpoint: keep adding tainted variables until nothing changes."""
    tainted = set(seed)
    assigns = [
        n
        for n in _iter_scope(body)
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign))
    ]
    changed = True
    while changed:
        changed = False
        for assign in assigns:
            value = assign.value  # AnnAssign.value can be None
            if value is None:
                continue
            if is_tainted(value, tainted):
                for name in _target_names(assign):
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
    return tainted


def _analyze_scope(
    body: list[ast.stmt], seed: set[str], filename: str
) -> list[Finding]:
    tainted = _build_taint_set(body, seed)
    findings: list[Finding] = []
    for node in _iter_scope(body):
        if not isinstance(node, ast.Call):
            continue
        sink = sink_for(dotted_name(node.func))
        if sink is None:
            continue
        bad_arg = dangerous_sink_arg(node, sink, tainted)
        if bad_arg is None:
            continue
        origin = describe_taint(bad_arg, tainted)
        message = (
            f"untrusted data ({origin}) reaches {dotted_name(node.func)}() — "
            f"{sink.why}"
        )
        findings.append(
            Finding(
                filename=filename,
                lineno=node.lineno,
                col=node.col_offset,
                vuln_class=sink.vuln_class,
                sink_name=dotted_name(node.func),
                message=message,
            )
        )
    return findings


def analyze_tree(
    tree: ast.Module,
    filename: str = "<unknown>",
    assume_tainted_params: bool = True,
) -> list[Finding]:
    """Run taint analysis over a whole module and return all findings."""
    findings: list[Finding] = []

    # Module top-level scope (params: none).
    findings += _analyze_scope(tree.body, seed=set(), filename=filename)

    # Every function/method is its own scope.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            seed = set(_param_names(node)) if assume_tainted_params else set()
            findings += _analyze_scope(node.body, seed=seed, filename=filename)

    # Stable order: by line number.
    findings.sort(key=lambda f: f.lineno)
    return findings


def analyze_file(
    path: str, assume_tainted_params: bool = True
) -> list[Finding]:
    """Parse a file from disk and analyze it."""
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source, filename=path)
    return analyze_tree(tree, filename=path, assume_tainted_params=assume_tainted_params)
