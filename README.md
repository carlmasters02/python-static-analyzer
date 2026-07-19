# pytaint

> A taint-based static analyzer that finds **SQL injection** and **command injection** in Python source code — without running it.

[![CI](https://github.com/carlmasters02/python-static-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/carlmasters02/python-static-analyzer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/carlmasters02/python-static-analyzer/branch/main/graph/badge.svg)](https://codecov.io/gh/carlmasters02/python-static-analyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`pytaint` parses Python files into an AST, identifies untrusted *sources*
and dangerous *sinks*, and uses simple taint tracking to flag data that
flows from a source to a sink without sanitization. It reports the file,
line, and *why* each finding is exploitable. Built incrementally as a
learning project — every module is heavily commented and each core security
concept is explained inline.

## Demo

```console
$ pytaint samples/
samples/vuln_command_injection.py:15 [command-injection]
    untrusted data (variable 'host') reaches os.system() — os.system() passes its string argument to the system shell
samples/vuln_sql_injection.py:12 [sql-injection]
    untrusted data (variable 'username') reaches cursor.execute() — a DB cursor .execute() runs its string as SQL
...
4 finding(s) across 2 file(s) scanned
```

## Install

Requires Python 3.9+. No dependencies beyond the standard library.

### Option A — with Python (pip)

```bash
git clone https://github.com/carlmasters02/python-static-analyzer.git
cd python-static-analyzer
pip install .            # installs the `pytaint` command
pytaint samples/
```

> Tip: use `pip install -e ".[dev]"` for an *editable* install with the test
> tools — code changes take effect immediately and `pytest` is ready to run.

### Option B — with Docker (no Python required)

```bash
git clone https://github.com/carlmasters02/python-static-analyzer.git
cd python-static-analyzer
docker build -t pytaint .
docker run --rm -v "$PWD/samples":/scan pytaint /scan
```

## Usage

```
pytaint PATH [--format {text,json}] [--no-taint-params] [--no-color] [--version]

  PATH               file or directory to scan (recursive)
  --format           output format: text (default) or json
  --no-taint-params  don't treat function parameters as tainted
                     (higher precision, lower recall)
  --no-color         disable ANSI colors in text output
  --version          show version and exit
```

Exit code is `0` when clean, `1` when findings exist (handy for CI), `2` on
a bad path. You can also run it as a module: `python -m pytaint samples/`.

## How it works — the four concepts

**AST (Abstract Syntax Tree).** Source-as-text is hard to reason about
(`grep` can't tell code from a comment). Python's built-in `ast` module
parses text into a *tree* mirroring the code's structure, so
`os.system(user_input)` becomes a `Call` node we can inspect precisely. See
[src/pytaint/parser.py](src/pytaint/parser.py).

**Sources and sinks.** A **source** is where untrusted data enters —
`input()`, `request.args`, `sys.argv`, and (by assumption) function
parameters. A **sink** is a dangerous operation — `os.system()` /
`subprocess.*(shell=True)` (→ command injection) and `cursor.execute()`
(→ SQL injection). The knowledge base lives in
[src/pytaint/signatures.py](src/pytaint/signatures.py).

**Taint analysis.** We mark data from a source as "tainted" and follow it
through assignments and string operations (`+`, f-strings, `.format()`,
`%`). If tainted data reaches a sink and wasn't cleaned by a sanitizer
(`shlex.quote`, `int(...)`, or SQL parameterization), we report it. This is
what makes the tool *precise* rather than flagging every `os.system` call.
See [src/pytaint/taint.py](src/pytaint/taint.py).

**Precision & recall.** *Precision* = of what we flagged, how much was real?
*Recall* = of the real bugs, how many did we catch? They trade off; F1
balances them. Measured against a labeled benchmark below.

```
 source file ──ast.parse──► AST ──find sources & sinks──► taint engine
   (introduce → propagate → check sinks w/ sanitizers, shell=, SQL params)
   ──► findings ──► text / JSON report
```

## Benchmark results (precision / recall)

Scored against [benchmark/cases/](benchmark/cases/) — 22 labeled cases
covering true vulnerabilities, safe "lookalikes" (parameterized SQL,
`shell=False`, sanitized input), and cases that deliberately exercise the
engine's known blind spots. Reproduce with `python -m benchmark.score`.

| Mode | TP | FP | FN | TN | Precision | Recall | F1 |
|------|---:|---:|---:|---:|----------:|-------:|---:|
| default (params tainted) | 9 | 1 | 3 | 9 | 90% | 75% | 82% |
| `--no-taint-params` | 4 | 1 | 8 | 9 | 80% | 33% | 47% |

Read honestly: the **1 false positive** is a variable reassigned to a
constant before the sink (we're flow-insensitive within a scope). The **3
false negatives** are real bugs we miss — an unmodeled source (`os.getenv`),
taint through a return value (no interprocedural analysis), and taint through
a list element. The second row shows the precision/recall tradeoff in
numbers.

> The real [OWASP Benchmark](https://owasp.org/www-project-benchmark/)
> targets Java, so it can't score a Python tool directly — we reuse its
> *methodology* (labeled vulnerable/safe cases with safe lookalikes) instead.

## Real-world scan

Run against five real GitHub repositories (275 `.py` files); full triage in
[REAL_WORLD_SCAN.md](REAL_WORLD_SCAN.md). Highlights: **zero false
positives** across 253 files of mature library code (flask / requests /
httpie); **one correct true positive** in the intentionally-vulnerable
`dvpwa`; and a whole app's worth of **missed bugs** in `DSVW` because its
input source (`self.path`) isn't in our signature list — the clearest
demonstration that *a taint tool is only as good as its source/sink lists*.

## Development

```bash
pip install -e ".[dev]"   # install with test tools (pytest, coverage)
pytest                    # run the suite + coverage report
python -m benchmark.score # run the precision/recall benchmark
python explore_ast.py --scan samples/vuln_sql_injection.py   # teaching tool
```

Every push to `main` runs the suite on GitHub Actions across Python 3.9,
3.11, and 3.13. Coverage is reported to Codecov.

## Known limitations (by design — this is a teaching tool)

- **Signature-bound:** only catches sources/sinks in
  [signatures.py](src/pytaint/signatures.py); a missing source → silent
  false negatives.
- **Intraprocedural only:** taint into a helper function and out to a sink
  there is not tracked across the call boundary.
- **Flow-insensitive within a scope:** statement order is ignored.
- **No container/attribute tracking:** taint through list/dict elements or
  object attributes is not followed.

## Project structure

```
python-static-analyzer/
├── src/pytaint/            # the package
│   ├── __init__.py         # version
│   ├── parser.py           # AST parsing + call discovery
│   ├── signatures.py       # source/sink knowledge base
│   ├── detector.py         # classify calls as source/sink
│   ├── taint.py            # the taint engine
│   ├── scanner.py          # directory walk + robustness
│   ├── reporting.py        # text / JSON output
│   ├── cli.py              # the `pytaint` command
│   └── __main__.py         # enables `python -m pytaint`
├── tests/                  # pytest / unittest suite
├── samples/                # labeled vulnerable/safe demo files
├── benchmark/              # labeled cases + precision/recall scorer
├── explore_ast.py          # teaching CLI (AST dump / classify / scan)
├── REAL_WORLD_SCAN.md      # results on real repos
├── .github/workflows/ci.yml
├── Dockerfile
├── pyproject.toml
├── LICENSE                 # MIT
└── README.md
```

## License

Released under the [MIT License](LICENSE) — free to use, modify, and
distribute; just keep the copyright notice.
