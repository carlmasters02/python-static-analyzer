# Milestone 5 — Scanning Real Open-Source Repositories

We pointed the analyzer (default settings, i.e. function parameters treated
as tainted) at five real GitHub repos: three mature libraries and two
deliberately-vulnerable training apps. Every finding below was manually
triaged against the actual source code.

## Results

| Repo | Kind | .py files | Findings | True + | False + | Known missed (FN) |
|------|------|----------:|---------:|-------:|--------:|------------------:|
| [pallets/flask](https://github.com/pallets/flask) | mature web framework | 83 | 0 | 0 | 0 | 0 |
| [psf/requests](https://github.com/psf/requests) | mature HTTP client | 37 | 0 | 0 | 0 | 0 |
| [httpie/cli](https://github.com/httpie/cli) | mature CLI tool | 133 | 0 | 0 | 0 | 0 |
| [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) | intentionally vulnerable | 21 | **1** | **1** | 0 | 0 |
| [stamparm/DSVW](https://github.com/stamparm/DSVW) | intentionally vulnerable | 1 | 0 | 0 | 0 | **~5** |

## What went right

**No false positives on 253 files of mature library code.** The tool did
*not* cry wolf. Notably, flask contains 8 `.execute(...)` call sites and our
"parameters are tainted" assumption was active, yet nothing was flagged —
because those libraries parameterize their SQL and pass subprocess arguments
as lists (`shell=False`). Tainted data never reaches a *dangerous* argument,
so our sink-argument precision (only the SQL query string; only `shell=True`)
correctly stayed quiet. httpie has 21 subprocess call sites and zero use
`shell=True`, so zero findings is the *correct* answer, not a miss.

**One clean true positive in dvpwa.** We flagged `Student.create()` in
`sqli/dao/student.py:45`:

```python
q = ("INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name})
await cur.execute(q)          # <-- 'name' is baked into the query string
```

This is a genuine SQL injection. Just as importantly, the *other* 11
`.execute()` sites in dvpwa use real parameterization —
`execute('... WHERE id = %s', (id_,))` — and we correctly left every one of
them alone. So on dvpwa: precision 100%, recall 100% for our two vuln classes.

## What went wrong — the DSVW false negatives (the real lesson)

DSVW is riddled with injection bugs, e.g.:

```python
# dsvw.py:30  — SQL injection
cursor.execute("SELECT id, username, name, surname FROM users WHERE id=" + params["id"])
# dsvw.py:39  — command injection
subprocess.run("nslookup " + params["domain"], shell=True, ...)
```

We caught **none** of them. Why? Follow the data backwards:

```python
path, query = self.path.split('?', 1) ...      # self.path = the HTTP request
params = dict(... regex over query ...)          # params derived from it
... params["id"] ...                             # reaches the sink
```

The untrusted data originates from **`self.path`** (the request path on a
`BaseHTTPRequestHandler`). That is not in our list of sources. Our taint
engine only marks data dirty if it comes from a *known* source — `input()`,
`request.args`, function parameters, etc. Because `self.path` isn't
recognized, `query` is never tainted, so `params` is never tainted, so the
sinks look like they receive clean constant-ish data. **Zero taint in →
zero findings out.**

### The takeaway

This is the single most important limitation of signature-based taint
analysis, and DSVW demonstrates it perfectly:

> **The tool is only as good as its list of sources and sinks.** A missing
> source produces silent false negatives — arguably the most dangerous kind
> of error in a security tool, because "0 findings" *looks* like "you're safe."

We could "fix" DSVW by adding `self.path` / `self.headers` as sources, but
deliberately did **not** — hand-tuning signatures to pass one specific repo
is exactly the kind of overfitting that makes benchmark numbers dishonest.
The honest engineering answer is: expand the source/sink lists deliberately
and broadly, then *re-measure* on a held-out benchmark (Milestone 6).

Other known blind spots this scan reminded us of:
- **No interprocedural tracking** — taint that flows into a helper function
  and hits a sink *there* is missed.
- **Flow-insensitive within a scope** — we don't model statement order.

## Reproduce

```bash
git clone --depth 1 https://github.com/anxolerd/dvpwa
python analyze.py dvpwa/            # -> 1 finding (student.py:45)

git clone --depth 1 https://github.com/stamparm/DSVW
python analyze.py DSVW/             # -> 0 findings (all missed; see above)
```
