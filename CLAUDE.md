# CLAUDE.md — project conventions for this repo

This repo started life as a **reusable template** for professional Python
command-line tools. When you (Claude) work here, follow the conventions
below so every project built from this template keeps the same hygiene.

If the user says something like *"use this repo as a template and build me
X,"* treat that as: keep the structure and habits described here, swap the
example `hello` tool for their real app, and update names/docs/tests to match.

## What this template already provides

- **`src/` layout** — the package lives under `src/<package_name>/`, so
  tests run against the *installed* package, not loose files.
- **pytest + coverage** — real tests under `tests/`, coverage reported in
  the terminal and as `coverage.xml`.
- **GitHub Actions CI** (`.github/workflows/ci.yml`) — runs the test suite
  on every push/PR across multiple Python versions.
- **Status badges** in the README — build, coverage (Codecov), license.
- **Dockerfile** — slim base image, installs the package, runs as a
  **non-root** user.
- **MIT LICENSE** and a **structured README** (description → demo → install
  → usage → how it works → development → structure → license).
- **Semantic-versioned releases** — git tags like `v1.0.0`.

## When reusing this template for a new app

1. **Rename** the package folder under `src/` and the console command name
   in `pyproject.toml` (`[project.scripts]`) to fit the new tool.
2. **Replace the logic**: the example `greet()` in `cli.py` is the only
   placeholder — swap it for the real feature. Keep the pattern of a small,
   testable pure function separated from the CLI plumbing.
3. **Write tests as you go**, in `tests/`, for the new logic and CLI.
4. **Update the README** to describe the new tool (all sections).
5. **Update badge URLs** in the README to the new `owner/repo`.
6. **Reset the version** to `0.1.0` in both `pyproject.toml` and
   `src/<package>/__init__.py` (a brand-new, still-experimental tool).
7. Keep the CI, Dockerfile, `.gitignore`, and `.dockerignore` — they work
   as-is for any Python CLI.

## Working style

- **Smallest working slice first**: get input → logic → visible output
  working end-to-end before adding features.
- **Build incrementally and verify by running the tool**, not just by
  reading code. Prefer to pause and let the user test meaningful slices.
- Prefer the **standard library** over new dependencies unless there's a
  real need — fewer dependencies, less to break.
- After changing code, **run the tests** (`pytest`) and, when relevant,
  build/run the tool or the Docker image to confirm it actually works.
- Keep the version number in `pyproject.toml` and `__init__.py` in sync,
  and tag releases with semantic versioning (MAJOR.MINOR.PATCH).

## Security habits (keep these in every project)

- **Secrets never go in git.** Keep keys/passwords in a `.env` file that is
  listed in `.gitignore`. Never hardcode them in source.
- **Store CI secrets in GitHub Secrets** (e.g. `CODECOV_TOKEN`), referenced
  as `${{ secrets.NAME }}` — never pasted into the workflow file.
- **Pin third-party GitHub Actions** to a version (e.g. `@v5`) so a
  compromised upstream update can't silently run in your pipeline.
- **Least privilege in Docker**: use a slim base image and run as a
  non-root user, so a break-in inherits as little power as possible.
- **No silent failures**: surface errors clearly rather than swallowing
  them; a bad input should fail loudly with a non-zero exit code.
