# hello-cli

> A tiny "hello world" command-line tool, built as a reusable template for professional Python repo hygiene.

[![CI](https://github.com/carlmasters02/python-cli-template/actions/workflows/ci.yml/badge.svg)](https://github.com/carlmasters02/python-cli-template/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/carlmasters02/python-cli-template/branch/main/graph/badge.svg)](https://codecov.io/gh/carlmasters02/python-cli-template)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`hello-cli` greets you from the command line. It does almost nothing on
purpose — the point is everything *around* the code: a clean layout, a real
test suite, continuous integration, a Docker image, and tagged releases.
Clone it as a starting point for well-structured, tested, ship-ready tools.

## Demo

```console
$ hello
Hello, World!

$ hello --name Ada
Hello, Ada!

$ hello --version
hello 1.0.0
```

## Install

Pick whichever fits — no need for both.

### Option A — with Python (pip)

Requires Python 3.9+.

```bash
git clone https://github.com/carlmasters02/python-cli-template.git
cd repo-template
pip install .          # installs the `hello` command
hello --name Carl
```

> Tip: use `pip install -e .` for an *editable* install — your code changes
> take effect immediately, no reinstall needed. Great while developing.

### Option B — with Docker (no Python required)

Runs anywhere Docker (or Podman) is installed, with zero local Python setup.

```bash
git clone https://github.com/carlmasters02/python-cli-template.git
cd repo-template
docker build -t hello-cli .
docker run --rm hello-cli --name Carl
```

## Usage

```
hello [-n NAME] [--version] [-h]

  -n, --name NAME   Name to greet (default: World)
  --version         Show the version and exit
  -h, --help        Show this help message and exit
```

## How it works

The whole tool is one small package under `src/hello_cli/`, split so the
logic is trivial to test:

- **`greet(name)`** — a *pure* function that just returns the greeting
  string. No printing, no side effects, so it's dead simple to unit-test.
- **`build_parser()` / `main()`** — the command-line plumbing (argument
  parsing and output) wrapped around `greet`.
- **The `hello` command** — defined in `pyproject.toml` under
  `[project.scripts]`, which maps the name `hello` to `main()` at install
  time. That's what turns a Python function into a real terminal command.

When you run `hello --name Ada`, the flow is:

```
hello --name Ada
   -> main() parses the arguments
   -> greet("Ada") returns "Hello, Ada!"
   -> the string is printed to your terminal
```

## Development

```bash
pip install -e ".[dev]"   # install with test tools (pytest, coverage)
pytest                    # run the suite + coverage report
```

Every push to `main` runs the same tests automatically on GitHub Actions
across Python 3.9, 3.11, and 3.13. Coverage is reported to Codecov.

## Project structure

```
python-cli-template/
├── src/hello_cli/          # the package
│   ├── __init__.py         # version number
│   └── cli.py              # greet() + CLI plumbing
├── tests/                  # pytest suite
│   ├── test_greet.py
│   └── test_cli.py
├── .github/workflows/ci.yml  # runs tests on every push
├── Dockerfile              # build/run without installing Python
├── .dockerignore
├── .gitignore
├── pyproject.toml          # packaging + tool config
├── LICENSE                 # MIT
└── README.md
```

## License

Released under the [MIT License](LICENSE) — free to use, modify, and
distribute; just keep the copyright notice.
