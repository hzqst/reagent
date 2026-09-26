---
title: Installing re-agent from source
type: guide
permalink: reagent/notes/setup/installing-re-agent-from-source
tags:
- setup
- install
- uv
- tooling
---

# Installing re-agent from source

`re-agent` (package `auto-re-agent`, script entry point
`re_agent.cli.main:main` per `pyproject.toml`) is installed as a **uv tool**
with an **editable** link to the repository. Editable means source edits take
effect without reinstalling; a reinstall is only needed to refresh
dependencies or the entry point.

## Install / reinstall

```bash
uv tool install --editable /home/hztest2/reagent --force
```

- `--editable` links the working tree (no rebuild for code changes).
- `--force` reinstalls when the tool is already present.
- Default install adds **no extras**, matching the recorded receipt.

Verified from the repo root on branch `main` @ `44237bb` (2026-09-26).

## Verify the install

```bash
re-agent --version                                   # -> re-agent 0.4.0
uv tool list                                         # -> auto-re-agent v0.4.0 / - re-agent
cat ~/.local/share/uv/tools/auto-re-agent/uv-receipt.toml
```

The receipt must show the editable source path:

```toml
[tool]
requirements = [{ name = "auto-re-agent", editable = "/home/hztest2/reagent" }]
entrypoints = [
    { name = "re-agent", install-path = "/home/hztest2/.local/bin/re-agent", from = "auto-re-agent" },
]
```

Smoke-test CLI dispatch with `re-agent --help`; a freshly merged feature can be
confirmed by its subcommand, e.g. `re-agent annotate --help` lists
`--allow-prototype-changes`.

## Dev tools are NOT included by default

`ruff`, `mypy`, and `pytest` are **not on PATH** with the default install, so
the three quality gates in `AGENTS.md` cannot run as-is. Install them with:

```bash
uv tool install --editable /home/hztest2/reagent --force \
  --with pytest --with ruff --with mypy
```

This installs the packages into the tool environment (they appear in the
receipt's `requirements`), **but it does not put their binaries on PATH**:
`uv tool install` only symlinks the tool's own entrypoints (`re-agent`) into
`~/.local/bin`. Invoke the extras by full path against the tool's bin dir:

```bash
TOOLBIN=~/.local/share/uv/tools/auto-re-agent/bin
"$TOOLBIN/ruff" check src tests examples
"$TOOLBIN/mypy" src/re_agent/
"$TOOLBIN/pytest" tests/ -m "not llm and not ghidra" -x --tb=short
```

Verified 2026-09-26: `ruff 0.16.9` / `mypy 2.3.1` / `pytest 9.1.1` execute from
that bin dir; `ruff check src tests examples` -> "All checks passed!".

## Gotchas

- The repository `.venv` is an **empty shell**: `python -m pip` reports
  "No module named pip" and `re-agent` is not installed there. Do not assume it
  is the active environment.
- The real install lives at `~/.local/bin/re-agent`, backed by the uv tool
  environment at `~/.local/share/uv/tools/auto-re-agent/`.
- Adding dev extras or rebuilding `.venv` is a separate decision from a plain
  reinstall; keep the default reinstall footprint-free unless gates are needed.
- `--with <pkg>` installs `<pkg>` into the tool env but does **not** expose its
  binary on PATH; only the tool's own entrypoint is symlinked. Reach extras via
  `~/.local/share/uv/tools/auto-re-agent/bin/`.

## Re-check

- `uv tool list`
- `head -1 "$(command -v re-agent)"` -> shebang points into the uv tool's python
  (`.../uv/tools/auto-re-agent/bin/python`).
