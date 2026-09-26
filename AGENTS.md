# AGENTS.md

Guidance for AI coding agents working in this repository. The canonical
user-facing documentation is `README.md`; deeper reference material lives in
`docs/`.

## What this project is

`auto-re-agent` (import package `re_agent`, console script `re-agent`) is an
autonomous reverse-engineering agent. It drives a reverse-engineering backend
(Ghidra via `ghidra-ai-bridge`, or an `ida-pro-mcp` server) to collect evidence
about a compiled function, has LLM roles write a candidate C/C++ implementation,
and then validates that candidate through a structural verifier, configured
build/test commands, and an 11-signal parity engine.

It produces candidate code and reports. It never patches the target source tree
and never commits or pushes anything.

## Architecture

```text
CLI -> Config -> Orchestrator -> Evidence Loop -> LLM Providers
                      |              |
                      v              v
              Function Picker    RE Backend Protocol
                      |
                      v
       Candidate Overlay -> Build/Test/Differential -> Parity Gate -> Repair feedback
```

| Path | Contents |
|---|---|
| `src/re_agent/cli/` | `main.py` (argparse dispatch) plus one `cmd_*.py` per subcommand |
| `src/re_agent/config/` | Dataclass schema, YAML/env loader, `defaults.py` profile templates |
| `src/re_agent/orchestrator/` | Run drivers: `single.py` (one function), class runs, manifest runs |
| `src/re_agent/agents/` | Reverser and checker roles, the fix loop, prompt templates |
| `src/re_agent/llm/` | One module per provider plus `registry.py` (the factory) |
| `src/re_agent/backend/` | `REBackend` protocol implementations plus `registry.py` |
| `src/re_agent/verification/` | Candidate overlay, build/test execution, objective verifier |
| `src/re_agent/parity/` | Source-vs-binary parity signals and scoring |
| `src/re_agent/reports/` | Formatters, coverage, evidence export, progress tracking |
| `src/re_agent/core/` | Domain models, session/progress persistence, symbol proposals |
| `src/re_agent/utils/` | Address, process, storage, text, and template helpers |

Public entry points are re-exported from each subpackage's `__init__.py`:
`create_provider` (`llm/registry.py:15`), `create_backend`
(`backend/registry.py:9`), `load_config` (`config/`), `reverse_single`,
`run_parity`, `Session` (`core/session.py:17`).

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
```

The `ghidra-bridge` optional dependency is only needed for real backend runs
(`pip install -e "../ghidra-bridge[headless]"` when working on that path); the
test suite does not require it.

## Quality gates

CI (`.github/workflows/ci.yml`) runs three jobs. Run their local equivalents
before considering a change done:

```bash
ruff check src tests examples
mypy src/re_agent/
pytest tests/ -m "not llm and not ghidra" -x --tb=short
```

- `mypy` runs in `strict` mode (`pyproject.toml [tool.mypy]`). New public
  functions need annotations; an untyped helper will fail the gate.
- `ruff` uses line length 120 with `E, F, W, I, UP, B, SIM` selected.
- The pytest gate runs on Python 3.10-3.13 on Linux, plus Windows 3.12 and
  macOS 3.13. Avoid constructs that only work on one platform.
- A fourth CI job builds the wheel and asserts that
  `re_agent.agents/prompts/checker_system.md` is present in the installed
  package, so prompt templates must ship as package data.
- Baseline at the time of writing: `ruff` and strict `mypy` clean over 76
  source files, 334 tests passing.

## Conventions

- `from __future__ import annotations` at the top of every module.
- Dataclasses for configuration and domain models; the schema in
  `config/schema.py` is the single source of truth for user-facing config keys.
- Logging via `logging.getLogger(__name__)`. User-facing CLI failures are raised
  as `ValueError` / `RuntimeError` with actionable messages and printed by
  `cli/main.py` as `Error: ...`, exiting 1.
- Durable JSON writes go through `utils/storage` (`atomic_json` + `file_lock`);
  do not write session or progress files with a bare `open()`.
- Prompt text lives in `src/re_agent/agents/prompts/*.md` and is rendered with
  `string.Template.safe_substitute` via `utils/templates.render_template`. Edit
  the templates, not string literals in the Python code.
- Tests mirror the package layout (`tests/test_llm/`, `tests/test_backend/`, …).
  Shared fixtures are in `tests/conftest.py`; sample inputs are in
  `tests/fixtures/`.

## Extension points

- **New LLM provider**: add a module under `llm/`, register it in
  `create_provider` (`llm/registry.py:15`), and add the provider name to the
  `ValueError` message listing supported providers. Providers that shell out to
  a coding-agent CLI also belong in `_CLI_PROVIDERS` (`llm/registry.py:12`).
- **New backend**: implement the `REBackend` protocol and register it in
  `create_backend` (`backend/registry.py:9`).
- **New CLI subcommand**: add a `cmd_*.py` module and a `sub.add_parser(...)`
  entry in `cli/main.py`.
- **New parity signal**: the built-in signal set is deliberately fixed;
  configuration exposes thresholds, semantic rules, and manual overrides
  instead of per-signal toggles. Adding a signal is a behaviour change to the
  documented table in `README.md`.

## Gotchas

- **CLI providers intentionally suppress project prompt files.** When running a
  `claude-cli` / `codex` / `pi` role from a project directory, the harness would
  otherwise inject that project's `AGENTS.md` / `CLAUDE.md` into every reverser
  and checker call. This is disabled on purpose: Claude passes `claudeMdExcludes`
  including `AGENTS.md` (`llm/claude_cli.py:15`), Codex sets
  `project_doc_max_bytes=0` (`llm/codex_cli.py:145`), and Pi passes
  `--no-context-files` (`llm/pi_cli.py:98`). `runner_prompt_file` is the
  supported way to supply role context instead, and its existence is validated in
  `create_provider` rather than in the config loader so that `annotate` (which
  builds no provider) is not blocked by it.
- **`re-agent` writes artifacts into the working directory.** Running it in this
  repository produces `reports/re-agent/` and `re-agent-progress.json`. Both are
  listed in `.gitignore`; do not hand-edit them or force-add them to a commit.
- **The `llm` and `ghidra` pytest markers are declared but unused.** No test is
  marked with either; provider and backend tests mock `subprocess.run` and the
  HTTP layer instead. `-m "not llm and not ghidra"` is a no-op today — do not
  rely on it to skip anything, and do not add a marker expecting it to be wired
  up elsewhere.
- **Validation commands are trusted on the owner's say-so.** Configured
  build/test commands only count as acceptance evidence when
  `validation.trust_configured_commands: true` is set explicitly; the agent
  cannot verify from their text that they actually validate a candidate.
- **`re-agent reverse` is the full pipeline.** `plan` and `evidence` make no
  model calls, and `reverse --dry-run` shows the target plan without calling an
  LLM. Prefer these when iterating so you are not spending provider budget.

## Project knowledge base (Basic Memory)

Durable notes about this project live in `memory/` as Markdown with YAML
frontmatter (`title` / `type` / `permalink`). `.mcp.json` and
`.codex/config.toml` both declare a `basic-memory` MCP server pinned to the
`reagent` project, so every agent session reads and writes the same notes.

- Prefer `search_notes` / `read_note` over reading the whole tree. Keeping
  context small is the reason the notes exist.
- Write with `write_note` / `edit_note`, one topic per note, under
  `memory/notes/<topic>/`.
- Give every conclusion a cheap way to be re-checked: a `file:line`, a symbol
  name, or the command that produced it.
- If the MCP registration is lost (new machine, reset config), restore it with
  `basic-memory project add reagent "<repo>/memory"`.
- `memory/` is committed, and this is a published open-source repository. Do not
  record credentials, private binaries, or client-specific analysis there.

## Working agreement for agents

- Match the existing style: this is a mypy-strict, single-responsibility-module
  codebase. Prefer extending an existing module over adding a parallel one.
- Behaviour changes belong with a test in the mirrored `tests/` directory.
- Run all three gates above and report what you actually ran. If a gate cannot
  be executed in the current environment (no Ghidra, no provider credentials),
  say so explicitly rather than claiming the change is verified.
- Never edit `reports/` contents by hand, and never commit generated artifacts.
