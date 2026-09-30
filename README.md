# ReAgent

[![PyPI](https://img.shields.io/pypi/v/auto-re-agent)](https://pypi.org/project/auto-re-agent/)
[![Python](https://img.shields.io/pypi/pyversions/auto-re-agent)](https://pypi.org/project/auto-re-agent/)
[![CI](https://github.com/Dryxio/reagent/actions/workflows/ci.yml/badge.svg)](https://github.com/Dryxio/reagent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ReAgent is an open-source AI reverse-engineering agent that uses Ghidra
and LLMs—including Claude, Codex, Pi, and OpenAI-compatible models—to reconstruct
and validate C/C++ functions from compiled binaries. It combines independent
reverser/checker models, agentic evidence gathering, candidate build and test
gates, structural verification, and parity analysis in one autonomous workflow.

Original pre-0.2 demo: [YouTube](https://youtu.be/zBQJYMKmwAs?si=emi1kDsJ81-2-tc3)

## Get started with your AI

**Give your AI this repo and tell it what you want to do.** It can check your setup, install the tools it needs, and walk you through anything that needs your help. Use an AI coding agent that can access files and run commands on your computer.

Copy this into your agent:

> Help me set up https://github.com/Dryxio/reagent. Read the README, check my installed tools and AI provider setup, and help me install and configure what's missing. Ask which program or project to work on. Start with one small function. Run the setup check (re-agent doctor), explain which AI provider will be used and any API costs, and set a small model-call limit. Then try to recreate that function in C/C++ and show me the result, what passed validation, and what still needs checking.

You'll need a program to analyze and a supported AI provider. Your agent can help connect Ghidra and use an existing authenticated Claude, Codex, or Pi CLI, or an API setup.

**Setup agents:** follow the [setup workflow](docs/agent-setup.md). Detect the host OS and installed toolchain, generate portable validation commands, and migrate incompatible existing commands before starting reversal. The user should not need an OS-specific prompt or edit command syntax manually.

## What it does

```text
re-agent reverse --class CTrain
    │
    ├── Configuration (YAML + supported environment overrides + CLI flags)
    ├── Function selection (dependency-order | easiest-first | high-impact)
    ├── Source and binary context
    │   ├── decompile, xrefs, structs, enums, vtables, globals, and strings
    │   └── normalized high P-code, CFG, assembly, and nearby project source
    ├── Reverser → checker → fix loop (bounded rounds and investigations)
    ├── Conservative structural verifier
    ├── Candidate overlay
    │   └── configured build, test, and runtime gates
    ├── Candidate parity gate (GREEN | YELLOW | RED)
    └── Reports, per-call logs, round checkpoints, session history, and knowledge graph
```

The tool generates candidate C/C++ implementations; it does not patch the
original source tree automatically. A successful reversal can require four
independent conditions:

1. the LLM checker returns `PASS`;
2. the objective verifier finds no strong structural mismatch;
3. candidate validation satisfies the configured acceptance policy;
4. parity is not blocked by the configured RED/YELLOW policy.

This is conservative verification, not a proof of semantic equivalence.

Checker replies should use `PASS` or `FAIL`. For JSON and legacy `VERDICT:` text
replies, parsing ignores case and surrounding whitespace and also accepts
`correct`, `ok`, `good`, and `verified` as `PASS`, or `incorrect` and `wrong` as
`FAIL`. Missing, non-string, or unrecognized verdicts are protocol errors:
`Checker protocol error: expected PASS/FAIL, got 'maybe'`. These errors stop the
current fix loop and appear in the reversal result's `error` field, rather than
triggering further code repair rounds. Objective verification, build/test
validation, and parity gates still apply to normalized `PASS` verdicts.

## New in 0.4.0

Build, test, and runtime validation now support argument arrays that execute
directly on Windows and POSIX. On native Windows, convert shell strings to arrays;
legacy strings still require `/bin/sh`. `re-agent doctor` reports a missing shell.

- `re-agent plan` builds bounded function manifests without model calls.
- `re-agent reverse --manifest` reconstructs selected functions across classes,
  with dependency ordering and cumulative validation in an isolated project copy.
- `re-agent evidence --manifest` exports stored evidence into linked JSON packets and TSV indexes.
- `re-agent status --manifest` reports coverage, stale results, and individual validation checks.
- Evidence gaps remain explicit, and manifests stay readable after backend errors with empty messages.
- Clang indexing handles CRLF offsets; Codex CLI requests use UTF-8 stdin for large prompts.

See [migration and configuration](docs/configuration.md#portable-validation-commands)
and [the changelog](CHANGELOG.md).

## Manual setup

Prefer to install it yourself? Expand the instructions below.

<details>
<summary>Manual installation, configuration and examples</summary>

## Requirements

- Python 3.10+
- Git, for the current source installation
- Ghidra plus a configured
  [Ghidra Bridge](https://github.com/Dryxio/ghidra-bridge)
- At least one LLM setup:
  - Claude API: `ANTHROPIC_API_KEY`
  - OpenAI-compatible API: `OPENAI_API_KEY`
  - Claude CLI: an authenticated local `claude` command
  - Codex CLI: an authenticated local `codex` command
  - Pi CLI: an authenticated local `pi` command ([pi.dev](https://pi.dev))

## Installation

Install the agent and its Ghidra query bridge from PyPI:

```bash
python3 -m pip install --upgrade "auto-re-agent[ghidra-bridge]>=0.4.0"
```

For headless Ghidra exports, install the bridge with its PyGhidra extra:

```bash
python3 -m pip install --upgrade "auto-re-agent[headless]>=0.4.0"
```

To install the latest development versions directly from GitHub instead:

```bash
python3 -m pip install --upgrade \
  "ghidra-ai-bridge @ git+https://github.com/Dryxio/ghidra-bridge.git@main" \
  "auto-re-agent @ git+https://github.com/Dryxio/reagent.git@main"
```

## Set up Ghidra evidence

Run these commands from the project you want to reverse:

```bash
# Create ghidra-bridge.yaml, then edit its Ghidra project/program paths
ghidra-bridge init

# Requires the bridge headless extra and a local Ghidra installation
ghidra-bridge export all

# Optional but recommended when reversed source/hook patterns are available
ghidra-bridge build-map

# Confirm that exports and configuration are visible
ghidra-bridge info
```

See the [bridge documentation](https://github.com/Dryxio/ghidra-bridge)
for its Ghidra, export, and source-map configuration.

## Quick start

Create a configuration in the target project:

```bash
# Recommended portable default
re-agent init --profile generic-cpp

# Other available profiles
# re-agent init --profile windows-x64
# re-agent init --profile gta-reversed
# re-agent init --profile openrct2
```

Running `re-agent init` without `--profile` preserves the original
GTA-reversed defaults. Prefer an explicit profile for new projects.

Then edit `re-agent.yaml`. At minimum, select an LLM, configure a backend,
set the source paths, and configure validation.

For IDA without a GUI, use `backend.type: idalib-mcp` with an existing
`database_path` (`.i64` or `.idb`). Re-agent starts and closes its own headless
IDA worker for each reverse/fix, checker, and recovery stage, with fresh
evidence caches and keepalive during model calls. See
[managed IDA configuration](docs/configuration.md#managed-headless-ida)
and [the example](examples/idalib-mcp.yaml). The existing `ida-mcp` mode
continues to connect to an externally managed server.

```yaml
llm:
  provider: claude-cli
  model: sonnet

# Optional: use a different provider/model for checking.
agents:
  checker:
    provider: codex
    model: gpt-5.4

backend:
  type: ghidra-bridge
  cli_path: ghidra-bridge

project_profile:
  name: generic-cpp
  language_standard: C++20
  source_root: src
  hooks_csv: null

orchestrator:
  max_review_rounds: 4
  investigation_enabled: true
  max_investigations: 8
  selection_strategy: dependency-order
  max_attempts_per_function: 3

validation:
  enabled: true
  copy_project: true
  project_root: .
  build_commands:
    - [cmake, -S, ., -B, build]
    - [cmake, --build, build]
  test_commands:
    - [ctest, --test-dir, build, --output-on-failure]
  require_build: true
  require_tests: true
  require_verified: true
  # This explicitly attests that the project-owned commands above are
  # meaningful validation gates. Leave false for untrusted commands.
  trust_configured_commands: true
  keep_project_copy: false
  parity_fail_on_red: true
  parity_fail_on_yellow: false
```

Validation is deliberately strict: with the generated defaults, no configured
commands produce `UNKNOWN`, and `require_verified: true` rejects that result.
For exploration without build validation, explicitly set
`validation.enabled: false`; such results are not build-verified.

Start with one function before launching a class run:

```bash
re-agent reverse --address 0x401000
re-agent reverse --class CTrain --max-functions 10
re-agent status
```

## LLM providers

### Claude API

```yaml
llm:
  provider: claude
  model: claude-sonnet-4-5-20250929
```

Set `ANTHROPIC_API_KEY` or `RE_AGENT_LLM_API_KEY`.

### Claude CLI

Authenticate the local Claude Code CLI first, then configure:

```yaml
llm:
  provider: claude-cli
  model: sonnet
  cli_path: claude
  effort: high
  max_budget_usd: 1.0
```

Claude CLI supports real session resume and reports usage/cost metadata. A
stale CLI login can still require re-authentication even when its auth-status
command reports a session.

Roles run tool-free (`--tools ""`). Set `claude_tools` to a built-in subset
such as `"Read,Grep,Glob"` to let a role consult files; MCP tools are denied
either way.

### OpenAI-compatible APIs

```yaml
llm:
  provider: openai # or openai-compat
  model: your-model
  base_url: https://your-endpoint.example/v1 # optional
```

Set `OPENAI_API_KEY` or `RE_AGENT_LLM_API_KEY`.

### Codex CLI

```yaml
llm:
  provider: codex
  model: gpt-5.4
```

Codex uses the authenticated local `codex exec` command. CLI-provider
`max_tokens` values are planning allowances, not hard output limits.

The provider passes `-c 'project_doc_fallback_filenames=["REAGENT_RUNNER.md"]'`
on both opening and resumed turns. This overrides user and project fallback
settings without requiring a Codex profile.

For separate interactive instructions, put this at the top level of your
project's `.codex/config.toml`:

```toml
project_doc_fallback_filenames = ["CLAUDE.md"]
```

Keep interactive project guidance in `CLAUDE.md` and runner guidance in
`REAGENT_RUNNER.md`. Migrate project `AGENTS.md` / `AGENTS.override.md` files:
those names take precedence over fallback files. Use bare fallback filenames,
not paths such as `.claude/REAGENT_RUNNER.md`.
The provider continues to enforce a read-only sandbox.

### Pi CLI

```yaml
llm:
  provider: pi
  model: ""        # empty defers to Pi's configured default model
  effort: high     # maps to Pi's thinking level
```

Pi uses the authenticated local `pi` command
([pi.dev](https://pi.dev), `@earendil-works/pi-coding-agent`). ReAgent keeps
Pi's default tools enabled unless `pi_tools` narrows them, and continues one
Pi session across a role's turns. `cli_path` is optional; an unchanged `model`
defers to Pi's own default.

### Runner prompt

The CLI providers run from your project directory, so the harness would
otherwise treat that project's own prompt (`AGENTS.md` / `CLAUDE.md`) as
context for every reverser and checker call. `runner_prompt_file` suppresses
that discovery and injects the named file as the role's system prompt instead:

```yaml
llm:
  provider: pi
  runner_prompt_file: .claude/SKILL_RUNNER.md
  pi_tools: "read,grep,ls"   # "" disables every tool
```

The path is resolved against the working directory. For Codex, an explicit
`runner_prompt_file` disables project document discovery, including the runner
fallback, and adds the file contents as developer instructions. Without this
option, Codex discovers `REAGENT_RUNNER.md`.
Codex still loads its
global `$CODEX_HOME/AGENTS.md`; only the project document is suppressed.

Omit `agents.reverser` or `agents.checker` to reuse the top-level `llm`
configuration for that role. A role block is a complete role configuration,
not a field-by-field merge with `llm`.

</details>

## Evidence and investigation

When supported by the backend, the reverser preloads a bounded evidence bundle
and can request additional read-only operations:

- `decompile`, `xrefs_from`, and `xrefs_to`
- `struct` and `enum`
- `vtable`, `global`, and `strings`
- `context`, normalized `pcode`, and `cfg`

Evidence bundle data is also ingested into
`reports/re-agent/knowledge-graph.json`, connecting functions, calls, globals,
and strings. Unsupported bridge capabilities degrade gracefully.

## Candidate validation

Generated code is written to an overlay. With `copy_project: true`, the project
is copied to a temporary directory, the candidate replaces the matching body
there, and commands run from that copy. `.git`, `.venv`, `build`, `reports`, and
Python cache files are not copied. Internal symlinks are remapped into the copy; external or broken links are rejected. Temporary project copies are deleted unless
`keep_project_copy: true`.

Commands may use:

- `{candidate_file}`, `{overlay_root}`, and `{source_file}` placeholders;
- `RE_AGENT_CANDIDATE_FILE`, `RE_AGENT_OVERLAY_ROOT`, and
  `RE_AGENT_SOURCE_FILE` environment variables.

Configured build/test/runtime commands are arbitrary project-owned shell
commands. The agent cannot prove from their text that they actually validate a
candidate, so they only become acceptance evidence when
`trust_configured_commands: true` is set explicitly.

If multiple C++ definitions match an overloaded method and the source cannot be
disambiguated, the overlay is rejected instead of replacing an arbitrary body.

## Verification and parity

The objective verifier runs on each review round. It compares generated code
with available decompile, assembly, CFG, and normalized high P-code evidence.
It returns `FAIL` only for strong mismatches; insufficient evidence returns
`UNKNOWN`.

The reversal pipeline runs the 11 built-in heuristic parity signals and configured
semantic rules against the generated candidate body on every round. RED is blocking by default; YELLOW can be made
blocking with `validation.parity_fail_on_yellow`.

The standalone command analyzes existing source: `re-agent parity` analyzes functions in
the existing source tree. It also supports semantic-rule files and manual check
overrides. Its process exit code remains zero on RED unless `--strict-exit` is
used.

The 11 built-in signals are:

| Signal | Level | Description |
|---|---|---|
| Missing source | RED | No source body was found |
| Stub markers | RED | Source contains a configured stub marker |
| Trivial stub | RED | Small plugin-call-heavy body with no control flow |
| Large ASM, tiny source | RED | Large disassembly with a very small source body |
| Plugin-call heavy | YELLOW | Plugin calls dominate the source body |
| Short body | YELLOW | Body has fewer than six lines |
| Low call count | YELLOW | Decompiled callees greatly exceed source calls |
| FP sensitivity | YELLOW | Assembly has FP-sensitive operations but source has no math tokens |
| Call-count mismatch | YELLOW | Source and assembly call counts differ beyond the configured threshold |
| NaN logic | YELLOW | Decompile indicates NaN-sensitive behavior missing from source |
| Inline wrapper | INFO | Source forwards to an internal implementation |

The built-in signal set is fixed; configuration exposes selected thresholds,
inline-wrapper behavior, semantic rules, and manual overrides rather than an
individual toggle for every signal.

## CLI reference

Global options must precede the subcommand, for example
`re-agent --config custom.yaml status`.

| Command | Purpose |
|---|---|
| `re-agent init --profile generic-cpp` | Create `re-agent.yaml` from a profile |
| `re-agent reverse --address ADDR` | Reverse one function |
| `re-agent reverse --class CLASS --max-functions N` | Reverse a bounded class batch |
| `re-agent reverse --class CLASS --dry-run` | Show a target plan without LLM calls |
| `re-agent reverse ... --max-rounds N --skip-parity` | Override loop/parity behavior |
| `re-agent parity --address ADDR --strict-exit` | Analyze an existing source function |
| `re-agent parity --filter REGEX --limit N --output report.json` | Filter and export parity results |
| `re-agent parity ... --skip-ghidra` | Run source-only parity signals |
| `re-agent status --class CLASS --format text` | Show session progress |
| `re-agent estimate --address ADDR` | Estimate one function |
| `re-agent estimate --class CLASS --limit N` | Estimate a class batch |
| `re-agent annotate --symbols symbols.json` | Preview IDA name/comment proposals |
| `re-agent annotate --symbols symbols.json --allow-prototype-changes --write --save` | Apply reviewed function type refinements and save the IDB |
| `re-agent recover-types --address ADDR` | Investigate IDA object/vtable types with an independent agent |
| `re-agent recover-types --address ADDR --write --save` | Recover types and save after independent readback |

Use `re-agent <command> --help` for the exact option list.

## Refresh selected function comments in IDA

Use a repeatable hexadecimal `--address` filter to select proposals before any
backend calls. A requested address with no matching proposal is an error.
`--comments-only` disables renames and type operations, including type queries:

```sh
re-agent annotate --address 0x4A3890 --comments-only
re-agent annotate --address 0x4A3890 --comments-only --write --save
```

Function comments use a single `[re-agent:begin]` / `[re-agent:end]` block.
Re-annotation replaces that block and preserves all text outside it. An identical
comment is reported as `unchanged`. Only the **non-repeatable function comment**
is updated; address comments and repeatable function comments remain untouched.
The server must expose `py_eval` for the fixed comment helper.

Changed comments must fit a conservative **1024 UTF-8 byte** budget, including
markers, evidence, confidence, and preserved human text. Dry-run and the write
helper reject oversized comments before writing the comment: IDA can silently
truncate longer comments even when both markers survive. Shorten `Evidence:`
entries or the proposal text and keep full evidence in `symbols.json`; comments
are never automatically shortened. Identical existing comments need no write
and are exempt from this budget.

If the helper's write or immediate readback fails, it attempts to restore the
previous comment and verifies it by reading it back. The error reports whether
restoration was confirmed; restoring the text does not clear IDA's modified flag.
An independent readback failure or communication error does not trigger a blind
restore that could overwrite a subsequent human edit. Inspect the comment and
the report's original text before saving or retrying when recovery is uncertain.

A nonempty comment without a valid unique block is reported as a conflict and
left unchanged. This includes comments written by older versions, whose ownership
cannot be established automatically. To migrate one, inspect the complete
current/proposed text in the dry-run report, then explicitly replace it:

```sh
re-agent annotate --address 0x4A3890 --comments-only --replace-function-comment
re-agent annotate --address 0x4A3890 --comments-only --replace-function-comment --write --save
```

`--replace-function-comment` requires `--address` and replaces the **whole**
ordinary function comment, including human text. Before each write the helper
checks the original comment again; a separate read verifies the result. Failed or
unconfirmed writes are reported with a nonzero exit status, never retried blindly,
and suppress `--save`; inspect the IDB before retrying. Comment conflicts can
coexist with eligible name/type changes in normal mode; use `--comments-only`
when only comments should change. Writes are not a batch transaction.

`--only-unnamed` retains its existing whole-entry skip behavior. It cannot be
combined with `--comments-only`, nor can either type-change flag be combined with
`--comments-only`. Normal annotation still applies proposed names verbatim:
`allow_overwrite=False` prevents name collisions with other addresses, not
replacement of the target's current name. Project naming suffixes are not inferred.

`reverse` replaces the entire proposal for an equivalent hexadecimal address,
under a file lock. On loading existing files, `annotate` collapses identical
selected rows but rejects conflicting proposals for the same address before any
writes. It never assumes the last row is newest. Unselected conflicts do not
block a scoped operation. Symbol-name aliases are not matched by `--address`;
regenerate proposals with numeric addresses for address-based selection.

## Apply function prototype proposals in IDA

`reverse` can attach an optional `prototype` to each symbol in
`report_dir/symbols.json`. Existing name/comment-only files remain supported.
The prototype has its own evidence, confidence and independent checker review;
a verified name does not approve a function type. The harness captures
`expected_current` from the backend and resets the review on every reversal/fix
response. An absent, malformed or mismatched checker review never grants approval.

An example of a **reviewed artifact** (evidence must reference actual inputs):

```json
{
  "schema_version": 1,
  "symbols": [{
    "address": "0x4A3890",
    "name": "FileClass::ReadWholeFile_4A3890",
    "prototype": {
      "declaration": "void *__thiscall FileClass::ReadWholeFile_4A3890(FileClass *this);",
      "expected_current": "void *__thiscall(void *this)",
      "required_types": ["FileClass"],
      "confidence": "verified",
      "evidence": ["matching-version header declaration/address and binary ABI evidence"],
      "review_status": "approved",
      "review_notes": ["independent checker evidence references"]
    }
  }]
}
```

Preview first, then explicitly enable writes:

```sh
re-agent annotate --symbols symbols.json --allow-prototype-changes
re-agent annotate --symbols symbols.json --allow-prototype-changes --write --save
```

By default, annotation supports only qualifier-preserving `void *` to existing complete
named struct/class pointer refinements. IDA must parse one plain prototype with
an explicit `__cdecl`, `__stdcall`, `__fastcall` or `__thiscall` convention.
Return types, function/argument flags, parameter counts, and ABI locations must
remain unchanged. Complex declarators, varargs, hidden-parameter changes and
custom calling conventions are rejected. Types are never created or imported.
The connected IDA server must expose `py_eval`; fixed IDAPython helpers perform
read-only preflight and a guarded native type application. Proposal strings are
passed as data, never as Python code. Unsupported helpers fail closed.

### Inferred prototypes and ABI type corrections

An inline header definition can identify a signature without stating its binary
address. Keep such a prototype `inferred`; do not relabel it `verified` to enable
writing. After independent checker approval, opt in for selected addresses:

```sh
re-agent annotate --symbols symbols.json --address 0x43AD00 \
  --allow-prototype-changes --allow-inferred-prototypes \
  --allow-abi-type-corrections
# Review the dry-run report, then repeat with --write --save.
```

`--allow-inferred-prototypes` authorizes reviewed inference.
`--allow-abi-type-corrections` separately permits same-width integer-to-integer
or integer-to-data-pointer corrections, including return types. Supported new
pointers are `void *` or existing complete named struct/class pointers.
Both flags require `--allow-prototype-changes` and explicit `--address` selection.
A verified proposal needing corrections still requires the correction flag.
The flags do not override disputed/unreviewed proposals, missing evidence, stale
snapshots, ABI mismatches, or unsupported types. Calling convention, flags,
argument count, stack layout and argument/return locations must remain unchanged.
Bool/enums, floats, aggregates, function pointers, arbitrary pointer casts and
qualifier changes are excluded.

Inferred proposals and all extended corrections need these additional fields
inside `prototype`, alongside the existing declaration/evidence fields:

```json
{
  "confidence": "inferred",
  "evidence_kind": "signature-bound",
  "evidence_details": {
    "header": "Header path and lines defining the signature",
    "version": "Evidence that the header matches the binary version",
    "address_binding": "Specific binary branches, member offsets and call sites"
  },
  "abi_evidence": {
    "calling_convention": "Evidence for registers, stack arguments and cleanup",
    "return": "Evidence covering every returning path",
    "arg:0": "Evidence for the explicit this parameter",
    "arg:1": "Evidence for the changed first explicit parameter",
    "arg:2": "Evidence supporting the changed signedness"
  }
}
```

Use `address-bound` when a source explicitly binds the address to the signature;
use `signature-bound` for definitions bound to an address through binary behavior.
Argument indices include explicit `this`. Supply ABI evidence for every changed
type; unchanged positions need no entry. The checker reviews evidence semantics;
field presence and ABI compatibility alone do not prove correctness.
Old verified proposals remain supported. Old inferred proposals lacking these
fields must be regenerated and reviewed. Unknown confidence values are rejected.

Reports include individual type differences, evidence/review details and ABI
compatibility. `needs-opt-in` means reviewed and technically eligible, with
`required_flags` listing missing authorization; it does not certify correctness.
Other statuses distinguish `insufficient-evidence`, `unreviewed`, `disputed`,
`unsupported-change`, and `stale`. The latter two produce a nonzero exit.
Normal annotation still applies eligible names/comments, so inspect those
operations in the preview too. Neither extended flag implies comments-only mode.

Dry run reports current/proposed types without applying types, comments, names,
or saving. Write mode pins the target to an exact function entry before renaming,
checks the original type again immediately before application, and independently
reads both the stored type and fresh decompilation afterwards. Stale proposals
are rejected; already equivalent types are reported as `unchanged`. `--save`
only reports success when IDA confirms the save.

`--only-unnamed` skips the entire entry, including its type, when the function is
already named. Omit it when refining an already named function.
`--include-flagged` cannot override a disputed/unreviewed prototype. Shared struct
changes and prototype changes require separate invocations and fresh proposals.

Reports contain separate name, comment and prototype outcomes: a rejected type
does not prevent otherwise eligible name/comment changes. Invalid types, failed
writes/readbacks, and failed saves produce a nonzero exit status. On an ambiguous
write failure (including a timeout), recovery reads the actual state before
attempting to restore the original explicit/inferred type state. If recovery
cannot be confirmed, further prototype writes and automatic saving stop. This
is not a transaction across the entire annotation batch; inspect the report for
partial changes. Changing the target prototype can affect caller decompilation.

For live acceptance, use a disposable IDB with an existing class type and a
`void *this` function: preview, apply, independently query/decompile the target,
then save and reopen the IDB to check persistence. The mocked tests exercise the
pipeline and failures but do not replace that integration check.

## Recover class pointers and virtual calls in IDA

`recover-types` is an interactive, IDA-specific agent. It investigates object
sources and virtual calls, creates missing class/vtable types, applies function
and local-variable types, then re-decompiles to decide the next step. It does
not consume or extend `SymbolProposal`; `annotate` remains the existing proposal
application workflow. Other backends currently report this command as unsupported.

Configure its model independently and reuse the existing IDA connection:

The `idalib-mcp` backend also supports this command and `annotate`. Each command
owns a separate worker. In managed mode, `--write` without `--save` performs
the investigation and readback but discards unsaved changes when the worker
closes; use `--write --save` to persist verified changes for later stages.

```yaml
backend:
  type: ida-mcp
  url: http://127.0.0.1:13337/mcp
  timeout_s: 120

recovery:
  provider: claude-cli  # Also: claude, openai, openai-compat, codex, pi
  model: sonnet
  max_steps: 40
  max_result_chars: 24000
  timeout_s: 1800
```

The `recovery` block accepts the model/provider fields of `llm`, but does not
inherit `llm` or `agents` settings. Set the provider and model appropriate for
your account. Native CLI tools are disabled for this role: the agent returns
tool requests and the recovery loop dispatches them to the configured IDA MCP
endpoint, recording every request and result. Native Codex MCP connections and
shell tools are disabled on opening and resumed turns. `runner_prompt_file`, if
set, is supplied as additional context; it does not replace the recovery policy.

The IDA server must expose `py_eval` for fixed type readback helpers and
`idb_save` for backups/saving. A dedicated recovery local-type tool writes saved
Hex-Rays settings using the variable's location, definition address and expected
current type. It also works for automatic locals without prior user settings,
which some MCP `set_type(kind=local)` implementations cannot handle.

```sh
# Read-only investigation; DOES call the model. Addresses must be function entries.
re-agent recover-types --address 0x437A10

# Evidence can be a source header, analysis note, or exported evidence packet.
re-agent recover-types --address 0x437A10 --evidence blitter-analysis.md --write --save
```

Repeat `--address` for the write scope and `--evidence` for additional files.
`--objective` narrows the recovery task. `--include-candidates` discovers
candidate overlays that earlier `reverse` runs wrote to
`report_dir/candidates/<address>/` for the selected addresses and injects them
as evidence, labelled unverified, giving the type agent the earlier run's
inferred class/vtable layout without a manual `--evidence` copy; IDA readback
remains the source of truth. It is opt-in and independent of `--write`, so
preview can use it to check a prior inference and a write run can decline it by
default. Requesting it when no overlay matches the selected addresses is an
error rather than a silent no-op. Related functions may be read; the agent
is instructed to modify only selected functions and newly created types, reuse
equivalent existing types, and report conflicting shared types or required
out-of-scope changes as unresolved. Do not run concurrent editors/agents on the
same IDB during a recovery run. Type changes can affect caller decompilation even
when callers are not explicitly edited.

Preview exposes only a fixed read-tool allowlist. Model-generated Python and
all write tools are unavailable; a fixed, read-only IDAPython helper captures
the initial function/local types. A preview is an investigation plan, not an
exact patch: subsequent decompilation can reveal additional work.

`--write` enables IDA type-editing tools and **trusted model-authored `py_eval`**.
The latter has the privileges of the IDA process: scope and no-save instructions
are agent policy, not a sandbox for arbitrary Python. This mode is intentionally
more permissive than `annotate`. Before the first potentially mutating tool,
the host creates an IDB backup alongside the active database on the **IDA host**.
The report records its path. Failure to create the backup prevents writes.

Reports default to `report_dir/recovery/<run-id>.json`; `--output` selects a path.
They contain initial/final decompilation, tool events persisted before dispatch,
backup location, agent conclusions, independent type checks and unresolved work.
`verified` means that the agent finished without reported unresolved items and
its type assertions matched fresh IDA readback; it is not proof of semantic
equivalence or discovery of every virtual call. The checks include at least a
selected function's local-variable or prototype assertion. Review slot offsets,
signatures and the resulting calls as well as the summary.

`--save` requires `--write` and is performed only after successful readback with
no unresolved items. A write error/timeout stops further writes and suppresses
automatic saving; the operation may already have partially changed the IDB.
Budget exhaustion, interrupted runs and failed verification also leave a journal
and return a nonzero exit status. Backups provide manual recovery, not automatic
transactional rollback. Unsaved changes remain in the running IDA instance.
Re-run against the current state after reviewing any partial changes; there is
no blind replay of a previous run's tool requests.

For a reproducible live acceptance exercise, see
[`examples/ida_type_recovery`](examples/ida_type_recovery/README.md).

## Working with function groups

For targets that span classes or have no recovered class names, create a bounded
manifest before running reconstruction:

```sh
re-agent plan --address 0x140001000 --max-depth 2 --max-functions 50 --output group.json
re-agent reverse --manifest group.json --dry-run
re-agent reverse --manifest group.json --max-functions 5
re-agent status --manifest group.json --format json
re-agent evidence --manifest group.json --output evidence-packets
```

Planning makes no model calls. Manifests retain returned evidence, direct call
edges, input fingerprints, and explicit gaps. Execution reuses the existing
validation and resume workflow; evidence export reads the stored snapshot only.
Use a new or empty export directory. Coverage describes the selected inventory
and configured acceptance policy, not proof of whole-program equivalence.

Build/test/runtime commands also accept argument arrays for native Windows and
POSIX execution; legacy shell strings retain their `/bin/sh` requirement. See
[configuration](docs/configuration.md) for command forms and manifest semantics,
and [implementation stages](docs/tooling-upgrade-plan.md) for scope and validation.

## Configuration precedence

The effective order is CLI runtime overrides, supported environment variables,
`re-agent.yaml`, then dataclass defaults. The currently supported environment
variables are:

- `RE_AGENT_LLM_PROVIDER`
- `RE_AGENT_LLM_API_KEY`
- `RE_AGENT_LLM_MODEL`
- `RE_AGENT_LLM_BASE_URL`
- `RE_AGENT_BACKEND_CLI_PATH`
- `RE_AGENT_BACKEND_TIMEOUT`

Role-specific `agents.*` configuration, validation, project profiles, parity,
and output paths should be configured in YAML.

See [docs/configuration.md](docs/configuration.md) for the complete schema.

## Profiles

- `generic-cpp`: portable C/C++ defaults
- `windows-x64`: Microsoft x64-oriented prompt rules
- `gta-reversed`: GTA-reversed hooks, stubs, source paths, and project rules
- `openrct2`: OpenRCT2-oriented hook/stub patterns

Profiles initialize project configuration; they do not replace bridge exports
or project-specific validation commands.

## Outputs

Default artifacts include:

- `reports/re-agent/code/`: final generated code per function
- `reports/re-agent/logs/`: unique run directories with per-call prompts, responses, provider metadata and round results
- `reports/re-agent/candidates/`: non-isolated candidate overlays
- `reports/re-agent/knowledge-graph.json`: persistent evidence graph
- `re-agent-progress.json`: current per-function state plus run history

The session file is atomically rewritten on save. Its `functions` map stores the
latest state per address, while its `runs` list preserves recorded attempts.

## How it compares

| Approach | Primary use | Evidence and validation | Workflow |
|---|---|---|---|
| Traditional decompiler | Translate machine code into analyst-readable pseudocode | Decompiler analysis; correctness is assessed manually | Function-by-function analysis |
| Interactive Ghidra AI or MCP assistant | Let an analyst ask questions and request Ghidra operations | Depends on the analyst, prompts, and connected tools | Human-directed conversation |
| `auto-re-agent` | Generate and validate candidate C/C++ implementations | Ghidra evidence, independent checker, structural checks, configured build/tests, and parity signals | Bounded autonomous reverser/checker pipeline with persistent reports |

`auto-re-agent` complements Ghidra rather than replacing it: Ghidra supplies
the program analysis, while the agent orchestrates evidence collection,
implementation, review, validation, and reporting. It is designed for
repeatable project-scale workflows, not just one-off decompiler chat.

## Frequently asked questions

### Is auto-re-agent a decompiler?

Not in the traditional sense. Ghidra performs the disassembly, decompilation,
and program analysis. `auto-re-agent` uses that evidence plus project source
context and LLMs to produce and validate candidate C/C++ implementations.

### Does it require Ghidra?

The full binary-backed reversal workflow currently uses Ghidra through
`ghidra-ai-bridge`. Existing source can be checked with source-only parity via
`re-agent parity --skip-ghidra`, but that mode has less evidence.

### Which LLM providers are supported?

Claude API, Claude CLI, OpenAI-compatible APIs, Codex CLI, and Pi CLI are supported.
The reverser and checker can use different providers or models.

### Does it modify the original source tree?

No. Generated implementations are written to reports and candidate overlays.
When isolated validation is enabled, builds and tests run in a temporary copy
of the project.

### Can it prove that generated source is equivalent to the binary?

No. The checker, structural verifier, configured build/test gates, and parity
signals provide conservative evidence, not a formal proof of semantic or
binary equivalence.

### What binaries and projects can it analyze?

It can work with programs that Ghidra can import and that the bridge can export.
Useful reconstruction also depends on project-specific source context, types,
symbols, validation commands, and the evidence available in the target binary.

### How are LLM cost and run length controlled?

Review rounds, investigations, and attempts per function are bounded in the
configuration. Provider logs record available usage and cost metadata; actual
cost depends on the selected models, evidence volume, and target complexity.

## Safety and limitations

- re-agent does not commit or push generated code;
- candidate generation does not overwrite the original source tree;
- review rounds, evidence actions, and per-function attempts are bounded;
- prompt/response logs include internal evidence-loop calls in unique run directories;
- validation argument arrays run directly on Windows and POSIX; shell strings
  require `/bin/sh`. Commands should only be trusted when controlled by the project owner;
- structural and parity checks catch useful mismatches but do not prove binary
  equivalence;
- real Ghidra/PyGhidra integration depends on the local Ghidra project and has
  to be tested in that environment.

## Why ghidra-ai-bridge stays separate

`ghidra-ai-bridge` remains an independent analysis package with a versioned
JSON/CLI evidence surface. auto-re-agent consumes it through a capability-based
backend. The same interface carries an IDA backend (`backend.type: ida-mcp`,
talking to an `ida-pro-mcp` server), and leaves room for Binary Ninja or other
backends.

## Development

```bash
git clone https://github.com/Dryxio/reagent.git
git clone https://github.com/Dryxio/ghidra-bridge.git
cd reagent

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e "../ghidra-bridge[headless]"
python3 -m pip install -e ".[dev]"

pytest -q
ruff check src tests
mypy src
```

## License

MIT
