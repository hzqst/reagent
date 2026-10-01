# Configuration

re-agent is configured primarily through `re-agent.yaml`, plus the supported
environment variables and runtime CLI flags documented below.

## Priority Order

Supported CLI overrides > supported environment variables > YAML config > defaults

## Environment Variables

| Variable | Maps to |
|----------|---------|
| `RE_AGENT_LLM_PROVIDER` | `llm.provider` |
| `RE_AGENT_LLM_API_KEY` | `llm.api_key` |
| `RE_AGENT_LLM_MODEL` | `llm.model` |
| `RE_AGENT_LLM_BASE_URL` | `llm.base_url` |
| `RE_AGENT_BACKEND_CLI_PATH` | `backend.cli_path` |
| `RE_AGENT_BACKEND_TIMEOUT` | `backend.timeout_s` |
| `RE_AGENT_LLM_RUNNER_PROMPT_FILE` | `llm.runner_prompt_file` |

## LLM Config

```yaml
llm:
  provider: "claude"        # claude | claude-cli | openai | openai-compat | codex | pi
  model: "claude-sonnet-4-5-20250929"
  api_key: null
  base_url: null
  max_tokens: 4096
  temperature: 0.0
  timeout_s: 1800
  runner_prompt_file: null   # project prompt for the CLI providers
  claude_tools: null         # claude-cli only: value for --tools
  pi_tools: null             # Pi only: tool allowlist ("" disables every tool)
  input_cost_per_million: 0.0
  output_cost_per_million: 0.0
```

Notes:

- `claude` uses the Anthropic SDK and typically reads `ANTHROPIC_API_KEY`
- `openai` and `openai-compat` use the OpenAI-compatible chat completions provider and typically read `OPENAI_API_KEY`
- `codex` uses the local `codex` CLI and ChatGPT login credentials instead of an API key
- `claude-cli` uses the local Claude Code CLI login. `cli_path`,
  `max_budget_usd`, and `effort` are optional.
- `pi` uses the local [Pi coding agent](https://pi.dev) CLI and its existing
  login/configuration. `cli_path` is optional; `effort` maps to Pi's `--thinking`
  level. An empty or unchanged `model` defers to Pi's own configured default.

CLI providers run from the project directory, so the harness would otherwise
inject that project's own prompt (`AGENTS.md` / `CLAUDE.md`) into every
reverser and checker call. `runner_prompt_file` replaces it with a prompt meant
for the sub-role:

```yaml
llm:
  provider: pi
  runner_prompt_file: .claude/SKILL_RUNNER.md
  pi_tools: "read,grep,ls"
```

- The path is resolved against the working directory and must exist.
- The harness's own discovery is suppressed: Claude Code memory through
  `--settings`/`claudeMdExcludes`, codex's project `AGENTS.md` through
  `-c project_doc_max_bytes=0`, Pi's context files through `--no-context-files`.
- The file is injected as the role's system prompt: `--append-system-prompt-file`
  (claude-cli), `-c developer_instructions=` (codex), `--append-system-prompt`
  (pi). Codex still loads its global `$CODEX_HOME/AGENTS.md`.
- `claude_tools` is the value for `claude --tools`. Left unset the provider
  stays tool-free, which is how re-agent has always run Claude; `""` also
  disables every tool and a subset such as `"Read,Grep,Glob"` allows just
  those. MCP tools are denied by `--disallowedTools` either way.
- `pi_tools` narrows Pi's toolset through `--tools`; the allowlist covers
  built-in, extension and custom tools alike, so `"read,grep,ls"` leaves the
  MCP adapter unreachable. An empty string instead passes `--no-tools`.

Independent role overrides inherit the top-level `llm` block only when the
role is omitted:

```yaml
agents:
  reverser:
    provider: claude-cli
    model: sonnet
    max_budget_usd: 1.0
    effort: high
  checker:
    provider: codex
    model: gpt-5.4
```

A present role block is a complete `LLMConfig`; its individual fields are not
merged with the top-level block.

## Backend Config

```yaml
backend:
  type: ghidra-bridge
  cli_path: ghidra-bridge
  timeout_s: 45
```

The `ghidra-ai-bridge` package installs the `ghidra-bridge` executable. Prepare
its exports separately before running reversal commands.

### IDA backend

```yaml
backend:
  type: ida-mcp
  url: http://127.0.0.1:13337/mcp
  timeout_s: 120
```

`ida-mcp` talks to a running [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp)
server over JSON-RPC instead of shelling out. The server exposes an open IDA
database; no exports are needed. Only read-only evidence tools are used, so the
IDB is never modified. `ida` is accepted as an alias for the type.

`timeout_s` must exceed the IDA-side tool timeouts, which reach 90s for
`decompile`/`disasm` and 120s for the composite analysis tools.

Backend capabilities are probed from the server's `tools/list`, so tools
disabled in the plugin's config page correctly report as unavailable. An
unreachable server raises an error rather than reporting "no capabilities",
which would let commands silently proceed with degraded evidence.

Two behaviors are worth knowing:

- **Addresses are re-prefixed.** re-agent normalizes addresses to bare hex
  (`0041bef0`), but IDA's address parser rejects that form and requires a `0x`
  prefix or a symbol name. Address-bearing arguments are converted
  automatically; symbol names pass through untouched.
- **Truncated output is re-fetched.** The server replaces structured output
  larger than 50,000 characters with a preview plus a download URL. The backend
  downloads the full payload; if that fails it raises rather than using the
  preview.

`has_structs` is derived from the `search_structs` tool, but `get_struct` reads
the `ida://struct/{name}` MCP resource instead. A profile that omits
`search_structs` (such as the upstream `readonly.txt`) therefore reports
`has_structs: false` even though struct retrieval still works. No production
call site consults this flag.

### Managed headless IDA

```yaml
backend:
  type: idalib-mcp
  database_path: /absolute/path/program.i64
  idalib_mcp_path: idalib-mcp
  startup_timeout_s: 120
  shutdown_timeout_s: 15
  timeout_s: 45
```

This mode requires a licensed, activated IDA/idalib installation and an
`idalib-mcp` supervisor exposing `idb_open`, `idb_list`, `py_eval`, and
`server_health`. The supervisor must support explicit `database` routing,
`force_headless`, and owned worker PID metadata. The Python environment behind
the executable must have working idalib and Hex-Rays support; reagent does not
import IDA into its own interpreter or install it automatically.

`database_path` must refer to an existing packed `.i64`/`.idb`. Relative paths
are resolved against the working directory, as with other project paths.
`idalib_mcp_path` can be an executable name on PATH or an explicit path. No
database is automatically created, replaced, or rebuilt. Close other IDA
instances using this database first. Concurrent reagent stages targeting the
same database fail with an explicit ownership error. Different databases may
run independently.

The lifecycle binds to `127.0.0.1` on a dynamically allocated port; `backend.url`
is unused in this mode. Startup verifies listener ownership, worker ownership,
and the actual IDB path before handing a client to a task. Supervisor tools are
bound to the selected database; models cannot choose another session. Struct
layout uses `type_inspect`, since the supervisor does not route IDA resources.

Each reverse, fix, and checker call gets a fresh worker and evidence cache.
One `recover-types` invocation (including all selected addresses and readback)
and one `annotate` invocation each form a stage. Planning, selection, doctor,
estimate, objective verification, and parity evidence use separate bounded
stages. Compilation and tests run after their IDA stage has closed. Direct
Python callers use `with backend_stage(backend, "task"):` from
`re_agent.backend.stages` around raw managed-backend operations; the public
agent/orchestrator entry points already provide their own stage boundaries.

The worker receives a heartbeat every 30 seconds while a model is running.
`startup_timeout_s` bounds startup/readiness; `shutdown_timeout_s` bounds each
shutdown operation. `timeout_s` controls individual evidence requests: increase
it for large functions or expensive composite tools. Lifecycle failures fail the
stage and are not silently accepted as source-only validation. Write calls are
never automatically replayed after a connection failure.

Only the existing explicit `--save` flow persists annotation/recovery changes.
Closing explicitly discards any remaining unsaved changes before exiting IDA.
The owned worker's runtime default for `idapro.close_database` is also set to
discard, so a later idle shutdown or handled termination signal cannot silently
save pending edits if the reagent process disappears. Explicit `idb_save`
continues to work normally.
`--write` alone therefore does not carry changes to the next stage. Recovery
backups remain separate files under the existing recovery policy. On failure,
cleanup stops only recorded owned process identities, including detached
workers; it never closes an external GUI. Any cleanup failure or leftover IDA
working files is reported. Inspect such files before reopening; reagent does
not delete them or assume they are safe to discard.

Per-stage process output is written beneath `output.log_dir/idalib`. The
runtime endpoint is not persisted in configuration or project fingerprints.
Existing external `ida-mcp` configurations and fingerprints remain compatible.

Real IDA tests are opt-in and copy the provided database to pytest's temporary
directory. They make no model calls:

```sh
RE_AGENT_IDALIB_TEST_DATABASE=/path/to/small-test.i64 \
  pytest tests/test_backend/test_idalib_integration.py -q -k 'not long_running'

# Repeated stages for over two hours, including an idle period beyond the worker TTL.
RE_AGENT_IDALIB_TEST_DATABASE=/path/to/small-test.i64 \
RE_AGENT_IDALIB_SOAK_SECONDS=7260 \
  pytest tests/test_backend/test_idalib_integration.py -q -s -k long_running
```

On PowerShell, set the same variables with `$env:NAME = 'value'` before running
pytest. `RE_AGENT_IDALIB_TEST_EXECUTABLE` optionally selects a different
`idalib-mcp` executable. A skipped real-IDA test is not verification of the
installed runtime.

### Applying annotations back to the database

A reversal run may propose a name and comment for each function it
reconstructs. Proposals are collected in `report_dir/symbols.json` and are
**never** written to the database on their own. `annotate` applies them:

```sh
# Preview only — nothing is written without --write.
re-agent annotate --only-unnamed

# Apply renames and comments, then persist the database.
re-agent annotate --only-unnamed --write --save
```

`annotate` needs `backend.type: ida-mcp`, because it writes through the same
MCP endpoint the read backend uses.

| Flag | Effect |
| --- | --- |
| `--write` | Actually apply changes. Without it the command is a dry run that prints the diff and an undo list. |
| `--only-unnamed` | Skip addresses that already carry a non-placeholder name (`sub_*`, `nullsub_*`, `FUN_*`, ...). Recommended: it keeps reviewed symbols from being overwritten. |
| `--include-flagged` | Also apply proposals the checker disputed. By default those are skipped. |
| `--allow-struct-changes` | Permit struct member changes. Required in addition to `--write`. |
| `--save` | Save the IDA database once writing is done. |

Proposals may also come from upstream headers rather than from a model:

```sh
re-agent annotate --from-hooks YRpp/ YRpp-phobos-dev/ --only-unnamed --write
```

`--from-hooks` scans the given directories with `project_profile.hook_patterns`
and derives each entry's class from its file name (`TechnoClass.h` →
`TechnoClass`). Those proposals are marked `verified`, because a header
annotation states the name rather than inferring it.

The scan is deliberately conservative, because upstream header trees are often
duplicated copies of one another. An entry is dropped when the sources disagree
about its name, when the header's own name is a placeholder (`sub_*`), or when
two addresses would claim the same name and collide on rename; the count of
dropped entries is reported on stderr. A pattern must place the function name
in group 1 and the address in group 2, and should bound its whitespace classes
to a single line — a bare `\s` will cross the newline and capture an enclosing
class name instead of the function name.

Two safety properties are worth knowing:

- **A name is never overwritten.** Renames are issued with
  `allow_overwrite: false`, and `--only-unnamed` filters on top of that.
- **Struct changes are checked and reverted on surprise.** A change that would
  alter the struct's total size is rejected outright — it would shift every
  following consumer. A `move` that does not land at the requested offset is
  rolled back. Struct changes read IDA's own printed declaration (via a fixed
  `py_eval` template) rather than rebuilding it, so alignment attributes and
  gaps are preserved; this requires the IDA host to share a filesystem with
  re-agent.

Proposals carry a `confidence` marker: `verified` when a header states the name,
`inferred` when a model derived it from behavior. Both reach the database, and
the comment records which one it was, so an inferred name can never be mistaken
for a reviewed one.

## Recovery Config

The `recovery` section configures the independent type-recovery model (used by
`recover-types`). It does not inherit `llm` or `agents`, and it does not load
the workspace `CLAUDE.md` or scan any directory by itself.

```yaml
recovery:
  provider: codex
  model: gpt-6-sol
  max_steps: 40
  max_result_chars: 24000
  # Read-only reference roots for the recovery agent's read/grep/glob tools.
  # Empty (default) grants the agent no filesystem access.
  file_roots:
    - references/particleman_goldsrc_8684
    - references/halflife-updated/cl_dll/particleman
```

### Additional evidence: `--evidence` and `--evidence-dirs`

By default the recovery agent sees only the selected IDB functions and whatever
the operator passes on the command line:

- `--evidence <file>` reads one file (repeatable). This is the original channel
  and is unchanged.
- `--evidence-dirs <path-or-glob>` reads many files at once (repeatable). Each
  value is a glob relative to the run's working directory. A directory is
  expanded recursively; results are filtered by
  `project_profile.source_extensions` unless the value names a file literally.
  A value that matches nothing is an error, so a typo cannot look like a
  successful injection. Both `--evidence-dirs` and `--evidence_dirs` spellings
  are accepted.

### Filesystem tools: `recovery.file_roots`

`--evidence-dirs` injects a fixed snapshot up front. When the reference tree is
large, `recovery.file_roots` instead gives the recovery agent three host-side
read-only tools so it can look things up on demand:

| Tool | Purpose |
| --- | --- |
| `read` | Read a UTF-8 file under a root, with `offset`/`limit` paging. |
| `grep` | Regex-search files under a root; returns root/file/line. |
| `glob` | List files matching a glob under a root. |

Each root must exist, or the run fails before dispatching anything. Every path
the model requests is resolved against the roots and rejected if it escapes
them (absolute paths, `..`, and symlinks pointing outside all count as escapes).
Output is bounded (match counts, line counts, bytes) so a broad query cannot
flood the model's context. The tools are added to the catalog only when at least
one root is configured; with `file_roots: []` the agent has no filesystem access
at all, and requests for `read`/`grep`/`glob` are denied like any unknown tool.

File content is treated as data, never as instructions: the recovery system
prompt states that tool results and file text cannot expand the agent's
permissions.

## Project Profile

The `project_profile` section makes re-agent work across different RE projects.
This example is specifically for GTA-reversed-style source:

```yaml
project_profile:
  hook_patterns:
    - 'RH_ScopedInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)'
  stub_markers: ["NOTSA_UNREACHABLE"]
  stub_call_prefix: "plugin::Call"
  source_root: "./source/game_sa"
  source_extensions: [".cpp", ".h", ".hpp"]
```

## Parity Config

```yaml
parity:
  enabled: true
  call_count_warn_diff: 3
  inline_wrapper_autoskip: false
```

## Orchestrator Config

```yaml
orchestrator:
  max_review_rounds: 4
  max_functions_per_class: 10
  objective_verifier_enabled: true
  objective_call_count_tolerance: 3
  objective_control_flow_tolerance: 2
  investigation_enabled: true
  max_investigations: 8
  selection_strategy: dependency-order # dependency-order | easiest-first | high-impact
  max_attempts_per_function: 3
```

## Candidate Validation

Generated code is written to a safe overlay. Commands can use both format
placeholders and environment variables.

```yaml
validation:
  enabled: true
  # true copies the project to a temporary isolated directory before commands
  copy_project: false
  project_root: .
  build_commands:
    - 'clang++ -fsyntax-only "{candidate_file}"'
  test_commands: []
  runtime_commands: [] # optional differential/record-replay harness
  require_build: true
  require_tests: false
  require_runtime: false
  require_verified: true # UNKNOWN validation results block acceptance
  trust_configured_commands: false # explicit attestation for project-owned shell gates
  parity_fail_on_red: true
  parity_fail_on_yellow: false
  command_timeout_s: 900
  working_directory: .
  keep_project_copy: false # delete isolated full-project copies after validation
```

With `copy_project: true`, the default working directory becomes the isolated
project copy and the source candidate replaces the real relative source file.
Configure the project inside that copy (for example `cmake -S . -B build`)
before building because generated `build/` directories are intentionally not copied.
With it disabled, build commands must consume `{candidate_file}` or
`RE_AGENT_CANDIDATE_FILE` explicitly.

Shell commands are user-defined and cannot be proven meaningful merely by
inspecting their text. They therefore produce `UNKNOWN` until
`trust_configured_commands: true` explicitly attests that the configured
project commands compile/test the candidate. The non-isolated placeholder
check is an additional mistake detector, not a semantic proof.


## Version 0.3 options and migration

`orchestrator.max_llm_calls_per_function` (default 80) is a shared cap across all
reverser and checker calls, including investigation responses. Each review round
can use up to `max_investigations` evidence actions. `estimate` reports that bound;
token counts remain planning estimates, not provider guarantees.

`orchestrator.cumulative_validation` defaults to true and takes effect with
`validation.copy_project: true`. Successful candidates are promoted only into the
scratch project so later candidates validate against them. Source files in the
original project remain unchanged.

For structured exports, select:

```yaml
backend:
  type: ghidra-json
  export_dir: /path/to/ghidra-exports
  address_map: /path/to/address-map.json # optional
project_profile:
  compilation_database: /path/to/compile_commands.json # optional, requires clang++
```

The JSON backend reads bridge export objects directly (schema 1, including legacy
unversioned exports). Missing required function data and unsupported versions fail
explicitly. Class enumeration includes matching exported functions and has no
50-item display limit; session state filters accepted functions. Provide an address
map to associate unnamed `FUN_*` exports with source symbols.

Clang indexing uses translation unit compile flags and byte-correct body ranges.
Overloads without a unique identity, macro-expanded bodies and compiler errors are
rejected. The default lightweight indexer is still available without Clang.

Differential harness commands use argument arrays, without shell expansion. Each
harness reads one JSON value from stdin and emits one JSON value describing the
observed behavior. Include return values, modified memory and relevant effects in
that result. Comparison is exact; normalize address-dependent values or floating
point representations in the project-owned adapters when appropriate.

```yaml
validation:
  differential_reference: [/path/to/reference-harness]
  differential_candidate: ['{overlay_root}/candidate-harness']
  differential_cases_file: /path/to/cases.json
  trust_configured_commands: true
```

The cases file must be a nonempty JSON array. Timeouts, invalid JSON, nonzero exits
and mismatches fail the gate and are fed back to the reverser. A matching harness
only establishes agreement on its declared observables and supplied cases.

A benchmark manifest is a JSON array of objects with `name`, `reference`,
`candidate`, and `cases`. Optional `expected_match: false` marks a negative control;
`timeout_s` defaults to 30. The command fails when an expectation is not met.

CLI reversal now honors `output.format` (json, markdown or text), defaults to JSON,
and validates the acceptance configuration before model calls. Standalone parity
continues to support human overrides; candidate validation never inherits those
manual overrides. Session corruption raises an error without replacing the file.
Changes to fingerprinted inputs archive previous results; use a separate session
file for independent experiments. Round checkpoints seed subsequent attempts with
previous code and diagnostics; provider-side conversations are not resumed across
process restarts.

Shell gates require POSIX `/bin/sh`. Placeholders are expanded as environment data,
including in single/double quotes. Isolated working directories cannot escape the
copy. Copies are not OS sandboxes: trusted project commands can still explicitly
access external paths. Internal links are remapped; external/broken links fail.


### Portable validation commands

Each build/test/runtime command may be a legacy POSIX shell string or an argument
array. Arrays execute directly, without a shell, on Windows and POSIX:

```yaml
validation:
  build_commands:
    - [cmake, -S, "{overlay_root}", -B, "{overlay_root}/build"]
    - [cmake, --build, "{overlay_root}/build"]
  test_commands:
    - [ctest, --test-dir, "{overlay_root}/build", --output-on-failure]
```

Arguments support `{candidate_file}`, `{overlay_root}`, and `{source_file}`.
Spaces and shell metacharacters remain literal data; `$VAR` and shell syntax are
not expanded in arrays. Legacy strings still require `/bin/sh`; doctor reports
when it is missing. Existing isolation and command-trust requirements still
apply. Non-isolated arrays must explicitly include a candidate/overlay placeholder.


### Optional evidence gaps

Function-context bundles and per-function Ghidra JSON exports may include `gaps`:

```json
{"function":"0x140001000","site":"0x140001010","kind":"unresolved_call",
 "reason":"Indirect register call target not resolved","origin":"analysis-export"}
```

Kinds are `unavailable`, `unsupported`, `query_failed`, `unresolved_call`, and
`limit`. The site is optional. Addresses are hexadecimal strings of unrestricted
width. Labels describe observations; they do not establish recovered semantics.
The graph preserves full context bundles and gap records alongside existing
nodes/edges. Refreshing a context replaces its previous gap observations. Old
exports remain supported; absent caller/callee fields produce unavailable records
while explicitly empty lists describe a known empty result. Detailed indirect-call
records require an exporter that supplies them; ReAgent does not invent targets.


### Bounded target manifests

`re-agent plan --address 0x140001000 --max-depth 2 --max-functions 50 --output group.json`
creates a deterministic inventory without model calls. Repeat `--address` or use
`--match` with the backend's symbol-search syntax. Seeds are visited first, then
direct callees breadth-first. Cycles and duplicates are visited once. Depth zero
includes only seeds but still records their observed direct dependencies.

The manifest stores the existing project fingerprint, selected function identity,
selection depth, full returned decompilation/context evidence, direct call edges,
and explicit gaps. Limits describe incomplete exploration, never completeness.
Only call references are traversed; unresolved indirect calls require backend
records. Inspect gaps before using a manifest. Changing fingerprinted inputs
requires regenerating the plan. Backend CLI configurations without local export
content cannot fingerprint changes to an external analysis database; regenerate
after changes to that database.


Run a reviewed manifest with `re-agent reverse --manifest group.json --max-functions 5`.
`--dry-run` checks input identity and displays the inventory without model calls.
Manifest mode is exclusive with `--address` and `--class`. The existing selector
orders only manifest members using backend dependencies; external callees are
never added automatically. Existing retry limits, acceptance rules, sessions,
and cumulative scratch validation apply across class boundaries. A function
limit caps attempts in this invocation, not the total inventory. As with class
runs, cumulative source promotion requires unique existing source definitions.


### Searchable stored evidence

`re-agent evidence --manifest group.json --output packets` writes an index,
per-function JSON packets, a copy of the input manifest, and function/call/
reference/gap TSV files. This reads stored manifest evidence only: it needs no
backend, LLM, or configuration file and makes no claim about current binary state.
Use a new or empty destination. TSV cells escape backslashes, tabs, carriage
returns, and newlines. JSON packets retain full stored records and any truncation
markers. The fingerprint and source context origin identify the evidence snapshot.


### Manifest coverage

`re-agent status --manifest group.json --format json` reconciles every selected
function with existing session results. Primary statuses are `unattempted`,
`attempted` (checkpoint only), `accepted`, `failed`, and `stale`; their counts sum
to the planned inventory. Input mismatch marks recorded work stale. This read-only
command does not rebind or archive the session. Results outside the manifest do
not affect coverage. External call edges and evidence gaps come from the snapshot.

Checker, objective, aggregate candidate-validation, and parity verdicts remain
separate. New validation results also record each executed build/test/runtime/
differential check in order. Missing checks mean no recorded execution, not a
pass; older sessions retain their aggregate verdict without invented details.
Acceptance means the configured policy accepted the candidate. It is not proof
of equivalence, and selected-inventory coverage is not whole-program coverage.
