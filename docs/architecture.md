# Architecture

re-agent is structured as a layered pipeline. The CLI and configuration feed an
orchestrator that drives a bounded evidence loop per function; candidate code is
then validated by a conservative objective verifier, configured build/test gates,
and the parity engine before a result is accepted.

```text
CLI -> Config -> Orchestrator -> Evidence Loop -> LLM Providers
                      |              |
                      v              v
              Function Picker    RE Backend Protocol
                      |
                      v
   Candidate Overlay -> Objective Verify -> Build/Test/Differential -> Parity -> Repair feedback
```

Every round produces a typed result and checkpoint. Candidate validation runs as a
callback inside the repair loop rather than as a one-shot step after LLM
approval. Providers share a call budget and emit one audit record per call. The
class runner uses a disposable cumulative project; promotion only occurs after
acceptance.

## Layers and modules

| Layer | Modules | Responsibility |
|---|---|---|
| CLI | `cli/main.py` plus one `cmd_*.py` per subcommand | argparse dispatch. Subcommands: `doctor`, `benchmark`, `plan`, `evidence`, `init`, `reverse`, `parity`, `status`, `estimate`, `recover-types`, `annotate`. Failures surface as `ValueError`/`RuntimeError`/`OSError`, printed as `Error: ...` with exit 1. |
| Config | `config/schema.py` (source of truth), `config/loader.py`, `config/defaults.py` | Dataclass schema, YAML/env loading, and profile templates. Precedence: CLI overrides > supported environment variables > `re-agent.yaml` > defaults. Profiles: `generic-cpp`, `windows-x64`, `gta-reversed`, `openrct2`. |
| Orchestrator | `orchestrator/single.py`, `class_runner.py`, `batch_runner.py` | Run drivers: one function (`reverse_single`), a class batch (`reverse_class`), or a manifest group (`reverse_manifest`, which restricts enumeration through a `_ManifestBackend` and delegates to the class runner). |
| Agents | `agents/loop.py`, `reverser.py`, `checker.py`, `source_context.py`, `agents/prompts/*.md` | Bounded reverser -> checker -> fix loop with investigation actions, prompt templates rendered via `utils.templates`. |
| LLM | `llm/registry.py` (`create_provider`) plus one module per provider | `claude` (API), `claude-cli`, `openai` / `openai-compat`, `codex`, `pi`. `claude-cli`, `codex`, and `pi` shell out to a coding-agent CLI and therefore read `runner_prompt_file`. |
| Backend | `backend/protocol.py`, `registry.py` (`create_backend`), `stages.py` | `REBackend` protocol with `BackendCapabilities`, plus an optional `EvidenceBackend` enhanced API. Backend types: `ghidra-bridge` (default), `ghidra-json`, `ida-mcp`, `idalib-mcp`, `stub`. `stages.py` scopes an owned IDA worker to a task phase. |
| Parity | `parity/engine.py`, `signals.py`, `rules.py`, `scoring.py`, `cache.py`, `clang_index.py`, `source_indexer.py` | Fixed 11-signal heuristic engine plus configured semantic rules and scoring (GREEN / YELLOW / RED). |
| Verification | `verification/candidate.py`, `objective.py`, `differential.py` | Safe candidate overlay and configurable build/test/runtime gates; the conservative structural verifier (`verify_candidate`); a reference-vs-candidate JSON differential harness. |
| Recovery | `recovery/runner.py`, `ida.py`, `files.py`, `provider.py` | Interactive, IDA-specific type-recovery agent, independent of `SymbolProposal`; read-only preview by default, opt-in writes with backup and independent readback. |
| Core | `core/models.py`, `session.py`, `knowledge_graph.py`, `function_picker.py`, `symbols.py`, `target_plan.py`, `identity.py` | Domain models, session/progress persistence, the persistent evidence graph, function selection, symbol proposals, and deterministic `TargetPlan` manifests. |
| Reports | `reports/formatter.py`, `coverage.py`, `evidence.py`, `tracker.py` | JSON/markdown output, coverage, manifest evidence export, and progress tracking. |
| Utils | `utils/` | Address, evidence, process, storage (`atomic_json` + `file_lock`), template, and text helpers. |

## Key behaviours

- **Manifests.** `plan` builds a bounded `TargetPlan` (seeds, depth, function
  limit, call edges, explicit evidence gaps) without model calls. `reverse
  --manifest` executes it through the class runner; `evidence --manifest` exports
  the stored snapshot only. Planning and export never call a model.
- **Backend capabilities.** `BackendCapabilities` flags cover decompile, asm,
  structs, xrefs, search, enums, context, vtables, globals, strings, normalized
  P-code, CFG, and function types. Unsupported operations degrade gracefully
  rather than failing the run.
- **Acceptance.** A successful reversal requires four independent conditions: the
  checker returns `PASS`; the objective verifier finds no strong structural
  mismatch; candidate validation satisfies the configured acceptance policy; and
  parity is not blocked by the RED/YELLOW policy. This is conservative
  verification, not a proof of semantic equivalence.
- **Ownership.** The pipeline never patches the target source tree and never
  commits or pushes. `ghidra-json` consumes typed export records directly; the
  `idalib-mcp` backend starts and closes its own headless IDA worker per task.

Differential verification is a project-owned harness interface: it compares
observable JSON values produced by a reference and a candidate command, rather
than inferring arbitrary ABI adapters. The bundled GTA example demonstrates this
over a few original x86 functions under emulation.
