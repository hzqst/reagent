"""Configuration schema dataclasses for re-agent."""

from __future__ import annotations

from dataclasses import dataclass, field

# Anthropic-oriented default model. Providers that defer to their own configured
# default (for example ``pi``) compare against it to tell "unset" from an override.
DEFAULT_LLM_MODEL = "claude-sonnet-4-5-20250929"


@dataclass
class ProjectProfile:
    """Project-specific patterns and paths."""

    hook_patterns: list[str] = field(
        default_factory=lambda: [
            r"RH_ScopedInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
            r"RH_ScopedVirtualInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
        ]
    )
    stub_patterns: list[str] = field(
        default_factory=lambda: [
            r"plugin::Call",
        ]
    )
    stub_markers: list[str] = field(
        default_factory=lambda: [
            "NOTSA_UNREACHABLE",
        ]
    )
    stub_call_prefix: str = "plugin::Call"
    class_macro: str = "RH_ScopedClass"
    source_root: str = "source/game_sa"
    compilation_database: str | None = None
    source_extensions: list[str] = field(
        default_factory=lambda: [
            ".cpp",
            ".h",
            ".hpp",
        ]
    )
    hooks_csv: str | None = "docs/hooks.csv"
    name: str = "gta-reversed"
    language_standard: str = "C++23"
    prompt_rules: list[str] = field(
        default_factory=lambda: [
            "Use real member names from the existing project and reference headers",
            "Never call virtual methods on this inside hook implementations",
            "Use matrix.TransformVector(vec) instead of deprecated Multiply3x3",
            "Verify struct offsets against project VALIDATE_OFFSET checks",
        ]
    )


@dataclass
class LLMConfig:
    """LLM provider configuration."""

    provider: str = "claude"
    model: str = DEFAULT_LLM_MODEL
    api_key: str | None = None
    base_url: str | None = None
    max_tokens: int = 4096
    temperature: float = 0.0
    timeout_s: int = 1800
    cli_path: str | None = None
    max_budget_usd: float | None = None
    effort: str | None = None
    # Project-level prompt for the CLI providers.  When set, the coding-agent
    # CLI's own project-prompt discovery (AGENTS.md / CLAUDE.md) is suppressed
    # and this file is injected as the runner's system-level prompt instead.
    runner_prompt_file: str | None = None
    # Claude Code CLI only: the value for ``claude --tools``.  Unset keeps the
    # provider tool-free, which is how re-agent has always run Claude; an empty
    # string also disables every tool, and a subset such as "Read,Grep,Glob"
    # allows just those.  MCP tools stay denied either way.
    claude_tools: str | None = None
    # Pi only: comma-separated tool allowlist passed to ``pi --tools``.  An
    # empty string disables every tool (``--no-tools``); leaving it unset keeps
    # Pi's own default.  A read-only subset such as ``"read,grep,ls"`` lets the
    # role consult upstream headers while keeping IDA access, shell and file
    # writes out of reach.
    pi_tools: str | None = None
    input_cost_per_million: float = 0.0
    output_cost_per_million: float = 0.0


@dataclass
class AgentModelsConfig:
    """Optional per-role model overrides.

    ``None`` keeps backwards compatibility by falling back to the top-level
    :class:`LLMConfig`.
    """

    reverser: LLMConfig | None = None
    checker: LLMConfig | None = None


@dataclass
class RecoveryConfig(LLMConfig):
    """Independent model and execution budget for backend-specific recovery."""

    max_steps: int = 40
    max_result_chars: int = 24000
    # Directories the recovery agent may read through the host-side read/grep/glob
    # tools. Empty (the default) leaves the recovery agent with no filesystem
    # access at all: it then sees only --evidence and the IDB, exactly as before.
    file_roots: list[str] = field(default_factory=list)
    # Budget for file-tool calls. ``None`` (the default) keeps the historical
    # behaviour: a file call spends a ``max_steps`` slot like any IDA call.  Set
    # an integer to give file calls their own budget so source lookup does not
    # crowd out IDA evidence -- this mirrors ``reverser_tools.max_file_calls``.
    max_file_calls: int | None = None


@dataclass
class ReverserToolsConfig:
    """Opt-in read-only filesystem tools for the reverser agent.

    Kept separate from ``agents.reverser`` on purpose: that role block is a
    complete LLM configuration, so adding tool knobs there would force anyone
    enabling source lookup to restate ``provider`` / ``model``.
    """

    # Directories the reverser may read through the host-side read/grep/glob
    # tools. Empty (the default) leaves the reverser with no filesystem access
    # at all, and the tools are neither offered in the prompt nor servable.
    # Relative entries resolve against ``validation.project_root``.
    file_roots: list[str] = field(default_factory=list)
    # Budget for successful file-tool calls, independent of
    # ``orchestrator.max_investigations`` so source lookup never crowds out
    # binary evidence.
    max_file_calls: int = 20


@dataclass
class BackendConfig:
    """Decompiler backend configuration."""

    type: str = "ghidra-bridge"
    export_dir: str | None = None
    address_map: str | None = None
    cli_path: str = "ghidra-bridge"
    url: str = "http://127.0.0.1:13337/mcp"
    timeout_s: int = 45
    database_path: str | None = None
    idalib_mcp_path: str = "idalib-mcp"
    startup_timeout_s: int = 120
    shutdown_timeout_s: int = 15


@dataclass
class ParityConfig:
    """Static parity verification settings."""

    enabled: bool = True
    call_count_warn_diff: int = 3
    inline_wrapper_autoskip: bool = False
    semantic_rules_file: str | None = None
    manual_checks_file: str | None = None
    cache_dir: str = ".cache/re-agent-parity"


@dataclass
class OrchestratorConfig:
    """Orchestrator loop settings."""

    max_review_rounds: int = 4
    max_llm_calls_per_function: int = 80
    cumulative_validation: bool = True
    max_functions_per_class: int = 10
    objective_verifier_enabled: bool = True
    objective_call_count_tolerance: int = 3
    objective_control_flow_tolerance: int = 2
    investigation_enabled: bool = True
    max_investigations: int = 8
    selection_strategy: str = "dependency-order"
    max_attempts_per_function: int = 3


@dataclass
class ValidationConfig:
    """Candidate overlay, build, test, and acceptance gate settings."""

    enabled: bool = True
    copy_project: bool = False
    project_root: str = "."
    build_commands: list[str | list[str]] = field(default_factory=list)
    test_commands: list[str | list[str]] = field(default_factory=list)
    runtime_commands: list[str | list[str]] = field(default_factory=list)
    differential_reference: list[str] = field(default_factory=list)
    differential_candidate: list[str] = field(default_factory=list)
    differential_cases_file: str | None = None
    require_build: bool = False
    require_tests: bool = False
    require_runtime: bool = False
    require_verified: bool = True
    trust_configured_commands: bool = False
    parity_fail_on_red: bool = True
    parity_fail_on_yellow: bool = False
    command_timeout_s: int = 900
    working_directory: str = "."
    keep_project_copy: bool = False


@dataclass
class OutputConfig:
    """Output and reporting settings."""

    report_dir: str = "reports/re-agent"
    log_dir: str = "reports/re-agent/logs"
    session_file: str = "re-agent-progress.json"
    format: str = "json"


@dataclass
class ReAgentConfig:
    """Top-level configuration for the re-agent system."""

    project_profile: ProjectProfile = field(default_factory=ProjectProfile)
    llm: LLMConfig = field(default_factory=LLMConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    parity: ParityConfig = field(default_factory=ParityConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    agents: AgentModelsConfig = field(default_factory=AgentModelsConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    recovery: RecoveryConfig | None = None
    reverser_tools: ReverserToolsConfig = field(default_factory=ReverserToolsConfig)

    @classmethod
    def create_default(cls) -> ReAgentConfig:
        """Create a configuration with all default values."""
        return cls(
            project_profile=ProjectProfile(),
            llm=LLMConfig(),
            agents=AgentModelsConfig(),
            backend=BackendConfig(),
            parity=ParityConfig(),
            orchestrator=OrchestratorConfig(),
            validation=ValidationConfig(),
            output=OutputConfig(),
            reverser_tools=ReverserToolsConfig(),
        )
