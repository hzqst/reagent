"""LLM provider factory registry."""

from __future__ import annotations

from pathlib import Path

from re_agent.config.schema import DEFAULT_LLM_MODEL, LLMConfig
from re_agent.llm.protocol import LLMProvider

# Providers that shell out to a coding-agent CLI and therefore read
# ``runner_prompt_file``.
_CLI_PROVIDERS = frozenset({"claude-cli", "codex", "pi"})


def create_provider(config: LLMConfig) -> LLMProvider:
    """Instantiate an LLM provider from a configuration object.

    Args:
        config: The LLM configuration specifying provider type, model,
            API key, and other parameters.

    Returns:
        An object satisfying the :class:`LLMProvider` protocol.

    Raises:
        ValueError: If ``config.provider`` is not a recognised provider name,
            or if a CLI provider was given a ``runner_prompt_file`` that does
            not exist.  The existence check lives here rather than in the
            config loader because commands that never build a provider (for
            example ``annotate``, which only talks to the IDA backend) must not
            be blocked by this key.
    """
    if (
        config.provider in _CLI_PROVIDERS
        and config.runner_prompt_file is not None
        and not Path(config.runner_prompt_file).is_file()
    ):
        raise ValueError(f"runner_prompt_file not found: {config.runner_prompt_file}")

    if config.provider == "claude":
        from re_agent.llm.claude import ClaudeProvider

        return ClaudeProvider(
            api_key=config.api_key,
            model=config.model,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            timeout_s=config.timeout_s,
        )

    if config.provider == "claude-cli":
        from re_agent.llm.claude_cli import ClaudeCLIProvider

        return ClaudeCLIProvider(
            model=config.model or "sonnet",
            timeout_s=config.timeout_s,
            claude_bin=config.cli_path or "claude",
            max_budget_usd=config.max_budget_usd,
            effort=config.effort,
            runner_prompt_file=config.runner_prompt_file,
            tools=config.claude_tools,
        )

    if config.provider in ("openai", "openai-compat"):
        from re_agent.llm.openai_compat import OpenAIProvider

        return OpenAIProvider(
            api_key=config.api_key,
            model=config.model,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            timeout_s=config.timeout_s,
            base_url=config.base_url,
        )

    if config.provider == "codex":
        from re_agent.llm.codex_cli import CodexCLIProvider

        return CodexCLIProvider(
            model=config.model or "gpt-5.4",
            codex_bin=config.cli_path or "codex",
            timeout_s=config.timeout_s,
            runner_prompt_file=config.runner_prompt_file,
        )

    if config.provider == "pi":
        from re_agent.llm.pi_cli import PiCLIProvider

        # An unchanged default model means "unset": let Pi use its configured default.
        model = "" if config.model == DEFAULT_LLM_MODEL else config.model
        return PiCLIProvider(
            model=model,
            pi_bin=config.cli_path or "pi",
            timeout_s=config.timeout_s,
            effort=config.effort,
            runner_prompt_file=config.runner_prompt_file,
            tools=config.pi_tools,
        )

    raise ValueError(
        f"Unknown LLM provider: {config.provider!r}. "
        f"Supported providers: 'claude', 'claude-cli', 'openai', "
        f"'openai-compat', 'codex', 'pi'."
    )
