"""Tests for config loading."""
from __future__ import annotations

from pathlib import Path

import pytest

from re_agent.config.loader import load_config
from re_agent.config.schema import ReAgentConfig


def test_load_default_config() -> None:
    config = load_config(None)
    assert isinstance(config, ReAgentConfig)
    assert config.llm.provider == "claude"
    assert config.backend.type == "ghidra-bridge"
    assert config.backend.cli_path == "ghidra-bridge"
    assert config.orchestrator.max_review_rounds == 4
    assert config.orchestrator.objective_verifier_enabled is True


def test_load_from_yaml(sample_config_path: Path) -> None:
    config = load_config(sample_config_path)
    assert config.project_profile.stub_call_prefix == "plugin::Call"
    assert config.llm.model == "claude-sonnet-4-5-20250929"
    assert config.parity.call_count_warn_diff == 3


def test_role_specific_agent_configs(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """\
llm:
  provider: claude
agents:
  reverser:
    provider: claude-cli
    model: sonnet
    max_budget_usd: 1.5
  checker:
    provider: codex
    model: gpt-5.4
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.agents.reverser is not None
    assert config.agents.reverser.provider == "claude-cli"
    assert config.agents.reverser.max_budget_usd == 1.5
    assert config.agents.checker is not None
    assert config.agents.checker.provider == "codex"


def test_reverser_tools_default_to_no_access() -> None:
    config = load_config(None)
    assert config.reverser_tools.file_roots == []
    assert config.reverser_tools.max_file_calls == 20


def test_reverser_tools_section(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """\
reverser_tools:
  file_roots: ["source", "vendor/headers"]
  max_file_calls: 5
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.reverser_tools.file_roots == ["source", "vendor/headers"]
    assert config.reverser_tools.max_file_calls == 5


def test_reverser_tools_must_be_a_mapping(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("reverser_tools: [source]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="reverser_tools must be a mapping"):
        load_config(path)


def test_reverser_tools_rejects_a_bad_budget(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("reverser_tools:\n  max_file_calls: -1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="max_file_calls must be a nonnegative integer"):
        load_config(path)


def test_reverser_tools_rejects_a_blank_root(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text('reverser_tools:\n  file_roots: ["source", "  "]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="file_roots must be a list of nonempty path strings"):
        load_config(path)


def test_recovery_max_file_calls_defaults_to_shared_budget(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("recovery:\n  max_steps: 10\n", encoding="utf-8")
    assert load_config(path).recovery is not None
    assert load_config(path).recovery.max_file_calls is None  # type: ignore[union-attr]


def test_recovery_max_file_calls_can_be_set(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("recovery:\n  max_steps: 10\n  max_file_calls: 6\n", encoding="utf-8")
    config = load_config(path)
    assert config.recovery is not None
    assert config.recovery.max_file_calls == 6


def test_recovery_max_file_calls_rejects_a_bad_value(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("recovery:\n  max_file_calls: 0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="recovery.max_file_calls must be a positive integer"):
        load_config(path)


def test_cli_overrides() -> None:
    config = load_config(None, cli_overrides={"llm.provider": "openai", "orchestrator.max_review_rounds": "6"})
    assert config.llm.provider == "openai"
    assert config.orchestrator.max_review_rounds == 6


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RE_AGENT_LLM_PROVIDER", "openai")
    monkeypatch.setenv("RE_AGENT_LLM_MODEL", "gpt-4o")
    config = load_config(None)
    assert config.llm.provider == "openai"
    assert config.llm.model == "gpt-4o"
