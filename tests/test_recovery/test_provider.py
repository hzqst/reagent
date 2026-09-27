"""The model must not bypass the recovery MCP gateway via native CLI tools."""
from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from re_agent.config.schema import RecoveryConfig
from re_agent.recovery.provider import _RecoveryCodexProvider, create_recovery_provider


@pytest.mark.parametrize("provider", ["pi", "claude-cli"])
def test_native_cli_tools_are_disabled(provider: str) -> None:
    with patch("re_agent.recovery.provider.create_provider") as factory:
        create_recovery_provider(RecoveryConfig(provider=provider, claude_tools="Bash", pi_tools="bash"))
        config = factory.call_args.args[0]
        assert config.claude_tools == ""
        assert config.pi_tools == ""


def test_codex_isolation_applies_on_resume() -> None:
    process = subprocess.CompletedProcess([], 0, '[{"name":"ida-pro-mcp"},{"name":"other"}]', '')
    with patch("re_agent.recovery.provider.subprocess.run", return_value=process):
        provider = _RecoveryCodexProvider(RecoveryConfig(provider="codex", model="test"))
    for args in (provider._exec_args(None), provider._resume_args("thread", None)):
        assert 'mcp_servers.ida-pro-mcp.enabled=false' in args
        assert 'mcp_servers.other.enabled=false' in args
        assert 'features.shell_tool=false' in args


def test_codex_discovery_failure_is_closed() -> None:
    with patch("re_agent.recovery.provider.subprocess.run", side_effect=FileNotFoundError), \
         pytest.raises(RuntimeError, match="isolate"):
        create_recovery_provider(RecoveryConfig(provider="codex"))


def test_codex_ambiguous_override_name_is_rejected() -> None:
    process = subprocess.CompletedProcess([], 0, '[{"name":"nested.name"}]', '')
    with patch("re_agent.recovery.provider.subprocess.run", return_value=process), \
         pytest.raises(RuntimeError, match="Cannot isolate"):
        _RecoveryCodexProvider(RecoveryConfig(provider="codex"))
