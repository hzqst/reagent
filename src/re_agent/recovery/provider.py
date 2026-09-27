"""Build recovery models without granting a second, unjournaled tool channel."""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import replace
from typing import Any

from re_agent.config.schema import LLMConfig, RecoveryConfig
from re_agent.llm.codex_cli import CodexCLIProvider
from re_agent.llm.protocol import LLMProvider
from re_agent.llm.registry import create_provider
from re_agent.recovery.runner import PROMPT


class _RecoveryCodexProvider(CodexCLIProvider):
    """Disable native MCP and shell on both opening and resumed Codex turns."""

    def __init__(self, config: LLMConfig) -> None:
        super().__init__(model=config.model, timeout_s=config.timeout_s, codex_bin=config.cli_path or "codex",
                         runner_prompt_file=str(PROMPT))
        try:
            proc = subprocess.run([self._codex_bin, "mcp", "list", "--json"], capture_output=True,
                                  text=True, timeout=config.timeout_s, check=False)
            if proc.returncode != 0:
                raise RuntimeError("Cannot discover Codex MCP connections to isolate recovery")
            servers: Any = json.loads(proc.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            raise RuntimeError("Cannot isolate Codex recovery tools; check codex mcp list --json") from exc
        if not isinstance(servers, list) or not all(isinstance(s, dict) and isinstance(s.get("name"), str)
                                                  for s in servers):
            raise RuntimeError("Codex returned an invalid MCP catalog; refusing unisolated recovery")
        self._disabled_servers = [s["name"] for s in servers]
        if any(re.fullmatch(r"[A-Za-z0-9_-]+", name) is None for name in self._disabled_servers):
            raise RuntimeError("Cannot isolate a Codex MCP name containing dots or special characters")

    def _prompt_isolation_args(self) -> list[str]:
        args = super()._prompt_isolation_args()
        for name in self._disabled_servers:
            # Codex splits override keys on dots; quoted TOML components are
            # treated as literal quotes, not unquoted table names.
            args.extend(["-c", f"mcp_servers.{name}.enabled=false"])
        for setting in ("features.shell_tool=false", "features.unified_exec=false", "features.apps=false",
                        "features.multi_agent=false", "features.skill_mcp_dependency_install=false",
                        'web_search="disabled"'):
            args.extend(["-c", setting])
        return args


def create_recovery_provider(config: RecoveryConfig) -> LLMProvider:
    """Reuse provider transport, but leave all tool dispatch to the recovery loop."""
    if config.provider == "codex":
        return _RecoveryCodexProvider(config)
    # Both allowlists cover native and extension tools. CLI context discovery
    # is suppressed by the built-in runner prompt; additional user context is
    # read by cmd_recover_types and passed as evidence, not as tool authority.
    isolated = replace(config, claude_tools="", pi_tools="", runner_prompt_file=str(PROMPT))
    return create_provider(isolated)
