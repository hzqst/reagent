"""Independent recovery command routing, selection and exit behavior."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from re_agent.cli.main import main
from re_agent.config.schema import BackendConfig, ReAgentConfig, RecoveryConfig


@pytest.mark.parametrize("status,code", [("planned", 0), ("verified", 0), ("incomplete", 1), ("failed", 1)])
@pytest.mark.parametrize("backend", ["ida-mcp", "ida"])
def test_recovery_uses_own_model_and_canonical_targets(tmp_path: Path, status: str, code: int, backend: str) -> None:
    config = ReAgentConfig(backend=BackendConfig(type=backend), recovery=RecoveryConfig(provider="pi", model="test"))
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()) as factory, \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": status}) as run:
        result = main(["recover-types", "--address", "00401000", "--address", "0x401000",
                       "--output", str(tmp_path / "report.json")])
    assert result == code
    factory.assert_called_once_with(config.recovery)
    assert run.call_args.args[2] == ["0x401000"]
    assert run.call_args.kwargs["write"] is False


def test_recovery_rejects_save_without_write() -> None:
    assert main(["recover-types", "--address", "0x401000", "--save"]) == 1


@pytest.mark.parametrize("backend,recovery", [("stub", RecoveryConfig()), ("ida-mcp", None)])
def test_unsupported_recovery_never_starts_model(backend: str, recovery: RecoveryConfig | None) -> None:
    config = ReAgentConfig(backend=BackendConfig(type=backend), recovery=recovery)
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), patch(f"{module}.create_recovery_provider") as factory:
        assert main(["recover-types", "--address", "0x401000"]) == 1
    factory.assert_not_called()
