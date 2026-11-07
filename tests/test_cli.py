from __future__ import annotations

import sys

from typer.testing import CliRunner

from interpose.cli.main import app, interpose_exec_app

runner = CliRunner()


def test_secret_add_accepts_shorthand_reference(runtime_config):
    result = runner.invoke(app, ["secret", "add", "SecretAPI/teste"], input="test-token-123\n")

    assert result.exit_code == 0, result.output
    assert "secret://secretapi/teste" in result.output

    list_result = runner.invoke(app, ["secret", "list"])
    assert list_result.exit_code == 0, list_result.output
    assert "secretapi/teste" in list_result.output


def test_secret_add_reports_invalid_reference_without_traceback(runtime_config):
    result = runner.invoke(app, ["secret", "add", "invalid"], input="test-token-123\n")

    assert result.exit_code == 1
    assert "Invalid secret reference:" in result.output
    assert "Traceback" not in result.output


def test_interpose_exec_accepts_command_and_arguments(runtime_config):
    result = runner.invoke(
        interpose_exec_app,
        [sys.executable, "-c", "print('interpose-exec-ok')"],
    )

    assert result.exit_code == 0, result.output
    assert result.output == "interpose-exec-ok\n"


def test_run_command_forwards_arbitrary_agent_arguments(runtime_config, tmp_path, monkeypatch):
    profile_path = tmp_path / "session.yaml"
    profile_path.write_text("version: 1\nenvironment: {}\n", encoding="utf-8")
    captured = {}

    class FakeLauncher:
        def run(self, command, **kwargs):
            captured["command"] = command
            captured["agent"] = kwargs["agent"]
            return 0

    monkeypatch.setattr("interpose.cli.main._session_launcher", lambda cwd: FakeLauncher())

    result = runner.invoke(
        app,
        ["run", "--profile", str(profile_path), "--agent", "cursor", "--", "agent", "--flag"],
    )

    assert result.exit_code == 0, result.output
    assert captured == {"command": ["agent", "--flag"], "agent": "cursor"}


def test_policy_add_and_list(runtime_config, tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "secret: apichave/teste\nallow:\n  hosts:\n    - localhost:8001\nmethods:\n  - GET\n",
        encoding="utf-8",
    )

    add_result = runner.invoke(app, ["policy", "add", str(policy_path)])
    list_result = runner.invoke(app, ["policy", "list"])

    assert add_result.exit_code == 0, add_result.output
    assert "secret://apichave/teste" in add_result.output
    assert list_result.exit_code == 0, list_result.output
    assert "secret://apichave/teste" in list_result.output
