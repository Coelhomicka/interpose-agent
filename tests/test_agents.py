from __future__ import annotations

from typer.testing import CliRunner

from interpose import agents
from interpose.cli.main import app
from interpose.session.launcher import build_session_environment
from interpose.session.profile import SessionProfile

runner = CliRunner()


def test_project_install_writes_every_agent_format(tmp_path):
    for target in agents.project_targets(tmp_path):
        target.install()

    agents_md = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert agents.BEGIN in agents_md and "$INTERPOSE_PROXY" in agents_md
    assert agents.BEGIN in (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert agents.BEGIN in (tmp_path / "GEMINI.md").read_text(encoding="utf-8")
    rule = (tmp_path / ".cursor" / "rules" / "interpose.mdc").read_text(encoding="utf-8")
    assert rule.startswith("---\n") and "alwaysApply: true" in rule


def test_install_keeps_existing_content_and_is_idempotent(tmp_path):
    existing = "# My project\n\nUse tabs.\n"
    (tmp_path / "AGENTS.md").write_text(existing, encoding="utf-8")
    target = agents.project_targets(tmp_path)[0]

    target.install()
    once = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    target.install()
    twice = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")

    assert once == twice
    assert once.startswith(existing.rstrip("\n"))
    assert once.count(agents.BEGIN) == 1


def test_remove_restores_the_users_file(tmp_path):
    existing = "# My project\n\nUse tabs.\n"
    (tmp_path / "AGENTS.md").write_text(existing, encoding="utf-8")
    targets = agents.project_targets(tmp_path)
    for target in targets:
        target.install()

    for target in targets:
        target.remove()

    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == existing
    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / ".cursor" / "rules" / "interpose.mdc").exists()


def test_global_targets_only_for_installed_tools(tmp_path):
    (tmp_path / ".claude").mkdir()

    targets = agents.global_targets(tmp_path)

    assert [t.path for t in targets] == [tmp_path / ".claude" / "skills" / "interpose" / "SKILL.md"]
    targets[0].install()
    skill = targets[0].path.read_text(encoding="utf-8")
    assert skill.startswith("---\nname: interpose\ndescription: ")


def test_print_outputs_the_instructions():
    result = runner.invoke(app, ["agents", "print"])

    assert result.exit_code == 0
    assert "INTERPOSE_PROXY" in result.output
    assert "Never ask the user to paste a real key" in result.output


def test_agent_environment_exposes_the_broker_url():
    profile = SessionProfile.from_yaml("version: 1\nenvironment:\n  API_KEY: secret://demo/api\n")

    environment = build_session_environment(
        profile, agent="a", session="s", source={}, proxy_base="http://127.0.0.1:9876/p/demo/proxy/"
    )

    assert environment["INTERPOSE_PROXY"] == "http://127.0.0.1:9876/p/demo/proxy"
    assert environment["API_KEY"] == "secret://demo/api"


def test_run_refuses_an_elevated_shell(tmp_path, monkeypatch):
    profile = tmp_path / "session.yaml"
    profile.write_text("version: 1\nenvironment: {}\n", encoding="utf-8")
    monkeypatch.setattr("interpose.core.elevation.is_elevated", lambda: True)
    monkeypatch.setattr("interpose.cli.main._session_launcher",
                        lambda cwd: (_ for _ in ()).throw(AssertionError("agent started")))

    result = runner.invoke(app, ["run", "--profile", str(profile), "--", "agent"])

    assert result.exit_code == 1
    assert "administrator" in result.output
