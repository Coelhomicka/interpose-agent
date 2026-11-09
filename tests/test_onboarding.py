"""`interpose scan`, `interpose import` and the provider catalog, across stacks.

Credential-shaped values are assembled at runtime so this file itself does not
trip secret scanners.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from interpose.cli.main import app
from interpose.container import create_container
from interpose.dashboard.app import DashboardAuth, DashboardContext, create_dashboard_app
from interpose.onboarding.importer import apply, plan
from interpose.onboarding.providers import identify
from interpose.onboarding.scanner import scan

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
OA = "sk-proj-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe"
AN = "sk-ant-api03-" + "QwErTyUiOpAsDfGhJkLzXcVbNm123456"
ST = "sk_live_" + "abcdEFGH1234ijklMNOP5678"
HF = "hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYz1234567"

STACKS = {
    ".env": f'OPENAI_API_KEY="{OA}"\nexport GITHUB_TOKEN={GH} # comment\nDEBUG=true\nAPI_URL=https://x.test\n',
    ".env.local": f"ANTHROPIC_API_KEY={AN}\n",
    ".envrc": f"export HF_TOKEN={HF}\n",
    ".dev.vars": f"STRIPE_SECRET_KEY={ST}\n",
    "appsettings.Development.json": '{\n  "Stripe": {\n    "SecretKey": "' + ST + '"\n  },\n'
                                    '  "ConnectionStrings": { "Db": "Server=prod.db;Password=Sup3rS3cret!" }\n}\n',
    "local.settings.json": '{ "Values": {\n    "OPENAI_API_KEY": "' + OA + '"\n  }\n}\n',
    ".mcp.json": '{"mcpServers": {"gh": {"env": {\n  "GITHUB_PERSONAL_ACCESS_TOKEN": "' + GH + '"\n}}}}\n',
    "application.properties": "spring.datasource.password=Pr0dPassw0rd!x\nserver.port=8080\n",
    "application.yml": f"openai:\n  api-key: {OA}\n",
    "docker-compose.yml": f"services:\n  app:\n    environment:\n      - ANTHROPIC_API_KEY={AN}\n"
                          "      - DATABASE_URL=postgres://admin:hunter2pw@db.internal:5432/app\n",
    "config/database.yml": "production:\n  password: R4ilsPr0dPw9\n",
    ".streamlit/secrets.toml": f'hf_token = "{HF}"\n',
    "terraform.tfvars": 'db_password = "Tf0rmS3cr3tPw"\nregion = "us-east-1"\n',
    ".npmrc": "//registry.npmjs.org/:_authToken=npm_" + "Ab1" * 12 + "\n",
    "wp-config.php": "define( 'DB_PASSWORD', 'Wp$ecretPw2024' );\n",
    "web.config": '<appSettings>\n  <add key="SendGridKey" value="SG.' + "a" * 22 + "." + "b" * 43
                  + '" />\n</appSettings>\n',
    "settings.py": f'SECRET_KEY = "dj-{"k" * 4}8f$2mZq#9xLw!pV"\nDEBUG = True\n',
    "src/client.ts": f'const key = "{GH}";\n',
    "node_modules/pkg/.env": f"OPENAI_API_KEY={OA}\n",
    ".env.example": "OPENAI_API_KEY=your-key-here\nGITHUB_TOKEN=\n",
}


@pytest.fixture()
def project(tmp_path):
    root = tmp_path / "shop"
    for name, text in STACKS.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _by_file(findings, root):
    result: dict[str, list] = {}
    for finding in findings:
        result.setdefault(finding.public(root)["file"], []).append(finding)
    return result


def test_scan_finds_credentials_in_every_stack(project):
    found = _by_file(scan(project), project)

    expected = {
        ".env": {"openai", "github"},
        ".env.local": {"anthropic"},
        ".envrc": {"huggingface"},
        ".dev.vars": {"stripe"},
        "appsettings.Development.json": {"stripe", "connection-string"},
        "local.settings.json": {"openai"},
        ".mcp.json": {"github"},
        "application.yml": {"openai"},
        "docker-compose.yml": {"anthropic", "connection-string"},
        ".streamlit/secrets.toml": {"huggingface"},
        ".npmrc": {"npm"},
        "web.config": {"sendgrid"},
        "src/client.ts": {"github"},
    }
    for name, providers in expected.items():
        assert name in found, name
        assert {f.provider.id for f in found[name] if f.provider} >= providers, name
    for name in ("application.properties", "config/database.yml", "terraform.tfvars", "wp-config.php",
                 "settings.py"):
        assert name in found, name  # generic credentials by key name


def test_scan_skips_placeholders_dependencies_and_examples(project):
    found = _by_file(scan(project), project)

    assert "node_modules/pkg/.env" not in found
    assert ".env.example" not in found
    keys = {f.key for f in found[".env"]}
    assert "DEBUG" not in keys and "API_URL" not in keys


def test_values_are_never_in_public_output(project):
    output = json.dumps([f.public(project) for f in scan(project)])

    for value in (GH, OA, AN, ST, HF):
        assert value not in output
        assert value[8:] not in output


def test_provider_name_wins_over_generic_shape():
    assert identify("DEEPSEEK_API_KEY", "sk-" + "a" * 32).id == "deepseek"
    assert identify("SOMETHING", "sk-" + "a" * 32).id == "openai"
    assert identify("X", AN).id == "anthropic"


def test_plan_moves_brokerable_and_reports_the_rest(project):
    items = plan(scan(project), namespace="shop")
    moving = {i.finding.public(project)["file"] for i in items if i.move}
    staying = {i.finding.public(project)["file"] for i in items if not i.move}

    assert ".env" in moving and ".streamlit/secrets.toml" in moving
    assert "src/client.ts" in staying  # source code is never rewritten
    assert "terraform.tfvars" in staying  # not brokerable without --include-unbrokered
    same_value = {i.reference for i in items if i.finding.value == GH}
    assert len(same_value) == 1  # one secret, however many files hold it


class _MemorySink:
    def __init__(self):
        self.stored: dict[str, tuple[str, str | None]] = {}

    def store(self, reference, value, provider):
        self.stored[reference] = (value, provider)


def test_apply_stores_values_and_rewrites_in_place(project):
    sink = _MemorySink()
    items = plan(scan(project), namespace="shop")

    apply(items, sink)

    env = (project / ".env").read_text(encoding="utf-8")
    assert OA not in env and GH not in env
    assert 'OPENAI_API_KEY="secret://openai/openai_api_key"' in env
    assert "export GITHUB_TOKEN=secret://github/github_token # comment" in env
    assert sink.stored["secret://openai/openai_api_key"] == (OA, "openai")
    settings = json.loads((project / "appsettings.Development.json").read_text(encoding="utf-8"))
    assert settings["Stripe"]["SecretKey"].startswith("secret://stripe/")
    assert "Password=Sup3rS3cret!" in settings["ConnectionStrings"]["Db"]  # left in place
    assert GH in (project / "src/client.ts").read_text(encoding="utf-8")


def test_apply_refuses_a_file_that_changed(project):
    items = plan(scan(project), namespace="shop")
    (project / ".env").write_text("OPENAI_API_KEY=other\n", encoding="utf-8")

    with pytest.raises(RuntimeError):
        apply(items, _MemorySink())


def test_cli_scan_exit_code_and_import_in_development_mode(project, runtime_config, monkeypatch):
    monkeypatch.chdir(project)
    runner = CliRunner()

    scanned = runner.invoke(app, ["scan"])
    assert scanned.exit_code == 1
    assert OA not in scanned.output

    dry = runner.invoke(app, ["import"])
    assert dry.exit_code == 0
    assert OA in (project / ".env").read_text(encoding="utf-8")

    applied = runner.invoke(app, ["import", "--apply", "--yes"])
    assert applied.exit_code == 0, applied.output
    assert OA not in (project / ".env").read_text(encoding="utf-8")
    container = create_container(runtime_config)
    assert container.secret_store.resolve("secret://openai/openai_api_key").value == OA
    policy = container.policy_repository.get_by_secret("secret://openai/openai_api_key")
    assert policy is not None and "api.openai.com" in policy.definition


def test_control_import_stores_and_suggests_only_catalog_policies(runtime_config, tmp_path):
    container = create_container(runtime_config)
    auth = DashboardAuth(default_token=False)
    dashboard = create_dashboard_app(
        container, DashboardContext(None, "http://127.0.0.1:9876", follow_project=False), auth,
        control_token="ctl",
    )
    client = TestClient(dashboard, base_url="http://127.0.0.1:18888")
    headers = {"Authorization": "Bearer ctl"}

    response = client.post("/control/import", headers=headers, json={"cwd": str(tmp_path), "items": [
        {"reference": "secret://openai/key", "value": OA, "provider": "openai"},
        {"reference": "secret://shop/db", "value": "Pr0dPassw0rd!x", "provider": None},
        {"reference": "secret://x/y", "value": "abcdefghij", "provider": "not-a-provider"},
    ]})

    assert response.status_code == 200
    assert response.json()["stored"] == 3 and response.json()["suggested"] == 1
    assert container.policy_repository.list() == []  # suggestions are not policies
    login = client.post("/control/login", headers=headers, json={"cwd": str(tmp_path)}).json()["path"]
    browser = TestClient(dashboard, base_url="http://localhost:18888")
    browser.get(login, follow_redirects=False)
    suggestions = browser.get("/api/state").json()["suggestions"]
    assert [s["hosts"] for s in suggestions] == [["api.openai.com"]]


def test_doctor_runs(project, monkeypatch):
    monkeypatch.chdir(project)

    result = CliRunner().invoke(app, ["doctor"])

    assert "Plaintext credentials" in result.output
