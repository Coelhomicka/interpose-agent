from __future__ import annotations

import sqlite3

import pytest
from cryptography.exceptions import InvalidTag

from interpose.container import create_container
from interpose.core.policies import PolicyDocument
from interpose.core.references import SecretReference
from interpose.core.scopes import GLOBAL_SCOPE, ScopeError, project_scope, validate_scope
from interpose.models import DestinationContext
from interpose.secrets.base import SecretNotFound
from interpose.secrets.encrypted_local import EncryptedLocalSecretStore

REF = "secret://openai/prod"


@pytest.fixture()
def project_container(runtime_config, tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    registry_container = create_container(runtime_config)
    project = registry_container.project_registry.register(root, "My App")
    return create_container(runtime_config, project_root=root), project


def test_project_value_shadows_global(project_container):
    container, project = project_container
    container.secret_store.store(REF, "global-value")
    container.secret_store.store(REF, "project-value", scope=project_scope(project.id))

    assert container.secret_store.resolve(REF).value == "project-value"


def test_global_value_is_the_fallback_inside_a_project(project_container):
    container, _ = project_container
    container.secret_store.store(REF, "global-value")

    assert container.secret_store.resolve(REF).value == "global-value"


def test_project_secret_is_invisible_outside_its_project(project_container, runtime_config, tmp_path):
    container, project = project_container
    container.secret_store.store(REF, "project-value", scope=project_scope(project.id))
    elsewhere = create_container(runtime_config, project_root=tmp_path)

    with pytest.raises(SecretNotFound):
        elsewhere.secret_store.resolve(REF)


def test_subfolder_resolves_to_enclosing_project(project_container, runtime_config):
    _, project = project_container
    nested = __import__("pathlib").Path(project.root) / "src" / "deep"
    nested.mkdir(parents=True)

    assert create_container(runtime_config, project_root=nested).project.id == project.id


def test_ciphertext_moved_between_scopes_fails_authentication(project_container, runtime_config):
    # Editing the database to relabel a project secret as global must not decrypt it.
    container, project = project_container
    container.secret_store.store(REF, "project-value", scope=project_scope(project.id))
    with sqlite3.connect(runtime_config.paths.database) as connection:
        connection.execute("UPDATE secrets SET scope = ?", (GLOBAL_SCOPE,))
    connection.close()

    with pytest.raises(InvalidTag):
        container.secret_store.backend.resolve(REF)


def test_project_policy_shadows_global_policy(project_container):
    container, project = project_container
    container.policy_repository.store(
        PolicyDocument.from_yaml("secret: openai/prod\nallow:\n  hosts:\n    - api.openai.com\n")
    )
    container.policy_repository.store(
        PolicyDocument.from_yaml("secret: openai/prod\nallow:\n  hosts:\n    - internal.example\n"),
        scope=project_scope(project.id),
    )
    reference = SecretReference.parse(REF)

    def allowed(host: str) -> bool:
        return container.policy_engine.evaluate(reference, DestinationContext(host=host, method="GET")).allowed

    assert not allowed("api.openai.com")
    assert allowed("internal.example")


def test_legacy_unscoped_vault_is_migrated(runtime_config):
    # Build the pre-scope schema by hand, then open it with the current store.
    seed = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    seed.store(REF, "legacy-value")
    with sqlite3.connect(runtime_config.paths.database) as connection:
        connection.executescript(
            """
            CREATE TABLE legacy AS SELECT id, reference, provider, namespace, secret_path,
                ciphertext, nonce, fingerprint, created_at, updated_at FROM secrets;
            DROP TABLE secrets;
            ALTER TABLE legacy RENAME TO secrets;
            CREATE TABLE legacy_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT, secret_reference TEXT NOT NULL UNIQUE,
                definition TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            INSERT INTO legacy_policies (secret_reference, definition, created_at, updated_at)
                VALUES ('secret://openai/prod', '{"secret": "openai/prod", "allow": {"hosts": ["api.openai.com"]}}',
                        '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
            DROP TABLE IF EXISTS policies;
            ALTER TABLE legacy_policies RENAME TO policies;
            """
        )
    connection.close()

    container = create_container(runtime_config)

    [metadata] = container.secret_store.list_metadata()
    assert metadata.scope == GLOBAL_SCOPE
    assert container.secret_store.resolve(REF).value == "legacy-value"
    assert container.policy_repository.list()[0].scope == GLOBAL_SCOPE


@pytest.mark.parametrize("scope", ["project:", "project:Bad Id", "team:x", ""])
def test_invalid_scopes_are_rejected(scope):
    with pytest.raises(ScopeError):
        validate_scope(scope)
