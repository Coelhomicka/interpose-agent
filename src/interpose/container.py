from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import RuntimeConfig
from .core.audit import AuditLogger
from .core.policies import PolicyEngine, SQLitePolicyRepository
from .core.redaction import SecretRedactionEngine
from .core.scopes import ScopeContext
from .executor.trusted_executor import TrustedExecutor
from .projects import Project, ProjectRegistry
from .secrets.encrypted_local import EncryptedLocalSecretStore, ScopedSecretStore
from .session.launcher import SessionLauncher


@dataclass(frozen=True)
class RuntimeContainer:
    config: RuntimeConfig
    secret_store: ScopedSecretStore
    policy_repository: SQLitePolicyRepository
    policy_engine: PolicyEngine
    audit_logger: AuditLogger
    redaction_engine: SecretRedactionEngine
    executor: TrustedExecutor
    session_launcher: SessionLauncher
    scope_context: ScopeContext
    project_registry: ProjectRegistry

    @property
    def project(self) -> Project | None:
        if self.scope_context.project_id is None:
            return None
        return self.project_registry.get(self.scope_context.project_id)


def create_container(
    config: RuntimeConfig | None = None,
    *,
    project_root: Path | str | None = None,
) -> RuntimeContainer:
    """Wire every component.

    With ``project_root``, the registered project containing that folder (if any)
    becomes active: secrets and policies resolve in its scope first, then global.
    """
    runtime_config = config or RuntimeConfig.from_env()
    project_registry = ProjectRegistry(runtime_config.paths.database)
    project = project_registry.find_for_path(project_root) if project_root is not None else None
    scope_context = ScopeContext(project_id=project.id if project else None)

    vault = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    secret_store = ScopedSecretStore(vault, scope_context)
    policy_repository = SQLitePolicyRepository(runtime_config.paths.database)
    policy_engine = PolicyEngine(policy_repository, scope_context)
    audit_logger = AuditLogger(runtime_config.paths.audit_database)
    redaction_engine = SecretRedactionEngine()
    executor = TrustedExecutor(
        secret_store=secret_store,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        redaction_engine=redaction_engine,
        agent_name=runtime_config.agent_name,
    )
    session_launcher = SessionLauncher(
        secret_store=secret_store,
        audit_logger=audit_logger,
        runtime_home=runtime_config.paths.home,
    )
    return RuntimeContainer(
        config=runtime_config,
        secret_store=secret_store,
        policy_repository=policy_repository,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        redaction_engine=redaction_engine,
        executor=executor,
        session_launcher=session_launcher,
        scope_context=scope_context,
        project_registry=project_registry,
    )
