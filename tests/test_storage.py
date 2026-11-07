from __future__ import annotations

from pathlib import Path

from interpose.secrets.encrypted_local import EncryptedLocalSecretStore


def test_storage_does_not_persist_plaintext(runtime_config):
    store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    store.store("secret://github/prod", "plain-secret-123")

    raw_bytes = Path(runtime_config.paths.database).read_bytes()
    assert b"plain-secret-123" not in raw_bytes



def test_fingerprint_is_keyed_not_bare_sha256(runtime_config):
    import hashlib

    store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    metadata = store.store("secret://db/prod", "hunter2")

    assert metadata.fingerprint.startswith("hmac-sha256:")
    assert hashlib.sha256(b"hunter2").hexdigest() not in metadata.fingerprint


def test_legacy_sha256_fingerprints_are_migrated(runtime_config):
    import hashlib
    import sqlite3

    store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    store.store("secret://db/prod", "hunter2")
    with sqlite3.connect(runtime_config.paths.database) as connection:
        connection.execute("UPDATE secrets SET fingerprint = ?", (hashlib.sha256(b"hunter2").hexdigest(),))
    connection.close()

    reopened = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)

    [metadata] = reopened.list_metadata()
    assert metadata.fingerprint == reopened.fingerprint("hunter2")


def test_generated_master_key_is_private(tmp_path, monkeypatch):
    import os
    import subprocess
    import sys

    from interpose.config import load_master_key

    monkeypatch.delenv("INTERPOSE_MASTER_KEY", raising=False)
    key_file = tmp_path / "home" / "master.key"

    load_master_key(key_file)

    if sys.platform == "win32":
        acl = subprocess.run(["icacls", str(key_file)], capture_output=True, text=True, check=True).stdout
        entries = [line for line in acl.splitlines()[:-2] if line.strip()]
        assert len(entries) == 1, acl
        assert "(I)" not in acl
    else:
        assert (os.stat(key_file).st_mode & 0o777) == 0o600


def test_surrounding_whitespace_is_trimmed_on_store(runtime_config):
    store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    store.store("secret://demo/api", " sk-demo-SEGREDO-123\r\n")

    assert store.resolve("secret://demo/api").value == "sk-demo-SEGREDO-123"


def test_whitespace_only_value_is_rejected(runtime_config):
    import pytest

    from interpose.secrets.base import SecretValueError

    store = EncryptedLocalSecretStore(runtime_config.paths.database, runtime_config.master_key)
    with pytest.raises(SecretValueError):
        store.store("secret://demo/api", "   ")
