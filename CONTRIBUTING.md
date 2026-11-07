# Contributing to Interpose

Thanks for considering a contribution. This project mediates real credentials, so the bar for
changes to the trusted zone is deliberately high — but there is plenty of work that does not touch
it at all.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

Read [`docs/en/THREAT_MODEL.md`](docs/en/THREAT_MODEL.md) and [`docs/en/ARCHITECTURE.md`](docs/en/ARCHITECTURE.md).
Most review friction comes from changes that quietly move the trust boundary. Knowing where it sits
saves a round trip.

**Found a vulnerability?** Do not open an issue — follow [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone https://github.com/Coelhomicka/interpose-agent.git
cd interpose

python -m venv .venv
source .venv/bin/activate       # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Verify:

```bash
pytest
ruff check .
```

Both must be clean before you open a pull request. CI runs them on Linux, macOS, and Windows
against Python 3.12 and 3.13.

Tests never touch your real runtime home: the `runtime_config` fixture points
`INTERPOSE_HOME` at a temporary directory and supplies a throwaway master key. If you write a
test that needs runtime state, use that fixture rather than constructing paths yourself.

Windows AppContainer tests are skipped on other platforms and some need an elevated shell. A skip is
expected, not a failure.

## Where help is most valuable

Ranked by how much each one unblocks:

1. **The service on Linux and macOS, and user presence on Windows.** On Windows the broker already
   runs as `NT SERVICE\Interpose` with the vault behind ACLs (`src/interpose/service/`). Linux
   (systemd `DynamicUser=`) and macOS (a launchd daemon with its own user) need the same install and
   service-manager glue around the unchanged `service/host.py`. On every platform, opening a
   dashboard session should require user presence (Windows Hello, Touch ID, polkit), because the
   control token is readable by the user.
2. **Linux and macOS isolation backends.** The `IsolationBackend` protocol in
   `src/interpose/session/isolation/base.py` is the extension point; the Windows AppContainer
   backend is the reference implementation. Linux wants namespaces plus nftables egress rules;
   macOS wants sandbox profiles and a Network Extension.
3. **Egress enforcement.** Policy is meaningless while the agent can open its own socket. With the
   vault protected, this is now the largest remaining gap.
4. **External secret stores.** `SecretStore` in `src/interpose/secrets/base.py` is a small
   protocol. Vault, Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, Keychain, and Secret
   Service all fit behind it.
5. **SDK compatibility.** Clients that validate token format locally reject `secret://...` before a
   request is ever made. Documenting which SDKs break, and how, is genuinely useful even without code.
6. **Protocol brokers.** Database authentication, SigV4 signing, SSH, and mTLS each need an
   operation broker so that key material never leaves the trusted zone.

See [`docs/en/ROADMAP.md`](docs/en/ROADMAP.md) for the full picture.

## Pull requests

- **One concern per pull request.** A change to the policy engine and a docs cleanup are two PRs.
- **Open an issue first for anything that changes the trust boundary** — resolution ordering, what
  the child environment receives, what an endpoint returns, how policy is sourced. It is much
  cheaper to disagree about the design before the code exists.
- **Add a test for every behavior change.** For security-relevant changes, add the test that fails
  without your fix.
- **Update the threat model** when your change moves a row in it. A new capability that is not
  reflected there is an undocumented promise.
- **Update `CHANGELOG.md`** under `## [Unreleased]`.

### Rules that will not be relaxed

A pull request doing any of these will be declined regardless of its quality:

- adding an endpoint, CLI command, or log line that returns or prints a stored secret value;
- resolving a secret before its policy is evaluated;
- allowing a session profile to grant a policy;
- accepting HTTPS `CONNECT` by tunneling it — see [SECURITY.md](SECURITY.md) for why;
- passing `INTERPOSE_MASTER_KEY` or `INTERPOSE_HOME` to a managed child;
- widening the default environment allowlist without a stated reason per variable.

If you have a design that achieves one of these goals while preserving the guarantee, open an issue.
The rules exist to protect the guarantee, not the implementation.

## Code style

`ruff` is the authority — configuration lives in `pyproject.toml`. Beyond it:

- `from __future__ import annotations` at the top of every module;
- explicit type hints on public functions;
- errors are domain exception types (`PolicyError`, `IsolationError`, `SecretNotFound`), not bare
  `ValueError`;
- comments explain *why*, not *what*. The existing comments on the sqlite connection handling and
  the `CONNECT` rejection are the intended register;
- **never log, print, or format a resolved secret value**, including in a debugging aid you intend
  to remove before merging.

## Commit messages

Imperative present tense, one logical change per commit:

```
Add nftables egress backend for Linux isolation

The Windows AppContainer backend enforces egress through firewall rules
scoped to the container SID. Linux needs the equivalent before the
isolation guarantee holds outside Windows.
```

Conventional Commits prefixes are welcome but not required.

## Licensing

Contributions are licensed under [Apache License 2.0](LICENSE), matching the project. There is no
CLA; opening a pull request is taken as agreement.
