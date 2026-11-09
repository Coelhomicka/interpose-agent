# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is `0.x`,
minor releases may contain breaking changes.

Entries that change a security guarantee are marked **[security]**.

## [Unreleased]

### Security

Fixes from the November 2026 adversarial audit; see `docs/en/SECURITY_AUDIT.md`.

- **[security]** Critical: in Host-header and absolute-form proxy mode, a `Host` value
  could match a wildcard allow pattern as text while the HTTP client connected to a different
  host, which sent the injected credential to that host. Destinations are now parsed strictly,
  and the URL the client dials is re-parsed and must equal the URL the policy approved.
- **[security]** Allow-host patterns are label-aware: exact `host[:port]`, a leading
  `*.example.com` (subdomains only), or `*`. Glob forms like `api.*` are refused, and a stored
  policy using one now denies.
- **[security]** Paths with dot segments, or with an encoded `?` or `#`, are refused instead of
  being normalized after the policy check.
- **[security]** Redaction also covers JSON-escaped, hex, URL-safe base64 and embedded base64
  (as in Basic auth), case-insensitively. The broker offers only `gzip, deflate` upstream and
  refuses any other response encoding, so it never scans a compressed body.
- **[security]** Non-ASCII hostnames are refused; send IDNA `xn--` labels.
- The threat model now states that project scopes are not an isolation boundary against
  same-user code.
- Regression and property-based (Hypothesis) tests for every finding.
- **[security]** Windows Hello approval for policy changes that widen where a secret can go
  (new policy, host, method, path, slot or scheme; removed deny or path limit; `allow_exec`).
  The dashboard asks for a WebAuthn assertion bound to the exact change. `interpose setup`
  enrolls the key from the private runtime into the vault folder; `interpose service enroll`
  replaces it. A same-user process holding the control token can no longer widen policy.
  The dashboard now opens on `http://localhost:<port>`, as WebAuthn requires.
- **[security]** Elevated service tasks other than install run from the private runtime in
  `%ProgramFiles%`, not from the user's own install, which the user's processes can modify.

### Added

- `interpose up`: starts the broker and a local configuration dashboard together and opens the
  dashboard with a single-use login link, in the style of the .NET Aspire dashboard. The dashboard
  manages secrets (write-only), policies (form with live YAML preview), project registration, and
  shows live activity and ready-to-copy `.env` and `session.yaml` snippets.
- Project and global scopes for secrets and policies. Inside a registered project, a reference
  resolves to the project's value first and the global value otherwise; policies follow the same
  chain. Existing vaults migrate in place, with every record becoming global.
- `interpose proxy` and `interpose run` use the registered project containing the current folder.
- **[security]** `interpose setup` (Windows): installs the broker as the `Interpose` service under
  the virtual account `NT SERVICE\Interpose`, with a private runtime in `%ProgramFiles%` and the
  vault in an ACL-protected `%ProgramData%` folder, and moves the development vault there. The
  service-control glue is plain ctypes, so no native dependency is added. `interpose service
  status|start|stop|uninstall` manage it; `interpose up` and `interpose run` use it when installed.
- Broker URLs of the form `/p/<project>/proxy/<host>/...` select a project's scope per request, so
  one broker serves every project. `${INTERPOSE_PROXY}` in a profile's `public_environment` expands
  to the right base URL for the current folder, in development and with the service.
- Dashboard login links are bound to the folder they were issued for, so one dashboard can manage
  several projects at once.
- `interpose agents install|remove|print`: one set of instructions rendered for every agent —
  `AGENTS.md` (Codex, Cursor, Devin, Antigravity, Copilot and others), `CLAUDE.md` and a Claude Code
  skill, `GEMINI.md`, and a Cursor rule — as marked blocks that never touch the rest of a file.
  `interpose setup` installs the user-level ones for the agents it finds.
- `interpose run` sets `INTERPOSE_PROXY` in the agent's environment.
- The service no longer starts with Windows. `interpose up` starts it and stops it on Ctrl+C, like
  `aspire run`; `setup` grants the installing user the right to start and stop that one service, so
  neither needs elevation. `interpose service start|stop` work unelevated too.
- **[security]** `interpose run` refuses to start an agent from an administrator shell unless
  `--allow-elevated` is given, and warns when the vault is in development mode.
- **[security]** `interpose-exec` passes secret-bearing arguments to curl on standard input instead
  of argv, runs only `curl` when a reference is present, and no longer returns the resolved command
  in its result.

### Security

- **[security]** Policies now control *where* a reference may appear. The broker records the header,
  query field, form field, or body each reference sits in and denies any location outside the
  policy's new `inject` slots before resolution. The default, when `inject` is omitted, is the
  `Authorization` and `X-API-Key` headers. Previously a reference in a request body to an allowed
  host was substituted, letting the allowed API itself publish or echo the secret.
  **Breaking:** policies for APIs that take the credential in a query or form field must declare it,
  e.g. `inject: [{query: key}]`.
- **[security]** Policies accept an optional `paths` allow-list matched against the upstream path.
- **[security]** The broker and admin API reject requests carrying an `Origin` header or a
  cross-site `Sec-Fetch-Site`, and requests whose `Host` is not loopback. Web pages could previously
  drive the broker with preflight-free form and `text/plain` requests, or read responses through DNS
  rebinding.
- **[security]** The admin API requires a bearer token generated at start, printed once to the
  operator's terminal, and never persisted. Its OpenAPI and docs routes are disabled. Previously any
  local process could register a policy granting its own destination. `interpose api` and
  `interpose proxy` refuse non-loopback bind addresses.
- **[security]** `interpose-exec` now requires `allow_exec: true` in the policy of every reference
  it resolves; non-curl commands require `EXEC` to be listed in `methods` explicitly; schemeless curl
  targets count as destinations; curl options that reroute traffic (`-K`, `--next`, `-x`,
  `--resolve`, `--connect-to`, `-L`, ...) are refused; and an explicit `--destination` is refused
  when the command addresses another host.
- **[security]** Secret fingerprints are HMAC-SHA256 keyed from the master key instead of a bare
  SHA-256 of the plaintext, which was an offline guessing oracle for low-entropy secrets. Existing
  fingerprints are migrated when the vault is opened.
- **[security]** A newly generated `master.key` is created with owner-only permissions: mode 0600,
  or on Windows an ACL with inheritance removed and full control for the current user alone.
- **[security]** Binary response bodies are redacted at the byte level; a single invalid UTF-8 byte
  previously caused the whole body to pass through unredacted.

### Fixed

- The broker no longer forwards the upstream `Content-Encoding` header after `httpx` has already
  decoded the body, which made clients fail to decompress a plain payload.
- The broker no longer forwards the upstream `Server` and `Date` headers next to its own.
- A folder inside a registered project could not be registered as a project of its own: the
  dashboard hid the button whenever any project applied. It now offers it, and a project can be
  unregistered from the top bar (its project secrets and policies are deleted with it, so a later
  project with the same id cannot inherit them). Home folders and drive roots can no longer be
  registered, since they would cover nearly every folder.
- `interpose setup` after `pipx install git+https://...` installed `interpose==<version>` from PyPI
  into the service runtime, which fails while the package is unpublished; it now installs the same
  repository commit the user installed.

### Added

- Apache-2.0 license, `NOTICE`, contribution guide, code of conduct, and security policy with a
  scope statement distinguishing vulnerabilities from documented non-guarantees.
- `docs/ARCHITECTURE.md` describing components, the request lifecycle, and the trust boundary.
- GitHub Actions CI running tests and lint on Linux, macOS, and Windows against Python 3.12 and 3.13,
  plus a package build check.
- `ruff` lint configuration and `pytest-cov`, wired into the `dev` extra.
- Issue and pull request templates, and Dependabot for Actions and pip.

### Documentation

- Corrected the quickstart, which showed `--agent` as if it were required. It is optional, defaults
  to `unknown`, and is an audit label — no policy is keyed to it and no behavior depends on it.
- Documented that broker-side audit attribution is **self-reported and currently non-functional**:
  the label reaches the child's environment but not the broker, which has no client authentication
  on loopback and cannot verify which process sent a request. Added as a row in the threat model.
- Added "What Interpose can and cannot wrap", covering the two real compatibility conditions —
  inheriting the launcher's environment, and supporting a configurable base URL — including the
  trap where `code .` signals an already-running editor instance and silently leaves the session
  unprotected.

### Fixed

- **[security]** SQLite connections in the secret vault, policy repository, and audit log were never
  closed. `sqlite3`'s connection context manager governs the transaction, not the handle, so every
  operation leaked a file descriptor and left the database file locked on Windows — including the
  file holding encrypted secret material.
- Test collection failed on Linux and macOS because `tests/test_isolation.py` imported the Windows
  AppContainer backend at module scope, which binds `ctypes.wintypes` at import time. The import is
  now deferred into the platform-guarded tests.
- CLI exits raised from exception handlers now chain the originating error with `raise ... from`,
  so a policy or resolution failure is no longer masked in tracebacks.

### Changed

- **Renamed the project from Secret Runtime to Interpose**, before any release. The package is now
  `interpose`, the CLI is `interpose`, `secure-exec` became `interpose-exec`, environment variables
  use the `INTERPOSE_` prefix, and the runtime home moved to `~/.interpose`. The `secret://` URI
  scheme is unchanged — it describes the reference, not the product.
- Strict warning filters (`-W error`) in the pytest configuration, so resource and deprecation
  warnings fail the build instead of accumulating silently.

## [0.1.0] - 2026-08-21

Initial implementation.

### Added

- `secret://` reference parsing and normalization.
- AES-GCM encrypted local vault with a metadata-only administrative surface.
- Policy engine evaluating destination, method, and scheme **before** secret resolution.
- Explicit local transport at `/proxy/{host}/{path}` with external HTTPS origination, and rejection
  of HTTPS `CONNECT` rather than tunneling traffic the broker cannot inspect.
- Secret substitution across query strings, form bodies, JSON bodies, and headers, with exact-value
  redaction of responses, headers, and error traces.
- Metadata-only SQLite audit log with resolved URLs redacted before persistence.
- Reference-only session profiles, `.env` reference validation, and an environment allowlist that
  strips inherited credentials from managed children.
- Agent-agnostic `interpose run` launcher for Codex, Claude Code, Cursor, and Gemini CLI.
- Windows AppContainer isolation backend with loopback firewall rules scoped to the container SID.
- Administrative FastAPI application with no endpoint that returns a secret value.
- `interpose-exec` limited compatibility mode for tools the broker cannot mediate.

[Unreleased]: https://github.com/Coelhomicka/interpose-agent/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Coelhomicka/interpose-agent/releases/tag/v0.1.0
