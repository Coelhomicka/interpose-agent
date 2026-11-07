**English** | [Português (Brasil)](../pt-br/ROADMAP.md)

# Roadmap

## Implemented MVP

- `secret://` reference parsing and normalization
- AES-GCM encrypted local vault
- secret and policy administrative CLI
- administrative FastAPI API without value-read endpoints
- policy-before-resolution engine
- nested substitution and exact-value redaction
- metadata-only SQLite audit
- reference-only session profiles
- `.env` reference validation
- agent-agnostic `interpose run`
- environment allowlist and inherited-credential removal
- HTTP forward/reverse broker
- explicit `/proxy/{host}` local transport with external HTTPS origination
- scheme-aware policy with secure external defaults
- separate public and credential environment bindings
- URL-encoded query and form substitution
- JSON, header, and body substitution
- explicit rejection of unsupported HTTPS `CONNECT`
- limited `interpose-exec` compatibility mode
- injection slots, path allow-lists, and explicit `allow_exec` in policies
- project and global scopes for secrets and policies
- `interpose up` with a local configuration dashboard
- Windows service under `NT SERVICE\Interpose`: private runtime in Program Files, ACL-protected
  vault, one-time `interpose setup`
- per-project broker routing (`/p/{project}/proxy/...`) and `${INTERPOSE_PROXY}` in profiles

## V2: Enforced isolation

- ~~trusted daemon under a separate OS identity~~ — done on Windows; Linux (systemd `DynamicUser=`)
  and macOS (launchd) next
- ~~filesystem ACLs for vault and master key~~ — done on Windows
- user presence (Windows Hello, Touch ID, polkit) to open a dashboard session
- authenticated Named Pipe on Windows
- authenticated Unix socket on Linux and macOS
- Linux namespaces and nftables egress enforcement
- Windows Filtering Platform and AppContainer integration
- macOS Network Extension and sandbox support
- DNS and QUIC controls
- trusted TLS termination with session-scoped CA
- redirect, DNS rebinding, path, and IP-range policy controls

## V3: Secret stores

- HashiCorp Vault
- Azure Key Vault
- AWS Secrets Manager
- GCP Secret Manager
- Windows Credential Manager
- macOS Keychain
- Linux Secret Service

## V4: Protocol brokers

- database authentication proxy
- SSH signing agent
- AWS SigV4 signing broker
- generic HMAC and asymmetric signing service
- mTLS origination
- certificate signing
- dynamic and short-lived credentials

## V5: Agent integrations

- generated `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and Cursor rules
- Codex CLI session adapter
- Claude Code session adapter
- Cursor launcher
- Gemini CLI session adapter
- optional MCP control plane for references and capabilities only
