# Security Policy

## Supported versions

Interpose is alpha software. Only the latest commit on `main` receives security fixes.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| `0.1.x` tags | No — upgrade to `main` |

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Report privately through
[GitHub Security Advisories](https://github.com/Coelhomicka/interpose-agent/security/advisories/new),
or by email to **mcmickael9@gmail.com** with `[interpose security]` in the subject.

Please include:

- the affected component (broker, vault, policy engine, launcher, isolation backend, CLI, admin API);
- the version or commit hash;
- a description of the impact — specifically, what an attacker learns or reaches that they should not;
- reproduction steps or a proof of concept;
- your platform and Python version.

**Never include a real credential in a report.** Use a throwaway value.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | 72 hours |
| Initial assessment | 7 days |
| Fix or documented mitigation | 90 days, sooner for critical issues |

This is a single-maintainer project, so these are good-faith targets rather than a contractual SLA.
Coordinated disclosure is preferred: we will agree a publication date with you and credit you in the
advisory and changelog unless you ask otherwise.

## Scope

Before reporting, please read [`docs/en/THREAT_MODEL.md`](docs/en/THREAT_MODEL.md). It documents, per
threat, what is protected and what is not. A report describing a limitation already listed as
*Not Protected Yet* is not a vulnerability — it is a known gap with a roadmap entry.

### In scope

- A path by which a stored secret value reaches a CLI output, an API response, a log line, or an
  audit record.
- Policy bypass: any request that reaches the resolution step for a destination, method, or scheme
  the policy does not allow.
- Resolution ordering: any path where a secret is decrypted before its policy is evaluated.
- Redaction bypass: a resolved value surviving in a response body, header, or error trace in a form
  the redaction engine should have caught.
- Environment leakage: a managed child receiving a plaintext value, `INTERPOSE_MASTER_KEY`, or
  `INTERPOSE_HOME`.
- Weaknesses in the AES-GCM vault: nonce reuse, key derivation flaws, unauthenticated data paths.
- Path or authority parsing flaws in the local transport that redirect a request to an
  unauthorized host.
- Privilege or ACL errors in the Windows AppContainer backend.

### Out of scope

These are documented non-guarantees, not vulnerabilities:

- A process running as the **same OS user** reading the vault file, master key, or broker memory.
  Enforced isolation is V2 on the [roadmap](docs/en/ROADMAP.md).
- An agent opening a **direct network socket**, bypassing the broker entirely. OS-level egress
  control is required and not yet implemented.
- The **unauthenticated administrative API** when it is exposed beyond loopback. It is documented as
  loopback-only.
- **`interpose-exec`** delivering plaintext to its subprocess. That is its documented behavior and the
  reason it is labeled a limited compatibility mode.
- HTTPS `CONNECT` not being intercepted. It is rejected with `501` by design.
- DNS, QUIC, covert channels, and other transports outside the broker.

If you believe one of these is exploitable in a way the threat model does not already describe,
report it — the boundary being wrong is itself worth knowing.

## Operational guidance

Interpose's guarantees hold only under the deployment it assumes:

1. Run the broker and the administrative CLI in a **trusted terminal**, not inside the agent session.
2. Keep `INTERPOSE_HOME` outside any directory the agent can read or write.
3. Keep the administrative API bound to loopback.
4. Add policies from operator-controlled files only. A profile inside the agent's workspace must
   never be a source of authorization.
5. Treat `interpose-exec` as a stopgap for tools the broker cannot mediate — never for agent-generated
   executables.
6. Scope policies narrowly. `allow.hosts` accepts glob patterns; `*` defeats the purpose of the
   policy engine.

## Security-relevant design decisions

Three decisions are deliberate and will not be "fixed" without a design that preserves the guarantee:

- **`CONNECT` is rejected, not tunneled.** A broker cannot enforce policy on traffic it cannot read.
  Accepting the tunnel would produce a security claim that does not hold.
- **No read-secret endpoint exists** anywhere in the API or CLI. Convenience is not a sufficient
  reason to add one.
- **Insecure external HTTP is denied by default** and requires an explicit `schemes: [http]` in the
  policy.
