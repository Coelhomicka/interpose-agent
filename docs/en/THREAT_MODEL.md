**English** | [Português (Brasil)](../pt-br/THREAT_MODEL.md)

# Threat Model

## Summary

Agents, IDEs, generated code, project files, and child processes are untrusted. The Secret Store, policy engine, broker, redaction engine, and audit writer form the trusted zone.

The preferred model is reference-only execution: untrusted processes receive `secret://` values and a trusted protocol broker performs the operation that requires plaintext. `interpose-exec` is a limited compatibility mode because its subprocess receives resolved arguments.

## Threats

| Threat | Status | Notes |
| --- | --- | --- |
| Prompt injection | Partially Protected | References remain opaque, but an injected agent can attempt unsupported operations or direct egress. |
| Malicious generated code | Partially Protected | The launcher supplies references only. With the Windows service the vault is out of the code's reach; network egress is not enforced yet, and without the service a same-user process can read the vault. |
| Secret exfiltration through an allowed HTTP target | Partially Protected | Host, method, path, and injection-slot policies are checked before resolution. A reference in the body or an undeclared header/field is denied, so an allowed API cannot be used to publish or echo it. An allowed slot on an endpoint that reflects it remains a residual risk; narrow `paths`. |
| Inherited environment credentials | Protected in managed sessions | The launcher builds the child environment from an allowlist and injects only declared references. |
| Environment inspection | Protected in managed sessions | Inspection reveals references. Processes launched outside `interpose run` are out of scope. |
| Filesystem inspection | Protected on Windows with the service; Not Protected in development mode | With `interpose setup` the vault and key live in `%ProgramData%\Interpose\vault`, open only to `NT SERVICE\Interpose`, SYSTEM and administrators, and the service runs code from `%ProgramFiles%`, which the user cannot modify. Setup refuses a pre-existing data folder not owned by Administrators or containing links, so it cannot be pre-seeded with a known key. In development mode a same-user process can read the database and the key file. An elevated process can read everything in either mode. |
| Stopping the service | Not Protected | `setup` lets the installing user start and stop the service so that `interpose up` needs no elevation, so a same-user process can stop it. That denies service and frees the ports, but reveals nothing: the vault stays protected, and `interpose up` and `interpose run` refuse a port held by any process other than the service. |
| Dashboard impersonation | Protected with the service | A process that grabs the dashboard port could pose as the dashboard and collect the values typed into it. `interpose up` checks that both ports are held by the service's process before it opens a login link. |
| Service control token | Not Protected Yet | The token clients use to request dashboard login links is readable by the installing user, so a same-user process can open a dashboard session and change policies or replace values (never read them). Requiring Windows Hello user presence for dashboard sessions is the planned fix. |
| Runtime administrative API access | Partially Protected | Requires a per-start bearer token that is printed to the operator's terminal and never persisted. A same-user process that can read the operator's terminal or the API's memory can still obtain it. |
| Dashboard access | Partially Protected | Single-use login link exchanged for an `HttpOnly`, `SameSite=Strict` cookie; loopback `Host` and same-origin checks; per-session CSRF token on every change; strict CSP; values are write-only. A same-user process that reads the terminal before the operator opens the link, or that drives the operator's logged-in browser, can act as the operator. |
| Cross-project secret access | Protected in managed sessions | The active project comes from the operator's registry, not from workspace files. Project ciphertexts are bound to their scope by AES-GCM associated data. |
| Partial reflection by an upstream | Not Protected | Some APIs echo a masked key in errors (`sk_test_****abcd`). Exact-match redaction does not catch partial echoes, so a few characters can reach the agent. |
| Browser-driven access to loopback listeners | Protected | The broker and API reject requests with an `Origin` header or a cross-site `Sec-Fetch-Site`, and reject non-loopback `Host` headers, blocking CSRF and DNS rebinding from web pages. |
| `/proc` or process inspection | Protected | Reference-only sessions contain no secret arguments, and `interpose-exec` hands secrets to curl on standard input (`--config -`), never in argv. |
| Process memory inspection | Protected on Windows with the service; Not Protected in development mode | The service process belongs to `NT SERVICE\Interpose`; Windows refuses to let the user's processes open it, even for limited queries. In development mode the broker runs as the user and its memory is readable by the user's processes. |
| Elevated agent | Not Protected | An administrator can read anything. `interpose run` refuses to start an agent from an elevated shell unless `--allow-elevated` is passed. |
| Direct network exfiltration | Not Protected Yet | The explicit local transport does not prevent an agent from opening direct sockets. OS egress enforcement remains mandatory. |
| HTTP broker exfiltration | Partially Protected | Destination, method, and scheme policies are enforced before resolution. DNS rebinding and path-level controls remain. |
| HTTPS traffic | Not Protected Yet | `CONNECT` is rejected because an opaque TLS tunnel cannot substitute references safely. |
| HTTP redirects | Protected | Automatic upstream redirects are disabled. |
| URL-encoded references | Protected for query/form HTTP | The broker decodes references, evaluates policy, resolves, and safely re-encodes values. |
| Fingerprint guessing | Protected | Fingerprints are HMAC-SHA256 under a key derived from the master key, so a listed fingerprint is not an offline oracle for low-entropy secrets. Legacy SHA-256 fingerprints are rewritten on open. |
| `interpose-exec` destination bypass | Partially Protected | Requires `allow_exec: true` per secret and only runs `curl` when a reference is present; counts schemeless curl hosts and refuses rerouting curl options. Argv inference remains a heuristic, and curl itself holds the plaintext while it runs. |
| Logs and audit | Protected for known resolved values | Resolved values and resolved URLs are redacted; audit records contain references and metadata only. |
| Audit attribution | Not Protected Yet | The broker has no client authentication on loopback, so it cannot verify which process sent a request. Records are reliable about what happened, not about who did it. |
| Tracebacks | Partially Protected | Broker errors are redacted. Untrusted application tracebacks contain references only in managed sessions. |
| Response reflection | Partially Protected | Known resolved values are redacted in headers and bodies, including non-UTF-8 binary bodies. Encoded or transformed reflections may evade exact redaction; injection slots keep references out of bodies that an upstream would transform. |
| DNS exfiltration | Not Protected Yet | DNS is not controlled at the OS layer. |
| Certificate pinning | Not Protected Yet | Future transparent TLS termination will not work for pinned clients without explicit integration. |
| Local cryptographic use | Future | Signing, mTLS, SSH, and SigV4 require operation brokers; returning key material is prohibited. |

## Guarantees

The current implementation guarantees that:

1. no public API or CLI operation returns a stored secret value;
2. broker policies — host, method, scheme, path, and injection slot — are evaluated before secret resolution;
3. managed child environments contain declared references rather than resolved values;
4. the launcher does not pass `INTERPOSE_MASTER_KEY` or `INTERPOSE_HOME` to children;
5. local secret storage uses authenticated encryption;
6. audit records do not intentionally persist plaintext secrets;
7. HTTP `CONNECT` is rejected instead of creating a false transparent-HTTPS guarantee.
8. the explicit local transport derives the destination from `/proxy/{host}` and defaults external traffic to HTTPS;
9. loopback listeners refuse browser-originated and DNS-rebound requests, and the admin API requires a token;
10. with the Windows service installed, the vault and master key are readable only by `NT SERVICE\Interpose`, SYSTEM and administrators, and the service loads code only from `%ProgramFiles%\Interpose`.

## Non-Guarantees

The current implementation does not guarantee protection against:

1. a malicious process running as the same operating-system user as the broker in development mode — including reading the broker's memory — or one that uses the service's control token to change policies through the dashboard;
2. a process running elevated (administrator or SYSTEM); `interpose run` refuses to start one by default;
3. direct network access that bypasses the local transport;
4. covert channels, DNS, QUIC, or unmanaged transports;
5. what `curl` does with a secret delivered through the limited `interpose-exec` mode while it runs;
6. SDKs that require plaintext locally to validate, derive, encrypt, or sign.
