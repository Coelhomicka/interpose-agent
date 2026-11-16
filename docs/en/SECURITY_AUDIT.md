**English** | [Português (Brasil)](../pt-br/SECURITY_AUDIT.md)

# Security Audit — November 2026

An adversarial review of the broker, policy engine, redaction, dashboard, control
API and `interpose-exec`, done before the first public release. The reviewer worked
from the code alone, without the authors' conclusions, and tried to obtain a secret
value or to make the broker send one to a host the operator did not approve.

**Attacker model:** arbitrary code running as the same non-elevated Windows user as
the agent. It can read every file that user can read, start processes, and send any
request to the loopback listeners.

Every finding was reproduced against a fake upstream (no secret left the machine),
and each fix ships with a regression test in
[`tests/test_audit_regressions.py`](../../tests/test_audit_regressions.py). Those
tests fail on the code before the fix.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | Critical | Policy host and connection host could disagree in Host-header proxy mode | Fixed |
| 2 | High | Project policies do not contain a same-user process | Documented: not a boundary |
| 3 | High | The service control token lets a same-user process change policies | Fixed: Windows Hello approval for widening changes |
| 4 | Medium | Redaction missed common encodings and compressed bodies | Fixed |
| 5 | Low | Unicode hosts were normalized differently by policy and by the HTTP client | Fixed |

### 1. Policy host vs connection host (Critical, fixed)

**Root cause.** In Host-header and absolute-form proxy mode, the destination came
from the `Host` header verbatim, and policy matched that text with `fnmatch`. The
upstream URL was then built from the same text and re-parsed by the HTTP client,
which ends the authority at the first `/`, `?` or `#`. A value that matched a
wildcard allow pattern as text could make the client connect to another host, so the
credential was injected into a request to the attacker. Exact-host policies were not
affected.

**Fix.**
- The `Host` header and absolute-form targets go through the same strict parser as the
  `/proxy/{host}` transport. It accepts one ASCII hostname or IP literal and an
  optional port. It refuses userinfo, paths, queries, fragments, backslashes,
  whitespace and Unicode, which must be sent as `xn--` A-labels.
- `verified_upstream_url` re-parses the URL the client will dial. Its host, port and
  path must equal the ones the policy approved, and dot segments are refused, so
  whatever the client would rewrite is rejected instead of guessed at.
- Allow patterns are label-aware. A pattern is an exact `host[:port]`, a leading
  `*.example.com` that covers subdomains only, or `*`. Glob forms such as `api.*` or
  `*example.com` are refused when a policy is written, and a stored policy that
  breaks this rule now denies instead of matching. Deny patterns keep glob
  semantics, because matching more there only blocks more.

### 2. Project scopes are not isolation (High, documented)

The project route (`/p/{id}/proxy/...`) chooses which policies apply. The broker
cannot tell which process is calling, so code running as the user can pick any
project's route, or the global one. A project policy that is narrower than the
global one therefore contains nothing.

No code change can fix this without per-process identity, which loopback HTTP does
not provide (see the attribution item in the [roadmap](ROADMAP.md)). Instead, the
[threat model](THREAT_MODEL.md) and the policy engine's documentation now state the
real guarantee: a secret can only reach the union of the hosts its policies allow,
anywhere on the machine. Write the narrowest policy in the global scope.

### 3. Control token (High, fixed)

`client\control.token` is readable by the installing user so that `interpose up`
can open dashboard sessions without a second login. A same-user process could use
it to open a session and add an allowed host, which defeated egress policy for
every secret. Values could still not be read back.

**Fix: user presence for widening changes.** Opening a session still needs no
second login. Any policy change that could send a secret somewhere new must carry a
WebAuthn assertion from the operator's authenticator: Windows Hello, which means
face, fingerprint or PIN.
- **What counts as widening:** a new policy, or a host, method, path, slot or
  scheme not covered before. So do removing a deny or a path limit, and enabling
  `allow_exec`. The check is conservative: whatever is not provably narrower needs
  approval.
- **The challenge** is single-use, expires in two minutes, and is bound to the
  session and to a hash of the exact scope and policy being stored. An approval for
  one change cannot be spent on another.
- **The verifier** checks the challenge, the origin (`http://localhost:<port>`),
  the relying party (`localhost`), the user-present and user-verified flags, the
  signature (RS256, ES256 or Ed25519) and the signature counter. It needs no new
  dependencies, and its CBOR parser is bounded and fuzzed.
- **Enrollment** is where trust comes from. `interpose setup`, or
  `interpose service enroll`, creates the credential through `webauthn.dll` from
  the private runtime in `%ProgramFiles%`, and writes its public key into the vault
  folder. Both places are closed to the user's processes, so they cannot enroll a
  key of their own. A damaged record keeps approval required instead of turning it
  off.

Every elevated task except install now also runs from that private runtime instead
of the user's own (writable) install.

**Residual risks.**
- A same-user process can make Windows Hello prompt at a moment the operator
  expects a prompt, and borrow the approval. Approve only right after saving a
  change yourself.
- Without enrollment (no Windows Hello on the machine), the dashboard shows a
  warning and changes are unprotected.
- Replacing a secret value needs no approval: it reveals nothing, but it can break
  a working credential.

### 4. Redaction coverage (Medium, fixed)

Redaction covered the exact, percent-encoded and base64 forms. It now also covers:
- JSON escaping (including `\/`) and hex;
- URL-safe base64, and base64 embedded at any byte alignment, as in
  `Basic base64(user:token)`;
- all of these case-insensitively.

The broker also used to forward the agent's `Accept-Encoding`, so an upstream could
answer in `br` or `zstd`. Redaction then scanned compressed bytes. The broker now
offers only `gzip, deflate` and refuses (502) any response in another encoding.

A property-based test (Hypothesis) checks that no supported reflection of a random
secret survives redaction.

Redaction remains defense in depth. The guarantee comes from the injection-slot and
host policies.

### 5. Unicode host normalization (Low, fixed)

Policy matched the host as text, while the HTTP client applied IDNA normalization
before dialing. Fullwidth dots, dotless `ı` and similar characters could therefore
mean one host to the policy and another to the connection. Non-ASCII hosts are now
refused. A fuzz test checks that, for any accepted `Host` value, the dialed host
equals the policy host.

## Checked and sound

- Userinfo in absolute-form targets is rejected. CRLF in header values is rejected by
  the HTTP client, and `interpose-exec` refuses control characters and backslashes.
- A reference used as a header, query or form *name*, in a body, or in an undeclared
  field is denied before resolution.
- Redirects are not followed, `trust_env` is off, and `CONNECT` is refused.
- Policy is evaluated before resolution, and `EXEC` and plain HTTP require explicit
  opt-in.
- AES-GCM associated data binds each ciphertext to its scope and reference.
  Fingerprints are keyed HMACs.
- Loopback listeners refuse `Origin`, cross-site `Sec-Fetch-Site` and non-loopback
  `Host` headers. Control routes also refuse requests shaped like a browser's.
- Dashboard login links are single-use and expire. Sessions use `HttpOnly`,
  `SameSite=Strict` cookies, with a per-session CSRF token and a strict CSP. Values
  are write-only.
- The service does not inherit `INTERPOSE_MASTER_KEY` or `INTERPOSE_HOME`, and the
  launcher builds child environments from an allowlist.

## Continuous checks

- `tests/test_audit_regressions.py` runs on every pull request on Linux, macOS and
  Windows. It includes Hypothesis fuzzing of host parsing and redaction.
- CodeQL (`security-extended`) runs on every pull request and weekly. OpenSSF
  Scorecard runs on `main`.

Report new issues privately: see [SECURITY.md](../../SECURITY.md).
