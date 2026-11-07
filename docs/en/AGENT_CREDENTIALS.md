**English** | [Português (Brasil)](../pt-br/AGENT_CREDENTIALS.md)

# Agent Credential Contract

## Purpose

This contract is the canonical instruction for Codex, Claude Code, Cursor, Gemini CLI, and other untrusted local agents.

## Required behavior

Credential variables contain opaque `secret://` references, never plaintext values.

When asked to configure a credential:

1. Write the requested reference into the expected environment variable or configuration field.
2. Normalize shorthand such as `APIChave/teste` to `secret://apichave/teste`.
3. Never ask for the plaintext value when a reference is available.
4. Never replace a reference with `****`, a fake token, or a hardcoded value.
5. Never implement code that resolves a reference.
6. Never inspect the Interpose database, master key, process memory, or administrative API.
7. Use the variable normally. The trusted data plane mediates supported operations.
8. When a broker base URL is provided, configure the application's normal base URL variable to use it. Do not reconstruct individual requests.
9. Never replace `/proxy/{allowed-host}` with another destination to bypass policy.
10. On `PolicyViolation`, report the reference, destination, method, scheme, and requested capability. Do not bypass the policy.
11. If a library rejects references before reaching a broker, report an unsupported local-secret operation. Do not request the secret.
12. Place references only where the credential belongs — normally the `Authorization` or `X-API-Key` header. Never put a reference in a request body, a message, a prompt, or any field an API stores or echoes. The broker denies those, and trying is a policy violation.

## Examples

Requested binding:

```text
Set API_KEY to credential APIChave/teste.
```

Correct `.env`:

```dotenv
API_KEY=secret://apichave/teste
API_BASE=http://127.0.0.1:9876/proxy/api.exemplo.com
# or, inside a registered project: http://127.0.0.1:9876/p/<project>/proxy/api.exemplo.com
```

Incorrect `.env`:

```dotenv
API_KEY=plaintext-value
API_KEY=****
API_BASE=https://api.exemplo.com
```

Applications may read or print the variable because it contains only the reference:

```python
import os

assert os.environ["API_KEY"] == "secret://apichave/teste"
```

## IDE adapters

Keep this contract as the source of truth and repeat its required behavior in the instruction surface supported by each agent, such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and Cursor workspace rules.

Instruction files are advisory. Security enforcement comes from the reference-only launcher, trusted brokers, policy engine, OS access controls, and network isolation.

## Control and data planes

The control plane may list references, metadata, capabilities, and policies. It must never return secret values.

The data plane receives operations containing references, validates their destination and purpose, resolves inside the trusted broker, performs the operation, redacts outputs, and returns only safe results.
