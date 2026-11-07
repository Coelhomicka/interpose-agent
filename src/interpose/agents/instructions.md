# Interpose: how credentials work here

This machine uses **Interpose**. Credentials are **references** such as `secret://openai/prod`,
never real values. A trusted local broker replaces the reference with the real key on the way out
and masks it on the way back. You never see, need, or handle the real value — and you must not try.

You are inside an Interpose session when `INTERPOSE_MODE=reference-only` is set. The broker's base
URL for this project is in `INTERPOSE_PROXY` (for example `http://127.0.0.1:9876/p/my-app/proxy`).
If it is not set, use `http://127.0.0.1:9876/proxy`.

## Making an authenticated call

1. Put the reference where the credential belongs — normally the `Authorization` or `X-API-Key`
   header. Read it from the environment variable that holds it; do not copy it into code.
2. Send the request **through the broker**: `$INTERPOSE_PROXY/<host>/<path>`. The broker opens the
   HTTPS connection to the real API itself, so talk plain `http` to the broker.
3. If a `*_BASE_URL` variable already points at the broker, use it as is.

```bash
curl -s "$INTERPOSE_PROXY/api.github.com/user" -H "Authorization: Bearer $GITHUB_TOKEN"
```

```python
import os, httpx
r = httpx.get(f"{os.environ['INTERPOSE_PROXY']}/api.github.com/user",
              headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"})
```

```python
# SDKs: the reference is the API key, the broker is the base URL.
from openai import OpenAI
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"],
                base_url=os.environ["INTERPOSE_PROXY"] + "/api.openai.com/v1")
```

```javascript
await fetch(`${process.env.INTERPOSE_PROXY}/api.github.com/user`,
            { headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } });
```

## Writing configuration and code

- In `.env` and config files, write the reference: `OPENAI_API_KEY=secret://openai/prod`.
- Point base URLs at the broker. In an Interpose `session.yaml`, use the placeholder:

  ```yaml
  version: 1
  environment:            # credentials: references only
    OPENAI_API_KEY: secret://openai/prod
  public_environment:     # anything else the app needs
    OPENAI_BASE_URL: ${INTERPOSE_PROXY}/api.openai.com/v1
  ```

- Printing or logging the variable is harmless: it only holds the reference.

## Reading responses

- `[REDACTED]` in a response is the broker masking the real key. Expected; leave it.
- `403 PolicyViolation: …` — the policy does not allow this call (host, method, path, or where the
  reference was placed). Stop and tell the user the reference, host, method, path and the reason.
  They can change the policy in the Interpose dashboard (`interpose up`). Do not retry another way.
- `404 unknown project` — the folder is not registered; ask the user to register it in the dashboard.
- `502` — the broker could not reach the API (down, wrong host, or no network).
- A library that refuses `secret://…` before sending anything (local format check) is an
  unsupported case: report it, do not ask for the real key.

## When a credential is missing

Ask the user to add it in the dashboard (`interpose up` → Secrets) under a reference you propose,
such as `secret://stripe/test`, and to allow the API host in a policy. Then use the reference.
**Never ask the user to paste a real key into the chat, a file, or a command.**

## Never

- read, copy or decrypt the Interpose vault, `master.key`, `runtime.db`, `%ProgramData%\Interpose`,
  or `~/.interpose`; read `control.token` or call the broker's `/control/` routes;
- ask for, guess, hardcode or invent a real key, or replace a reference with `****` or a fake token;
- put a reference in a request body, a chat message, a prompt, or any field an API stores or echoes;
- call the API directly instead of through the broker, or change `/proxy/<host>` to another host to
  get around a policy;
- change policies, open the dashboard yourself, elevate privileges, or disable Interpose.
