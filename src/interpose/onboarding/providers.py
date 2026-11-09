"""Known API providers: how to recognize their credentials and a policy to start from.

A provider with ``hosts`` is *brokerable*: its credential travels in an HTTP
header or query field, so the broker can inject it and the application only ever
holds the ``secret://`` reference. Providers without hosts (AWS signs requests
with the key, a private key signs locally, a database speaks its own protocol)
are recognized so they can be reported, but the broker cannot carry them yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    hosts: tuple[str, ...] = ()
    inject: tuple[tuple[str, str], ...] = (("header", "authorization"),)
    env_names: tuple[str, ...] = ()
    value_pattern: re.Pattern[str] | None = None
    note: str = ""
    paths: tuple[str, ...] | None = None
    docs: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def base_url_hint(self) -> str | None:
        """How to point this provider's official SDK at the broker, when it reads an env var."""
        variable = self.extra.get("base_url_env")
        if not variable or not self.hosts:
            return None
        return f"{variable}=$INTERPOSE_PROXY/{self.hosts[0]}{self.extra.get('base_path', '')}"

    @property
    def brokerable(self) -> bool:
        return bool(self.hosts)

    def policy(self, secret_reference: str) -> dict:
        """A policy document (as a mapping) for this provider's credential."""
        document: dict = {
            "secret": secret_reference,
            "allow": {"hosts": list(self.hosts)},
            "inject": [{kind: name} for kind, name in self.inject],
        }
        if self.paths is not None:
            document["paths"] = list(self.paths)
        return document


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# Order matters: more specific value patterns come first (``sk-ant-`` before ``sk-``).
PROVIDERS: tuple[Provider, ...] = (
    Provider("anthropic", "Anthropic", ("api.anthropic.com",), (("header", "x-api-key"),),
             ("ANTHROPIC_API_KEY", "CLAUDE_API_KEY"), _p(r"sk-ant-[A-Za-z0-9_-]{20,}"),
             extra={"base_url_env": "ANTHROPIC_BASE_URL", "base_path": ""}),
    Provider("openrouter", "OpenRouter", ("openrouter.ai",), env_names=("OPENROUTER_API_KEY",),
             value_pattern=_p(r"sk-or-v1-[A-Za-z0-9]{32,}")),
    Provider("openai", "OpenAI", ("api.openai.com",), env_names=("OPENAI_API_KEY",),
             value_pattern=_p(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
             extra={"base_url_env": "OPENAI_BASE_URL", "base_path": "/v1"}),
    Provider("github", "GitHub", ("api.github.com", "uploads.github.com"),
             env_names=("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"),
             value_pattern=_p(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")),
    Provider("gitlab", "GitLab", ("gitlab.com",), (("header", "private-token"),),
             ("GITLAB_TOKEN", "GL_TOKEN"), _p(r"glpat-[A-Za-z0-9_-]{20,}")),
    Provider("stripe", "Stripe", ("api.stripe.com",), env_names=("STRIPE_SECRET_KEY", "STRIPE_API_KEY"),
             value_pattern=_p(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    Provider("slack", "Slack", ("slack.com",), env_names=("SLACK_BOT_TOKEN", "SLACK_TOKEN", "SLACK_USER_TOKEN"),
             value_pattern=_p(r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    Provider("sendgrid", "SendGrid", ("api.sendgrid.com",), env_names=("SENDGRID_API_KEY",),
             value_pattern=_p(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")),
    Provider("huggingface", "Hugging Face", ("huggingface.co", "api-inference.huggingface.co"),
             env_names=("HF_TOKEN", "HUGGINGFACE_TOKEN", "HUGGING_FACE_HUB_TOKEN"),
             value_pattern=_p(r"hf_[A-Za-z0-9]{30,}")),
    Provider("gemini", "Google Gemini", ("generativelanguage.googleapis.com",), (("header", "x-goog-api-key"),),
             ("GEMINI_API_KEY", "GOOGLE_API_KEY"), _p(r"AIza[0-9A-Za-z_-]{35}")),
    Provider("groq", "Groq", ("api.groq.com",), env_names=("GROQ_API_KEY",),
             value_pattern=_p(r"gsk_[A-Za-z0-9]{20,}")),
    Provider("xai", "xAI", ("api.x.ai",), env_names=("XAI_API_KEY",), value_pattern=_p(r"xai-[A-Za-z0-9]{20,}")),
    Provider("perplexity", "Perplexity", ("api.perplexity.ai",), env_names=("PERPLEXITY_API_KEY", "PPLX_API_KEY"),
             value_pattern=_p(r"pplx-[A-Za-z0-9]{20,}")),
    Provider("replicate", "Replicate", ("api.replicate.com",), env_names=("REPLICATE_API_TOKEN",),
             value_pattern=_p(r"r8_[A-Za-z0-9]{20,}")),
    Provider("linear", "Linear", ("api.linear.app",), env_names=("LINEAR_API_KEY",),
             value_pattern=_p(r"lin_api_[A-Za-z0-9]{20,}")),
    Provider("notion", "Notion", ("api.notion.com",), env_names=("NOTION_TOKEN", "NOTION_API_KEY"),
             value_pattern=_p(r"(?:secret_|ntn_)[A-Za-z0-9]{40,}")),
    Provider("resend", "Resend", ("api.resend.com",), env_names=("RESEND_API_KEY",),
             value_pattern=_p(r"re_[A-Za-z0-9_]{16,}")),
    Provider("mistral", "Mistral", ("api.mistral.ai",), env_names=("MISTRAL_API_KEY",)),
    Provider("deepseek", "DeepSeek", ("api.deepseek.com",), env_names=("DEEPSEEK_API_KEY",)),
    Provider("cohere", "Cohere", ("api.cohere.com", "api.cohere.ai"), env_names=("COHERE_API_KEY", "CO_API_KEY")),
    Provider("elevenlabs", "ElevenLabs", ("api.elevenlabs.io",), (("header", "xi-api-key"),),
             ("ELEVENLABS_API_KEY", "XI_API_KEY")),
    Provider("pinecone", "Pinecone", ("api.pinecone.io", "*.pinecone.io"), (("header", "api-key"),),
             ("PINECONE_API_KEY",)),
    Provider("supabase", "Supabase", ("*.supabase.co",), (("header", "apikey"), ("header", "authorization")),
             ("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY", "SUPABASE_ANON_KEY")),
    Provider("vercel", "Vercel", ("api.vercel.com",), env_names=("VERCEL_TOKEN",)),
    Provider("cloudflare", "Cloudflare", ("api.cloudflare.com",), env_names=("CLOUDFLARE_API_TOKEN", "CF_API_TOKEN")),
    Provider("datadog", "Datadog", ("api.datadoghq.com", "api.datadoghq.eu"), (("header", "dd-api-key"),),
             ("DD_API_KEY", "DATADOG_API_KEY")),
    Provider("sentry", "Sentry", ("sentry.io",), env_names=("SENTRY_AUTH_TOKEN",),
             value_pattern=_p(r"sntrys_[A-Za-z0-9_=+/]{40,}")),
    Provider("airtable", "Airtable", ("api.airtable.com",), env_names=("AIRTABLE_API_KEY", "AIRTABLE_TOKEN"),
             value_pattern=_p(r"pat[A-Za-z0-9]{14}\.[a-f0-9]{64}")),
    # Recognized, but the broker cannot carry them yet.
    Provider("aws", "AWS access key", env_names=("AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN"),
             value_pattern=_p(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
             note="AWS signs each request with the key (SigV4); it needs a signing broker, not injection."),
    Provider("npm", "npm token", env_names=("NPM_TOKEN",), value_pattern=_p(r"npm_[A-Za-z0-9]{36}"),
             note="Used by the npm client itself; keep it out of the project and in the user's npm config."),
    Provider("private-key", "Private key", value_pattern=_p(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
             note="Signs locally; it needs a signing broker. Never commit it."),
    Provider("connection-string", "Connection string",
             value_pattern=_p(r"[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s/@]{3,}@[^\s/]+"),
             note="Database and broker protocols are not HTTP; the broker cannot inject into them yet."),
)

_BY_ID = {provider.id: provider for provider in PROVIDERS}
_BY_ENV = {name: provider for provider in PROVIDERS for name in provider.env_names}


def provider(provider_id: str) -> Provider | None:
    return _BY_ID.get(provider_id)


def identify(key: str | None, value: str) -> Provider | None:
    """The provider a credential belongs to.

    A well-known variable name wins when the value is consistent with it
    (``DEEPSEEK_API_KEY=sk-...`` is DeepSeek, not OpenAI); otherwise the value's
    own shape decides.
    """
    named = _BY_ENV.get(key.upper().rsplit(".", 1)[-1].replace("-", "_")) if key else None
    if named is not None and (named.value_pattern is None or named.value_pattern.search(value)):
        return named
    for candidate in PROVIDERS:
        if candidate.value_pattern is not None and candidate.value_pattern.search(value):
            return candidate
    return named


def brokerable_providers() -> list[Provider]:
    return [candidate for candidate in PROVIDERS if candidate.brokerable]
