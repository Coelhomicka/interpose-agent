from __future__ import annotations

from interpose.core.redaction import SecretRedactionEngine


def test_redaction_engine_replaces_secret_value():
    engine = SecretRedactionEngine()
    engine.register("my-token-123")

    redacted = engine.redact("Error using token my-token-123")

    assert redacted == "Error using token [REDACTED]"



def test_redacts_trimmed_echo_of_value_with_surrounding_space():
    # Regression: a value stored as " sk-..." went out as "Bearer  sk-...", the
    # upstream echoed it trimmed, and exact-match redaction let it through.
    engine = SecretRedactionEngine()
    engine.register(" sk-demo-SEGREDO-123")

    assert engine.redact('{"your_token_was": "sk-demo-SEGREDO-123"}') == '{"your_token_was": "[REDACTED]"}'


def test_redacts_url_encoded_and_base64_echoes():
    import base64

    engine = SecretRedactionEngine()
    engine.register("key/with+special=chars")

    assert "special" not in engine.redact("next=https://x/?k=key%2Fwith%2Bspecial%3Dchars")
    basic = base64.b64encode(b"key/with+special=chars").decode()
    assert engine.redact(f"Authorization: Basic {basic}") == "Authorization: Basic [REDACTED]"


def test_short_variants_are_not_redacted_on_their_own():
    # The exact value is always redacted; derived variants this short are not,
    # because replacing them everywhere would corrupt unrelated text.
    engine = SecretRedactionEngine()
    engine.register("a b")

    assert engine.redact("a+b a%20b") == "a+b a%20b"
    assert engine.redact("x a b y") == "x [REDACTED] y"
