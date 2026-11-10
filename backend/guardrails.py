"""The 'secure mode' defences. Toggling secure mode routes requests through these.

Two pillars, matching the two pillars of LLM-app defence:
  - screen_input:    stop instruction-override attempts before the model sees them.
  - sanitize_output: treat model output as untrusted — escape HTML and redact
                     known secrets — before it reaches the user or the browser.

These are intentionally simple and explainable. Real deployments layer more
(structured prompts, allow-lists, a dedicated classifier, human review), but the
principle an interviewer wants to hear is exactly this: validate what goes in,
and never trust what comes out.
"""
from __future__ import annotations

import html
import re

from backend.model import INJECTION_TRIGGERS

_TRIGGER_RE = re.compile("|".join(re.escape(t) for t in INJECTION_TRIGGERS), re.IGNORECASE)
_RAW_HTML = re.compile(r"<\s*(script|img|svg|iframe|a|object|embed|style)\b[^>]*>", re.IGNORECASE)

# Secrets that must never appear in output, even if the model is tricked into emitting them.
REDACT = ["SAVE20OFF", "OMEGA-4417"]


def screen_input(user_message: str) -> str | None:
    """Return a refusal string if the input looks like prompt injection, else None."""
    if _TRIGGER_RE.search(user_message):
        return "Request blocked by input screening: this looks like an attempt to override the assistant's instructions."
    return None


def sanitize_output(reply: str) -> str:
    """Escape HTML and redact known secrets. Safe to render and free of planted secrets."""
    escaped = html.escape(reply)
    for secret in REDACT:
        escaped = escaped.replace(secret, "[REDACTED]")
    return escaped


def output_looks_dangerous(reply: str) -> bool:
    """Used by tests to assert raw active HTML is present (insecure) or gone (secure)."""
    return bool(_RAW_HTML.search(reply))
