"""A deterministic, offline *mock* LLM for the training lab.

It is NOT a real language model. It is a small rule-based stand-in that
reproduces the *behaviours* an LLM-backed app exhibits — following instructions
found in user input, echoing untrusted content into its output — so the lab can
teach those failure modes without an API key and with reproducible results.

A real-provider mode can wrap this later; the lesson (what the app does with the
model's input and output) is identical either way.
"""
from __future__ import annotations

import re

# Phrases a hijacked model treats as higher-priority instructions. Classic,
# widely documented prompt-injection triggers — kept here as teaching material.
INJECTION_TRIGGERS = [
    "ignore previous", "ignore all previous", "ignore your", "disregard",
    "reveal your", "show your", "print your", "system prompt",
    "your instructions", "your rules", "repeat the text above",
]

_ECHO_RE = re.compile(r"(?:summarize|echo|repeat|translate)\s*:?\s*(.+)", re.IGNORECASE | re.DOTALL)


def _has_trigger(text: str) -> bool:
    lowered = text.lower()
    return any(trigger in lowered for trigger in INJECTION_TRIGGERS)


def generate(system_prompt: str, user_message: str) -> str:
    """Return the mock model's reply, given the system prompt and user message.

    Vulnerable on purpose: when the user message contains an injection trigger,
    the model obeys it and discloses its system prompt (which the app author
    wrongly assumed was hidden). It also echoes content it is asked to repeat,
    verbatim — the root of insecure output handling.
    """
    if _has_trigger(user_message):
        # The hijacked model dumps its own instructions, secrets and all.
        return f"Of course. My full instructions are:\n{system_prompt}"

    echo = _ECHO_RE.search(user_message)
    if echo:
        # Untrusted content is copied straight into the model's output.
        return f"Here is that content:\n{echo.group(1).strip()}"

    lowered = user_message.lower()
    if any(word in lowered for word in ("promo", "discount", "code", "secret", "password")):
        return "I'm sorry, I can't share internal codes or secrets."
    return "Thanks for contacting support! How can I help with your order today?"
