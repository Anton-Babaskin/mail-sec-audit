"""Neutralise untrusted strings from logs, DNS, certificates and commands."""

from __future__ import annotations

import re

# C0 controls except tab, DEL, C1 controls, bidi embedding/override/isolate
# and directional marks. ESC is in C0, so ANSI sequences lose their effect.
_UNSAFE = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]")


def _escape(match: re.Match[str]) -> str:
    code = ord(match.group(0))
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def clean(value: str, limit: int = 300) -> str:
    """Escape control and bidi characters, replace tabs, cap the length."""
    value = _UNSAFE.sub(_escape, value.replace("\t", " "))
    if len(value) > limit:
        value = value[: max(0, limit - 1)] + "…"
    return value
