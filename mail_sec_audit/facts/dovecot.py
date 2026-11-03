"""Selected Dovecot settings (never ``doveconf -x``, never key material)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..runner import Runner
from ..stacks.base import Stack
from .base import Unavailable, from_result


@dataclass(frozen=True)
class DovecotSettings:
    values: dict[str, Optional[str]]
    source: str
    failure: Optional[Unavailable] = None


def collect(runner: Runner, stack: Stack) -> DovecotSettings:
    values: dict[str, Optional[str]] = {}
    failure = None
    for name in ("ssl", "ssl_min_protocol", "auth_allow_cleartext", "disable_plaintext_auth"):
        result = runner.run(stack.dovecot_argv("doveconf", "-h", name))
        if result.ok:
            values[name] = result.stdout.strip()
        else:
            values[name] = None  # unknown setting in this Dovecot version, or no access
            if failure is None and "unknown setting" not in (result.stderr + result.stdout).lower():
                failure = from_result(result)
    return DovecotSettings(values, "cmd:doveconf -h", failure)
