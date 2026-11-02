"""SSH.MAX_AUTH_TRIES: MaxAuthTries"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from ._ssh import sshd_or_finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("SSH.MAX_AUTH_TRIES")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    config = sshd_or_finding(ctx, B)
    if isinstance(config, Finding):
        return [config]
    value = config.get("maxauthtries") or ""
    if not value.isdigit():
        return [B.unknown("parse_error", source=config.source)]
    evidence = [ev(config.source, f"maxauthtries {value}")]
    if int(value) > 6:
        return [B.warn(value=value, evidence=evidence)]
    return [B.ok(value=value, evidence=evidence)]
