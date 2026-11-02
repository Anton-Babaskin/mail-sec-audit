"""SSH.KBD_INTERACTIVE: keyboard-interactive authentication"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from ._ssh import sshd_or_finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("SSH.KBD_INTERACTIVE")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    config = sshd_or_finding(ctx, B)
    if isinstance(config, Finding):
        return [config]
    value = config.get("kbdinteractiveauthentication") or ""
    evidence = [ev(config.source, f"kbdinteractiveauthentication {value}")]
    if value == "no":
        return [B.ok(evidence=evidence)]
    if value in ("yes", "no"):
        return [B.info(evidence=evidence)]
    return [B.unknown("parse_error", source=config.source)]
