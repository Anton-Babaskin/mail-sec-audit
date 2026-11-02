"""USERS.SUDO_NOPASSWD: sudo rules without a password"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("USERS.SUDO_NOPASSWD")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    sudoers = ctx.facts.sudoers()
    if isinstance(sudoers, Unavailable):
        return [B.unavailable(sudoers)]
    if sudoers.nopasswd:
        return [B.info(count=len(sudoers.nopasswd), evidence=[ev(sudoers.source, *sudoers.nopasswd, limit=20)])]
    return [B.ok(evidence=[ev(sudoers.source)])]
