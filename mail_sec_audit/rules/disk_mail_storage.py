"""DISK.MAIL_STORAGE: mailbox storage location and its filesystem"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("DISK.MAIL_STORAGE")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    stack = ctx.facts.stack()
    path = stack.mail_storage
    if not path and stack.mta == "postfix":
        config = ctx.facts.postfix()
        if not isinstance(config, Unavailable):
            path = config.main.get("virtual_mailbox_base") or None
    if not path or not path.startswith("/"):
        return [B.info("unknown_path")]
    if not stack.compose_project and not ctx.host.exists(path):
        return [B.info("unknown_path")]
    usage = ctx.facts.command(["df", "-P", "-B1", path])
    lines = list(usage.lines) if not isinstance(usage, Unavailable) else []
    if ctx.config.deep:
        du = ctx.facts.command(["du", "-s", "-x", "-B1", path])
        if not isinstance(du, Unavailable):
            lines += list(du.lines)
    return [B.info(path=path, evidence=[ev(f"cmd:df -P -B1 {path}", *lines)])]
