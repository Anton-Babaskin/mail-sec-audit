"""CTX.PLATFORM: detected mail platform and version"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("CTX.PLATFORM")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    stack = ctx.facts.stack()
    lines = [f"platform {stack.name} ({stack.detection or 'auto'})", f"mta {stack.mta}", f"imap {stack.imap}"]
    if stack.version_source:
        lines.append(stack.version_source)
    return [B.info(platform=stack.name, version=stack.version or "", evidence=[ev("stack:detect", *lines)])]
