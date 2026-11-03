"""PATCH.APT_METADATA_AGE: age of the APT package lists"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("PATCH.APT_METADATA_AGE")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.package_manager() != "apt":
        return [B.na("na")]
    meta = ctx.facts.apt_metadata()
    if isinstance(meta, Unavailable):
        return [B.unavailable(meta)]
    if meta.newest_epoch is None:
        return [B.unknown("no_data", source=meta.source)]
    days = int((ctx.host.now().timestamp() - meta.newest_epoch) // 86400)
    evidence = [ev(meta.source, f"newest list: {days} day(s) old")]
    if days > 7:
        return [B.warn(days=days, evidence=evidence)]
    return [B.info(days=days, evidence=evidence)]
