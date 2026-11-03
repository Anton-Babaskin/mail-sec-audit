"""FW.HOST_FIREWALL: an active default-deny host firewall"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("FW.HOST_FIREWALL")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    state = ctx.facts.firewall()
    active = state.active
    if active:
        names = ", ".join(f.name for f in active)
        return [B.ok(names=names, evidence=[ev(f.source, f"{f.name}: active") for f in active])]
    unreadable = state.unreadable
    if unreadable and unreadable[0].unavailable is not None:
        return [B.unavailable(unreadable[0].unavailable)]
    evidence = [ev(f.source, f"{f.name}: no default deny on INPUT") for f in state.frontends]
    if not state.frontends:
        return [B.fail("none", evidence=[ev("cmd:ufw/firewall-cmd/nft/iptables", "no firewall frontend found")])]
    return [B.fail(evidence=evidence)]
