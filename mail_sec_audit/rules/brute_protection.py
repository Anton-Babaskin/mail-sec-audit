"""BRUTE.PROTECTION: some brute-force protection is active"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.fail2ban import Fail2ban
from ..facts.systemd import Units
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("BRUTE.PROTECTION")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    providers = []
    evidence = []
    unknown = None
    f2b = ctx.facts.fail2ban()
    if isinstance(f2b, Fail2ban) and f2b.responding:
        providers.append("fail2ban")
        evidence.append(ev(f2b.source, "fail2ban: pong"))
    elif isinstance(f2b, Unavailable):
        unknown = f2b
    units = ctx.facts.units()
    if isinstance(units, Units):
        for unit, name in (("crowdsec.service", "crowdsec"), ("sshguard.service", "sshguard")):
            if units.active(unit):
                providers.append(name)
                evidence.append(ev(units.source, f"{unit}: active"))
    for name, state in ctx.facts.containers().items():
        if ctx.stack and name in ctx.stack.brute_force_containers and state == "running":
            providers.append(name)
            evidence.append(ev("cmd:docker ps", f"{name}: running"))
    if providers:
        return [B.ok(names=", ".join(providers), evidence=evidence)]
    if unknown is not None:
        return [B.unavailable(unknown)]
    return [B.warn(evidence=evidence or [ev("cmd:fail2ban-client/systemctl", "no provider found")])]
