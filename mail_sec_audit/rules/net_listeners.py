"""NET.LISTENERS: non-loopback listeners outside the expected port list"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.sshd import SshdConfig
from ..model import Finding
from .base import Builder, Check, Ctx, ev

BASE_PORTS = (22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 4190)
# DHCP and DHCPv6 clients bind these UDP ports; they are not services.
UDP_CLIENT_PORTS = (68, 546)


CHECK = Check("NET.LISTENERS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    listeners = ctx.facts.listeners()
    if isinstance(listeners, Unavailable):
        return [B.unavailable(listeners)]
    expected = set(BASE_PORTS) | set(ctx.config.allowed_ports) | set(ctx.stack.expected_ports if ctx.stack else {})
    config = ctx.facts.sshd()
    if isinstance(config, SshdConfig):
        expected |= {int(p) for p in config.all("port") if p.isdigit()}
    findings = []
    seen = set()
    for item in listeners.items:
        if item.loopback or (item.proto == "udp" and item.port in UDP_CLIENT_PORTS):
            continue
        subject = f"{item.proto}/{item.endpoint}"
        if item.port in expected or subject in seen:
            continue
        seen.add(subject)
        findings.append(
            B.warn(subject=subject, proto=item.proto, endpoint=item.endpoint, evidence=[ev(listeners.source, item.raw)])
        )
    if findings:
        return findings
    public = [f"{i.proto}/{i.endpoint}" for i in listeners.items if not i.loopback]
    return [B.ok(count=len(public), evidence=[ev(listeners.source, *public)])]
