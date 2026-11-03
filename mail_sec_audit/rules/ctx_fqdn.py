"""CTX.FQDN: the mail host name is fully qualified."""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("CTX.FQDN")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    identity = ctx.facts.identity()
    name = ctx.config.mail_host or identity.fqdn
    source = "cli:--hostname" if ctx.config.mail_host else identity.fqdn_source
    evidence = [ev(source, name)]
    labels = name.rstrip(".").split(".")
    if len(labels) >= 2 and all(labels) and name != "localhost.localdomain":
        return [B.ok(name=name, evidence=evidence)]
    return [B.warn(name=name, evidence=evidence)]
