"""MTA.RELAY_RESTRICTIONS: Postfix rejects relaying for unauthorised clients on port 25"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.postfix import relay_protected
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("MTA.RELAY_RESTRICTIONS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.stack().mta != "postfix":
        return [B.na("na")]
    config = ctx.facts.postfix()
    if isinstance(config, Unavailable):
        return [B.unavailable(config)]
    relay = config.effective("smtpd_relay_restrictions")
    recipient = config.effective("smtpd_recipient_restrictions")
    service = "smtpd/pass" if config.port25_command == "postscreen" else f"{config.port25_service}/inet"
    evidence = [
        ev(
            config.source,
            f"port 25: {config.port25_service} inet -> {config.port25_command} ({service})",
            f"smtpd_relay_restrictions = {relay}",
            f"smtpd_recipient_restrictions = {recipient}",
        )
    ]
    if relay_protected(relay) or relay_protected(recipient):
        return [B.ok(service=service, evidence=evidence)]
    return [B.fail(service=service, evidence=evidence)]
