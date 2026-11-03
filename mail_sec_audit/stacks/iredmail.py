"""iRedMail: Postfix and Dovecot on the host; Dovecot logs in
/var/log/dovecot/, iRedAPD in /var/log/iredapd/; amavisd on 10024/10026 with
re-injection on 10025 (a loopback hop, not an external delivery)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..facts import mta as mta_facts
from .base import Service, Stack
from .generic import host_services, mail_logs

if TYPE_CHECKING:
    from ..facts import Facts

OPTIONAL_UNITS = ("amavis.service", "iredapd.service", "clamav-daemon.service")


def build(facts: Facts) -> Stack:
    mta, imap = mta_facts.detect(facts.host, facts.runner, facts.units_for(mta_facts.MTA_UNITS))
    release = facts.host.read_text("/etc/iredmail-release", 1024)
    version = None
    if release.ok and release.text.strip():
        version = re.sub(r"[^A-Za-z0-9._ -]", "", release.text.strip().splitlines()[0])[:40]
    services = host_services(facts, mta, imap)
    services += [Service(unit, "systemd", False, "WARN") for unit in OPTIONAL_UNITS]
    return Stack(
        name="iredmail",
        version=version,
        version_source="file:/etc/iredmail-release",
        mta=mta,
        imap=imap,
        services=services,
        mail_logs=mail_logs(("/var/log/dovecot/*.log*",)),
        mail_storage="/var/vmail" if facts.host.is_dir("/var/vmail") else None,
    )
