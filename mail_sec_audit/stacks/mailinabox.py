"""Mail-in-a-Box.

- ``/usr/local/bin/mailinabox`` is ``cd <checkout>; source setup/start.sh``
  and ignores arguments: it is never executed. The version comes from
  ``git describe`` in the checkout named on its ``cd`` line.
- Dovecot writes to ``/var/log/mail.log`` directly, without a host name.
- Dovecot quota-status listens on 12340 on all addresses (closed by ufw).
- Local delivery goes through LMTP to spampd on 127.0.0.1:10025.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..facts import mta as mta_facts
from .base import Service, Stack
from .generic import host_services, mail_logs

if TYPE_CHECKING:
    from ..facts import Facts

WRAPPER = "/usr/local/bin/mailinabox"
OPTIONAL_UNITS = ("opendkim.service", "postgrey.service", "spampd.service", "nsd.service", "nginx.service")


def setup_dir(facts: Facts) -> str:
    read = facts.host.read_text(WRAPPER, 4096)
    if not read.ok:
        return ""
    match = re.search(r"^cd (/\S*)\s*$", read.text, re.MULTILINE)
    if not match or not facts.host.exists(match.group(1) + "/.git"):
        return ""
    return match.group(1)


def storage_root(facts: Facts) -> str:
    read = facts.host.read_text("/etc/mailinabox.conf", 64 * 1024)
    match = re.search(r"^STORAGE_ROOT=(/\S+)$", read.text, re.MULTILINE) if read.ok else None
    return match.group(1) if match else "/home/user-data"


def build(facts: Facts) -> Stack:
    mta, imap = mta_facts.detect(facts.host, facts.runner, facts.units_for(mta_facts.MTA_UNITS))
    mta = "postfix" if mta == "none" else mta
    imap = "dovecot" if imap == "none" else imap
    version = None
    source = ""
    checkout = setup_dir(facts)
    if checkout:
        result = facts.runner.run(
            ["git", "-c", "core.fsmonitor=false", "--no-pager", "--no-optional-locks", "-C", checkout]
            + ["describe", "--always", "--abbrev=0"]
        )
        if result.ok and result.stdout.strip():
            version = re.sub(r"[^A-Za-z0-9._-]", "", result.stdout.strip().splitlines()[0])
            source = f"cmd:{result.display}"
    root = storage_root(facts)
    services = host_services(facts, mta, imap)
    services += [Service(unit, "systemd", False, "WARN") for unit in OPTIONAL_UNITS]
    return Stack(
        name="mailinabox",
        version=version,
        version_source=source,
        mta=mta,
        imap=imap,
        services=services,
        expected_ports={12340: "Dovecot quota-status", 53: "nsd"},
        mail_logs=mail_logs(),
        mail_storage=f"{root}/mail/mailboxes",
        backup_hints=(f"{root}/backup/encrypted", f"{root}/backup"),
    )
