"""Host-installed MTA without a known platform (Postfix, Exim, OpenSMTPD,
Sendmail; Dovecot or Courier)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..facts import mta as mta_facts
from ..facts.systemd import Units
from .base import LogSource, Service, Stack

if TYPE_CHECKING:
    from ..facts import Facts

MAIL_FILES = ("/var/log/mail.log*", "/var/log/maillog*", "/var/log/exim4/mainlog*", "/var/log/exim/mainlog*")
JOURNAL_UNITS = (
    "postfix.service",
    "postfix@-.service",
    "exim4.service",
    "exim.service",
    "opensmtpd.service",
    "sendmail.service",
    "dovecot.service",
)
MTA_SERVICES = {
    "postfix": (("postfix.service", "postfix@-.service"), "FAIL"),
    "exim": (("exim4.service", "exim.service"), "FAIL"),
    "opensmtpd": (("opensmtpd.service",), "FAIL"),
    "sendmail": (("sendmail.service",), "WARN"),
}
IMAP_SERVICES = {"dovecot": (("dovecot.service",), "FAIL"), "courier": (("courier-imap.service",), "WARN")}


def host_services(facts: Facts, mta: str, imap: str) -> list[Service]:
    """The unit that exists for the detected MTA/IMAP server (first known name)."""
    units = facts.units_for(mta_facts.MTA_UNITS)
    services = []
    for table, key in ((MTA_SERVICES, mta), (IMAP_SERVICES, imap)):
        if key not in table:
            continue
        names, status = table[key]
        chosen = names[0]
        if isinstance(units, Units):
            known = [n for n in names if units.known(n)]
            active = [n for n in known if units.active(n)]
            chosen = (active or known or [names[0]])[0]
        services.append(Service(chosen, "systemd", True, status))
    return services


def mail_logs(extra_patterns: tuple[str, ...] = ()) -> list[LogSource]:
    return [LogSource("files", patterns=MAIL_FILES + extra_patterns), LogSource("journal", units=JOURNAL_UNITS)]


def build(facts: Facts) -> Stack:
    mta, imap = mta_facts.detect(facts.host, facts.runner, facts.units_for(mta_facts.MTA_UNITS))
    return Stack(
        name="generic",
        mta=mta,
        imap=imap,
        services=host_services(facts, mta, imap),
        mail_logs=mail_logs(),
    )
