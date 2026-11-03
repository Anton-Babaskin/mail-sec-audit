"""Which MTA and IMAP/POP3 server run on a host-based stack."""

from __future__ import annotations

from typing import Union

from ..host import Host
from ..runner import Runner
from .base import Unavailable
from .systemd import Units

MTA_UNITS = (
    "postfix.service",
    "postfix@-.service",
    "exim4.service",
    "exim.service",
    "opensmtpd.service",
    "sendmail.service",
    "dovecot.service",
    "courier-imap.service",
)


def real_sendmail(host: Host) -> bool:
    """Sendmail proper, not a sendmail-compatible binary of another MTA."""
    return host.exists("/etc/mail/sendmail.cf")


def detect(host: Host, runner: Runner, units: Union[Units, Unavailable]) -> tuple[str, str]:
    def active(*names: str) -> bool:
        return isinstance(units, Units) and any(units.active(n) for n in names)

    def known(*names: str) -> bool:
        return isinstance(units, Units) and any(units.known(n) for n in names)

    if active("postfix.service", "postfix@-.service"):
        mta = "postfix"
    elif active("exim4.service", "exim.service"):
        mta = "exim"
    elif active("opensmtpd.service"):
        mta = "opensmtpd"
    elif active("sendmail.service") and real_sendmail(host):
        mta = "sendmail"
    elif runner.which("postconf") or known("postfix.service"):
        mta = "postfix"
    elif runner.which("exim4") or runner.which("exim") or known("exim4.service", "exim.service"):
        mta = "exim"
    elif runner.which("smtpctl") or known("opensmtpd.service"):
        mta = "opensmtpd"
    elif real_sendmail(host):
        mta = "sendmail"
    else:
        mta = "none"

    if active("dovecot.service"):
        imap = "dovecot"
    elif active("courier-imap.service"):
        imap = "courier"
    elif runner.which("doveconf") or known("dovecot.service"):
        imap = "dovecot"
    elif runner.which("courierauthconfig") or known("courier-imap.service"):
        imap = "courier"
    else:
        imap = "none"
    return mta, imap
