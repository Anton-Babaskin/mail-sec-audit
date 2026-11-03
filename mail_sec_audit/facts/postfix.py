"""Effective Postfix settings: main.cf values plus master.cf overrides.

The restrictions that apply to mail arriving on port 25 come from the
``smtpd`` behind it: the ``smtp/inet`` service, or ``smtpd/pass`` when
port 25 runs postscreen (Mailcow). ``-o`` overrides of that service win
over main.cf.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Union

from ..runner import Runner
from ..stacks.base import Stack
from .base import Unavailable, from_result

MAIN_PARAMS = (
    "smtpd_relay_restrictions",
    "smtpd_recipient_restrictions",
    "mynetworks",
    "mynetworks_style",
    "virtual_mailbox_base",
    "mail_version",
)


@dataclass(frozen=True)
class PostfixConfig:
    main: dict[str, str]
    overrides: dict[tuple[str, str], dict[str, str]]
    port25_service: str
    port25_command: str
    source: str

    def effective(self, name: str) -> str:
        service = ("smtpd", "pass") if self.port25_command == "postscreen" else (self.port25_service, "inet")
        value = self.overrides.get(service, {}).get(name)
        return value if value is not None else self.main.get(name, "")


def _name_values(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        name, sep, value = line.partition(" = ")
        if sep:
            values[name.strip()] = value.strip()
        elif line.strip().endswith(" ="):
            values[line.strip()[:-2].strip()] = ""
    return values


def collect(runner: Runner, stack: Stack) -> Union[PostfixConfig, Unavailable]:
    main = runner.run(stack.postfix_argv("postconf", "-x", *MAIN_PARAMS))
    if not main.ok:
        return from_result(main)
    values = _name_values(main.stdout)
    overrides: dict[tuple[str, str], dict[str, str]] = {}
    master_p = runner.run(stack.postfix_argv("postconf", "-x", "-P"))
    if master_p.ok:
        for line in master_p.stdout.splitlines():
            key, sep, value = line.partition(" = ")
            parts = key.strip().split("/")
            if sep and len(parts) == 3:
                overrides.setdefault((parts[0], parts[1]), {})[parts[2]] = value.strip()
    master_m = runner.run(stack.postfix_argv("postconf", "-M"))
    service, command = "smtp", "smtpd"
    if master_m.ok:
        for line in master_m.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 8 and fields[1] == "inet" and re.fullmatch(r"(?:.*:)?(?:smtp|25)", fields[0]):
                service, command = fields[0], fields[7]
                break
    # Expand $name references left in overrides (postconf -x expands main.cf only).
    for params in overrides.values():
        for name, value in list(params.items()):
            if value.startswith("$") and re.fullmatch(r"\$\{?[a-z0-9_]+\}?", value):
                ref = value.strip("${}")
                looked = runner.run(stack.postfix_argv("postconf", "-x", "-h", ref))
                params[name] = looked.stdout.strip() if looked.ok else value
    return PostfixConfig(values, overrides, service, command, f"cmd:{main.display}")


def tokens(value: str) -> list[str]:
    return [t for t in re.split(r"[\s,]+", value.strip()) if t]


def relay_protected(value: str) -> Optional[bool]:
    """True: a reject/defer for unauthorised destinations comes before any
    unconditional permit. False: an unconditional permit comes first.
    None: neither (the list allows by falling through)."""
    for token in tokens(value):
        lowered = token.lower()
        if lowered in ("reject_unauth_destination", "defer_unauth_destination", "reject", "defer"):
            return True
        if lowered == "permit":
            return False
    return None
