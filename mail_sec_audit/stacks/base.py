"""Interface of a mail stack adapter.

Everything that differs between Mail-in-a-Box, Mailcow, iRedMail and a
generic host lives behind this interface; rules only call these methods.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Service:
    """A service the stack needs: a systemd unit or a compose service."""

    name: str
    kind: str  # "systemd" | "container"
    required: bool = True
    fail_status: str = "FAIL"  # status when the service is not running


@dataclass(frozen=True)
class LogSource:
    """Where mail logs come from."""

    kind: str  # "files" | "journal" | "docker"
    patterns: tuple[str, ...] = ()
    units: tuple[str, ...] = ()
    container: str = ""


@dataclass
class Stack:
    name: str
    version: Optional[str] = None
    version_source: str = ""
    mta: str = "none"
    imap: str = "none"
    services: list[Service] = field(default_factory=list)
    postfix_container: str = ""
    dovecot_container: str = ""
    compose_project: str = ""
    expected_ports: dict[int, str] = field(default_factory=dict)
    brute_force_containers: tuple[str, ...] = ()
    mail_logs: list[LogSource] = field(default_factory=list)
    mail_storage: Optional[str] = None
    detection: str = ""

    def postfix_argv(self, *args: str) -> list[str]:
        if self.postfix_container:
            return ["docker", "exec", self.postfix_container, *args]
        return list(args)

    def dovecot_argv(self, *args: str) -> list[str]:
        if self.dovecot_container:
            return ["docker", "exec", self.dovecot_container, *args]
        return list(args)
