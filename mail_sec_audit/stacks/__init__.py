"""Mail stack detection. Order: --platform, Mailcow containers,
/etc/iredmail-release, Mail-in-a-Box markers, generic host."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..facts import docker as docker_facts
from . import generic, iredmail, mailcow, mailinabox
from .base import Stack

if TYPE_CHECKING:
    from ..facts import Facts


def detect_stack(facts: Facts) -> Stack:
    platform = facts.config.platform
    host, runner = facts.host, facts.runner
    if platform == "auto":
        if runner.which("docker") and docker_facts.service_container(runner, "postfix-mailcow"):
            platform = "mailcow"
        elif host.exists("/etc/iredmail-release"):
            platform = "iredmail"
        elif any(
            host.exists(p)
            for p in ("/etc/mailinabox.conf", "/usr/local/lib/mailinabox", "/home/user-data/mail/mailboxes")
        ):
            platform = "mailinabox"
        else:
            platform = "generic"
        detection = "auto"
    else:
        detection = "cli"
    builders = {
        "mailcow": mailcow.build,
        "iredmail": iredmail.build,
        "mailinabox": mailinabox.build,
        "generic": generic.build,
    }
    stack = builders[platform](facts)
    stack.detection = detection
    return stack
