"""Mailcow (dockerized).

Postfix and Dovecot run in compose services ``postfix-mailcow`` and
``dovecot-mailcow``; configuration and queue commands go through
``docker exec`` (checked against the allowlist), logs through ``docker
logs``. Port 25 is postscreen with ``smtpd pass`` behind it.
``netfilter-mailcow`` is the brute-force protection. The Mailcow config file
holds passwords and is never read; ``update.sh`` is never run.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..facts import docker as docker_facts
from .base import LogSource, Service, Stack

if TYPE_CHECKING:
    from ..facts import Facts

SERVICES = ("postfix-mailcow", "dovecot-mailcow", "netfilter-mailcow")


def build(facts: Facts) -> Stack:
    runner = facts.runner
    containers = {name: docker_facts.service_container(runner, name) for name in SERVICES}
    postfix = containers["postfix-mailcow"]
    dovecot = containers["dovecot-mailcow"]
    states = {name: c.state for name, c in containers.items() if c is not None}
    project = docker_facts.inspect(runner, postfix.id, docker_facts.INSPECT_PROJECT) if postfix else ""
    version, source = None, ""
    if postfix:
        workdir = docker_facts.inspect(runner, postfix.id, docker_facts.INSPECT_WORKDIR)
        if re.fullmatch(r"/[A-Za-z0-9_./@+-]{0,255}", workdir or ""):
            result = runner.run(
                ["git", "-c", "core.fsmonitor=false", "--no-pager", "--no-optional-locks", "-C", workdir]
                + ["describe", "--tags", "--always"]
            )
            if result.ok and result.stdout.strip():
                version = re.sub(r"[^A-Za-z0-9._-]", "", result.stdout.strip().splitlines()[0])
                source = f"cmd:{result.display}"
    storage = docker_facts.inspect(runner, dovecot.id, docker_facts.INSPECT_VMAIL) if dovecot else ""
    logs = [LogSource("docker", container=c.id) for c in (postfix, dovecot) if c is not None]
    return Stack(
        name="mailcow",
        version=version,
        version_source=source,
        mta="postfix",
        imap="dovecot",
        services=[Service("postfix-mailcow", "container"), Service("dovecot-mailcow", "container")],
        postfix_container=postfix.id if postfix else "",
        dovecot_container=dovecot.id if dovecot else "",
        compose_project=project if re.fullmatch(r"[a-z0-9_-]{1,64}", project or "") else "",
        brute_force_containers=("netfilter-mailcow",),
        mail_logs=logs,
        mail_storage=storage or None,
        container_states=states,
    )
