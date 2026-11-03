"""Host identity: names, OS release, kernel, stable host id."""

from __future__ import annotations

import hashlib
import re
import socket
from dataclasses import dataclass
from typing import Optional

from ..host import Host
from ..runner import Runner


@dataclass(frozen=True)
class Identity:
    hostname: str
    fqdn: str
    fqdn_source: str
    os_name: str
    kernel: str
    host_id: str


def _os_name(host: Host) -> str:
    read = host.read_text("/etc/os-release", 64 * 1024)
    if not read.ok:
        return "unknown"
    match = re.search(r'^PRETTY_NAME="?([^"\n]*)"?\s*$', read.text, re.MULTILINE)
    return match.group(1) if match else "unknown"


def collect(host: Host, runner: Runner) -> Identity:
    short = host.hostname()
    result = runner.run(["hostname", "-f"])
    lines = result.stdout.split() if result.ok else []
    fqdn: Optional[str] = lines[0] if lines else None
    source = "cmd:hostname -f"
    if not fqdn:
        fqdn = socket.getfqdn() or short
        source = "socket.getfqdn"
    machine_id = host.read_text("/etc/machine-id", 256)
    seed = machine_id.text.strip() if machine_id.ok and machine_id.text.strip() else fqdn
    # machine-id must not be published; derive an application-specific id.
    host_id = hashlib.sha256(f"mail-sec-audit:{seed}".encode()).hexdigest()[:16]
    system, release, machine = host.uname()
    return Identity(
        hostname=short,
        fqdn=fqdn,
        fqdn_source=source,
        os_name=_os_name(host),
        kernel=f"{system} {release} {machine}",
        host_id=host_id,
    )
