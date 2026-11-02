"""Reboot indicators: Debian marker and running vs newest installed kernel."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

from ..host import Host


@dataclass(frozen=True)
class RebootState:
    marker: bool
    marker_packages: tuple[str, ...]
    running_kernel: str
    newest_kernel: Optional[str]

    @property
    def kernel_outdated(self) -> Optional[bool]:
        if self.newest_kernel is None:
            return None
        return natural_key(self.newest_kernel) > natural_key(self.running_kernel)


def natural_key(version: str) -> tuple[tuple[int, str], ...]:
    return tuple((int(part), "") if part.isdigit() else (-1, part) for part in re.split(r"(\d+)", version) if part)


def collect(host: Host, running: Optional[str] = None) -> RebootState:
    marker = host.exists("/var/run/reboot-required") or host.exists("/run/reboot-required")
    pkgs = host.read_text("/var/run/reboot-required.pkgs", 64 * 1024)
    packages = tuple(p for p in pkgs.text.split() if p) if pkgs.ok else ()
    running = running or os.uname().release
    kernels = [name[len("vmlinuz-") :] for name in host.listdir("/boot") or [] if name.startswith("vmlinuz-")]
    # Only compare kernels of the same flavour (e.g. -generic, -amd64, .el9_4.x86_64).
    flavour = re.sub(r"^[\d.\-_]+", "", running)
    same = [k for k in kernels if re.sub(r"^[\d.\-_]+", "", k) == flavour] or kernels
    newest = max(same, key=natural_key) if same else None
    return RebootState(marker, packages, running, newest)
