"""AppArmor and SELinux state from /sys, without running utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..host import Host


@dataclass(frozen=True)
class MacState:
    apparmor: Optional[bool]
    apparmor_profiles: Optional[tuple[int, int]]  # enforce, complain
    selinux: Optional[str]  # enforcing | permissive | disabled | None


def collect(host: Host) -> MacState:
    aa = host.read_text("/sys/module/apparmor/parameters/enabled", 16)
    apparmor = aa.text.strip().upper().startswith("Y") if aa.ok else None
    profiles = host.read_text("/sys/kernel/security/apparmor/profiles", 4 * 1024 * 1024)
    counts = None
    if profiles.ok:
        counts = (profiles.text.count("(enforce)"), profiles.text.count("(complain)"))
    enforce = host.read_text("/sys/fs/selinux/enforce", 16)
    selinux: Optional[str] = None
    if enforce.ok:
        selinux = "enforcing" if enforce.text.strip() == "1" else "permissive"
    elif host.exists("/etc/selinux/config"):
        selinux = "disabled"
    return MacState(apparmor, counts, selinux)
