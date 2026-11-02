"""Pending updates and automatic update settings (APT or DNF)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Union

from ..host import Host
from ..runner import Runner
from .base import Unavailable, from_result

INST_RE = re.compile(r"^Inst (\S+)(?: \[[^\]]*\])? \((.*)\)")


@dataclass(frozen=True)
class Pending:
    manager: str
    source: str
    packages: tuple[str, ...]
    security: tuple[str, ...] = ()


@dataclass(frozen=True)
class AptMetadata:
    newest_epoch: Optional[float]
    source: str = "file:/var/lib/apt/lists"


@dataclass(frozen=True)
class AutoUpdates:
    manager: str
    enabled: Optional[bool]
    source: str
    lines: tuple[str, ...] = field(default_factory=tuple)


def manager(runner: Runner) -> Optional[str]:
    if runner.which("apt-get"):
        return "apt"
    if runner.which("dnf"):
        return "dnf"
    return None


def pending(runner: Runner, tmpdir: str) -> Union[Pending, Unavailable]:
    kind = manager(runner)
    if kind == "apt":
        result = runner.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"])
        if not result.ok:
            return from_result(result)
        packages: list[str] = []
        security: list[str] = []
        for line in result.stdout.splitlines():
            match = INST_RE.match(line)
            if match:
                packages.append(match.group(1))
                if re.search(r"-security|Debian-Security", match.group(2)):
                    security.append(match.group(1))
        return Pending("apt", f"cmd:{result.display}", tuple(packages), tuple(security))
    if kind == "dnf":
        result = runner.run(["dnf", "-C", "-q", f"--setopt=logdir={tmpdir}/dnf", "check-update"])
        # check-update: 0 = nothing pending, 100 = updates listed, other = error.
        if result.returncode == 0:
            return Pending("dnf", f"cmd:{result.display}", ())
        if result.returncode != 100:
            return from_result(result)
        names = []
        for line in result.stdout.splitlines():
            if not line.strip() or line.startswith((" ", "Obsoleting", "Security:", "Last metadata")):
                continue
            if line.startswith("Obsoleting Packages"):
                break
            parts = line.split()
            if len(parts) >= 3:
                names.append(parts[0])
        return Pending("dnf", f"cmd:{result.display}", tuple(names))
    return Unavailable("missing_tool", "cmd:apt-get/dnf", tool="apt-get/dnf")


def apt_metadata(host: Host) -> Union[AptMetadata, Unavailable]:
    entries = host.listdir("/var/lib/apt/lists")
    if entries is None:
        return Unavailable("no_data", "file:/var/lib/apt/lists")
    newest: Optional[float] = None
    for name in entries:
        if name in ("partial", "lock", "auxfiles"):
            continue
        st = host.stat(f"/var/lib/apt/lists/{name}")
        if st is not None and (newest is None or st.st_mtime > newest):
            newest = st.st_mtime
    return AptMetadata(newest)


def auto_updates(host: Host, runner: Runner, units: dict[str, dict[str, str]]) -> Union[AutoUpdates, Unavailable]:
    kind = manager(runner)
    if kind == "apt":
        found: list[str] = []
        enabled: Optional[bool] = None
        for path in host.glob("/etc/apt/apt.conf.d/*"):
            read = host.read_text(path, 64 * 1024)
            for line in read.text.splitlines() if read.ok else []:
                match = re.match(r'\s*APT::Periodic::Unattended-Upgrade\s+"?(\d+)"?\s*;', line)
                if match:
                    found.append(f"{path}: {line.strip()}")
                    enabled = match.group(1) != "0"
        return AutoUpdates("apt", enabled, "file:/etc/apt/apt.conf.d", tuple(found))
    if kind == "dnf":
        active = [
            name
            for name in ("dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer")
            if units.get(name, {}).get("ActiveState") == "active"
        ]
        return AutoUpdates("dnf", bool(active), "systemd:dnf-automatic", tuple(active))
    return Unavailable("missing_tool", "cmd:apt-get/dnf", tool="apt-get/dnf")
