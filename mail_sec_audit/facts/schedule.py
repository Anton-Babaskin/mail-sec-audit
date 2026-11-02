"""cron.d entries, user crontabs from the spool and custom systemd units."""

from __future__ import annotations

from dataclasses import dataclass

from ..host import Host


@dataclass(frozen=True)
class Schedule:
    cron_d: tuple[str, ...]
    user_crontabs: tuple[tuple[str, int], ...]
    crontabs_readable: bool
    custom_units: tuple[str, ...]


def collect(host: Host) -> Schedule:
    cron_d = tuple(n for n in host.listdir("/etc/cron.d") or [] if not n.startswith("."))
    crontabs: list[tuple[str, int]] = []
    readable = True
    for spool in ("/var/spool/cron/crontabs", "/var/spool/cron"):
        if not host.is_dir(spool):
            continue
        names = host.listdir(spool)
        if names is None:
            readable = False
            continue
        for name in names:
            path = f"{spool}/{name}"
            if not host.is_regular(path):
                continue
            read = host.read_text(path, 256 * 1024)
            if not read.ok:
                readable = False
                continue
            active = [line for line in read.text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            if active:
                crontabs.append((name, len(active)))
    units: list[str] = []
    for base in ("/etc/systemd/system",):
        for name in host.listdir(base) or []:
            if name.endswith((".service", ".timer", ".socket")) and host.is_regular(f"{base}/{name}"):
                units.append(name)
    return Schedule(cron_d, tuple(crontabs), readable, tuple(sorted(units)))
