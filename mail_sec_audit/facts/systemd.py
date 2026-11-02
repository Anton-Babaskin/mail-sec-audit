"""systemd unit states, failed units and timers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Union

from ..host import Host
from ..runner import Runner
from .base import Unavailable, from_result


@dataclass(frozen=True)
class Units:
    states: dict[str, dict[str, str]]
    source: str

    def known(self, unit: str) -> bool:
        state = self.states.get(unit, {})
        return state.get("LoadState", "not-found") not in ("not-found", "")

    def active(self, unit: str) -> bool:
        return self.states.get(unit, {}).get("ActiveState") == "active"


@dataclass(frozen=True)
class Lines:
    lines: tuple[str, ...]
    source: str


def available(host: Host) -> bool:
    return host.is_dir("/run/systemd/system")


def units(host: Host, runner: Runner, names: Sequence[str]) -> Union[Units, Unavailable]:
    if not available(host):
        return Unavailable("not_applicable", "file:/run/systemd/system", "systemd is not running")
    result = runner.run(["systemctl", "show", "--property=Id,LoadState,ActiveState,UnitFileState", "--", *names])
    if not result.ok:
        return from_result(result)
    states: dict[str, dict[str, str]] = {}
    for block in result.stdout.strip().split("\n\n"):
        props = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        unit = props.get("Id")
        if unit:
            states[unit] = props
    return Units(states, f"cmd:{result.display}")


def failed(host: Host, runner: Runner) -> Union[Lines, Unavailable]:
    if not available(host):
        return Unavailable("not_applicable", "file:/run/systemd/system", "systemd is not running")
    result = runner.run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
    if not result.ok:
        return from_result(result)
    return Lines(tuple(line.strip() for line in result.stdout.splitlines() if line.strip()), f"cmd:{result.display}")


def timers(host: Host, runner: Runner) -> Union[Lines, Unavailable]:
    if not available(host):
        return Unavailable("not_applicable", "file:/run/systemd/system", "systemd is not running")
    result = runner.run(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"])
    if not result.ok:
        return from_result(result)
    return Lines(tuple(line.strip() for line in result.stdout.splitlines() if line.strip()), f"cmd:{result.display}")
