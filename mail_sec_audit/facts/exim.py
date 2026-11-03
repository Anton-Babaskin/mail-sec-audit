"""Exim relay options from ``exim -bP``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from ..runner import Runner
from .base import Unavailable, from_result

OPTIONS = ("primary_hostname", "local_domains", "relay_to_domains", "relay_from_hosts")


@dataclass(frozen=True)
class EximOptions:
    values: dict[str, str]
    source: str


def collect(runner: Runner) -> Union[EximOptions, Unavailable]:
    program = "exim4" if runner.which("exim4") else "exim"
    result = runner.run([program, "-bP", *OPTIONS])
    if not result.ok:
        return from_result(result)
    values = {}
    for line in result.stdout.splitlines():
        name, sep, value = line.partition("=")
        if sep:
            values[name.strip()] = value.strip()
    return EximOptions(values, f"cmd:{result.display}")
