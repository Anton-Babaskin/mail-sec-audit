"""Listening sockets from ``ss``."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Union

from ..runner import Runner
from .base import Unavailable, from_result


@dataclass(frozen=True)
class Listener:
    proto: str
    address: str
    port: int
    interface: str = ""
    raw: str = ""

    @property
    def loopback(self) -> bool:
        if self.address in ("localhost",):
            return True
        try:
            ip = ipaddress.ip_address(self.address)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped.is_loopback
        return ip.is_loopback

    @property
    def wildcard(self) -> bool:
        return self.address in ("0.0.0.0", "::", "*")

    @property
    def endpoint(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class Listeners:
    items: tuple[Listener, ...]
    source: str


def parse_endpoint(text: str) -> Optional[tuple[str, int, str]]:
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit():
        return None
    interface = ""
    if host.startswith("[") and "]" in host:
        host, _, rest = host[1:].partition("]")
        interface = rest.lstrip("%")
    if "%" in host:
        host, _, interface = host.partition("%")
    return host, int(port), interface


def collect(runner: Runner) -> Union[Listeners, Unavailable]:
    result = runner.run(["ss", "-H", "-l", "-n", "-t", "-u"])
    if not result.ok:
        return from_result(result)
    items = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        parsed = parse_endpoint(fields[4])
        if parsed is None:
            continue
        host, port, interface = parsed
        items.append(Listener(fields[0], host, port, interface, line.strip()))
    return Listeners(tuple(items), f"cmd:{result.display}")
