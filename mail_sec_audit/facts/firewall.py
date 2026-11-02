"""Host firewall state.

A firewall counts as active when UFW is active, firewalld is running, or
the INPUT path drops by default (nftables base chain ``hook input`` with
policy drop or a final unconditional drop/reject; iptables INPUT policy DROP
or a final unconditional ``-j DROP/REJECT``). Chains created by Docker
(DOCKER*, FORWARD-only rules) and Fail2ban ban chains are not a firewall.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..host import Host
from ..runner import Runner
from .base import Unavailable, from_result


@dataclass(frozen=True)
class Frontend:
    name: str
    active: Optional[bool]  # None: could not be read
    source: str
    detail: str = ""
    unavailable: Optional[Unavailable] = None


@dataclass(frozen=True)
class FirewallState:
    frontends: tuple[Frontend, ...] = field(default_factory=tuple)

    @property
    def active(self) -> list[Frontend]:
        return [f for f in self.frontends if f.active]

    @property
    def unreadable(self) -> list[Frontend]:
        return [f for f in self.frontends if f.active is None]


def nft_input_drops(ruleset: str) -> bool:
    """True when an input hook base chain drops by default."""
    chain_re = re.compile(r"chain\s+(\S+)\s*\{(.*?)\n\s*\}", re.DOTALL)
    for match in chain_re.finditer(ruleset):
        name, body = match.group(1), match.group(2)
        if name.upper().startswith("DOCKER") or not re.search(r"hook\s+input\b", body):
            continue
        if re.search(r"policy\s+drop\s*;", body):
            return True
        rules = [line.strip() for line in body.splitlines() if line.strip() and not line.strip().startswith("type ")]
        if rules and re.fullmatch(r"(?:counter(?: packets \d+ bytes \d+)?\s+)?(drop|reject(?: with .*)?)", rules[-1]):
            return True
    return False


def iptables_input_drops(rules: str) -> bool:
    lines = [line.strip() for line in rules.splitlines() if line.strip()]
    if any(re.fullmatch(r"-P INPUT (DROP|REJECT)", line) for line in lines):
        return True
    input_rules = [line for line in lines if line.startswith("-A INPUT ")]
    return bool(input_rules) and re.fullmatch(r"-A INPUT -j (DROP|REJECT)(?: .*)?", input_rules[-1]) is not None


def collect(host: Host, runner: Runner) -> FirewallState:
    frontends: list[Frontend] = []
    if runner.which("ufw"):
        result = runner.run(["ufw", "status", "verbose"])
        if result.ok and re.search(r"^Status: active", result.stdout, re.MULTILINE):
            frontends.append(Frontend("ufw", True, f"cmd:{result.display}"))
        elif result.ok and re.search(r"^Status: inactive", result.stdout, re.MULTILINE):
            frontends.append(Frontend("ufw", False, f"cmd:{result.display}"))
        else:
            frontends.append(Frontend("ufw", None, f"cmd:{result.display}", unavailable=from_result(result)))
    if runner.which("firewall-cmd"):
        result = runner.run(["firewall-cmd", "--state"])
        text = (result.stdout + result.stderr).strip()
        if text == "running":
            frontends.append(Frontend("firewalld", True, f"cmd:{result.display}"))
        elif text == "not running":
            frontends.append(Frontend("firewalld", False, f"cmd:{result.display}"))
        else:
            frontends.append(Frontend("firewalld", None, f"cmd:{result.display}", unavailable=from_result(result)))
    if runner.which("nft"):
        result = runner.run(["nft", "list", "ruleset"])
        if result.ok:
            frontends.append(Frontend("nftables", nft_input_drops(result.stdout), f"cmd:{result.display}"))
        else:
            frontends.append(Frontend("nftables", None, f"cmd:{result.display}", unavailable=from_result(result)))
    # Legacy iptables only when its tables are already loaded: listing would
    # otherwise autoload iptable_filter.
    for program, names in (("iptables", "/proc/net/ip_tables_names"), ("ip6tables", "/proc/net/ip6_tables_names")):
        tables = host.read_text(names, 4096)
        if not tables.ok or not tables.text.strip() or runner.which(program) is None:
            continue
        result = runner.run([program, "-S"])
        if result.ok:
            frontends.append(Frontend(program, iptables_input_drops(result.stdout), f"cmd:{result.display}"))
        else:
            frontends.append(Frontend(program, None, f"cmd:{result.display}", unavailable=from_result(result)))
    return FirewallState(tuple(frontends))
