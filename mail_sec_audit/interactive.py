"""--interactive: the only mode that changes the system (Fail2ban ban/unban).

Every action is shown in full and needs a typed confirmation (BAN/UNBAN).
Addresses are refused when they are malformed, not globally routable, owned
by this host, or belong to any established SSH session (not only the one
in SSH_CONNECTION, which sudo usually drops).
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import sys
from collections.abc import Iterator
from typing import TYPE_CHECKING, Callable, Optional

from .runner import Runner

if TYPE_CHECKING:
    from .cli import Config
    from .host import Host
    from .i18n import Translator
    from .model import Report

JAIL_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


@contextlib.contextmanager
def mutations(runner: Runner) -> Iterator[None]:
    runner.policy.allow_mutating = True
    try:
        yield
    finally:
        runner.policy.allow_mutating = False


def normalize_ip(text: str) -> Optional[str]:
    text = text.strip().strip("[]")
    if text.startswith("::ffff:") and "." in text:
        text = text[7:]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def jails(runner: Runner) -> list[str]:
    result = runner.run(["fail2ban-client", "status"])
    match = re.search(r"Jail list:\s*(.*)", result.stdout) if result.ok else None
    if not match:
        return []
    return [j.strip() for j in match.group(1).split(",") if JAIL_RE.fullmatch(j.strip())]


def ssh_ports(runner: Runner) -> set[int]:
    result = runner.run(["sshd", "-T"])
    ports = {int(m) for m in re.findall(r"^port (\d+)$", result.stdout, re.MULTILINE)} if result.ok else set()
    return ports or {22}


def protected_addresses(host: Host, runner: Runner) -> set[str]:
    protected: set[str] = set()
    for name in ("SSH_CONNECTION", "SSH_CLIENT"):
        first = host.env.get(name, "").split(" ", 1)[0]
        ip = normalize_ip(first) if first else None
        if ip:
            protected.add(ip)
    ports = ssh_ports(runner)
    sockets = runner.run(["ss", "-H", "-t", "-n", "state", "established"])
    for line in sockets.stdout.splitlines() if sockets.ok else []:
        fields = line.split()
        if len(fields) < 4:
            continue
        local, peer = fields[2], fields[3]
        local_port = local.rsplit(":", 1)[-1]
        if local_port.isdigit() and int(local_port) in ports:
            ip = normalize_ip(peer.rsplit(":", 1)[0])
            if ip:
                protected.add(ip)
    own = runner.run(["hostname", "-I"])
    for token in own.stdout.split() if own.ok else []:
        ip = normalize_ip(token)
        if ip:
            protected.add(ip)
    return protected


def is_global(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


def refusal(ip: Optional[str], protected: set[str], routable: Callable[[str], bool] = is_global) -> Optional[str]:
    """Return the catalog key explaining why ``ip`` must not be banned."""
    if ip is None:
        return "interactive.refuse.invalid"
    if not routable(ip):
        return "interactive.refuse.not_global"
    if ip in protected:
        return "interactive.refuse.protected"
    return None


def candidates(report: Report) -> list[tuple[str, int]]:
    totals: dict[str, int] = {}
    stats = report.auth_statistics or {}
    for key in ("ssh_failed", "mail_failed"):
        for ip, count in stats.get(key, []):
            totals[str(ip)] = totals.get(str(ip), 0) + int(count)
    return sorted(totals.items(), key=lambda item: (-item[1], item[0]))[:15]


def menu(
    config: Config,
    host: Host,
    runner: Runner,
    t: Translator,
    report: Report,
    ask: Callable[[str], str] = input,
    say: Callable[[str], None] = print,
    tty: Optional[bool] = None,
    routable: Callable[[str], bool] = is_global,
) -> None:
    if not (sys.stdin.isatty() and sys.stdout.isatty() if tty is None else tty):
        say(t("interactive.no_tty"))
        return
    if host.euid != 0:
        say(t("interactive.need_root"))
        return
    ping = runner.run(["fail2ban-client", "ping"])
    if not ping.ok or "pong" not in ping.stdout.lower():
        say(t("interactive.unavailable"))
        return
    protected = protected_addresses(host, runner)
    user = host.env.get("SUDO_USER", "root")
    while True:
        say("")
        say(t("interactive.title"))
        for item in ("ban", "unban", "show", "exit"):
            say(t(f"interactive.menu.{item}"))
        action = ask(t("interactive.prompt.action")).strip()
        if action in ("0", ""):
            return
        if action == "1":
            _ban(runner, t, report, protected, user, ask, say, routable)
        elif action == "2":
            _unban(runner, t, user, ask, say)
        elif action == "3":
            _show(runner, t, say)
        else:
            say(t("interactive.unknown_choice"))


def _ban(
    runner: Runner,
    t: Translator,
    report: Report,
    protected: set[str],
    user: str,
    ask: Callable[[str], str],
    say: Callable[[str], None],
    routable: Callable[[str], bool],
) -> None:
    options = candidates(report)
    say(t("interactive.candidates"))
    for index, (address, count) in enumerate(options, 1):
        say(f"  {index:2d}) {count:<7} {address}")
    say(t("interactive.manual"))
    choice = ask(t("interactive.prompt.choice")).strip()
    if choice in ("0", ""):
        return
    raw: str
    if choice.lower() == "m":
        raw = ask("IP: ")
    elif choice.isdigit() and 1 <= int(choice) <= len(options):
        raw = options[int(choice) - 1][0]
    else:
        say(t("interactive.refuse.invalid", {"ip": choice}))
        return
    ip = normalize_ip(raw)
    why = refusal(ip, protected, routable)
    if why or ip is None:
        say(t(why or "interactive.refuse.invalid", {"ip": raw.strip()}))
        return
    available = jails(runner)
    if not available:
        say(t("interactive.no_jails"))
        return
    for index, jail in enumerate(available, 1):
        say(f"  {index:2d}) {jail}")
    pick = ask(t("interactive.prompt.jail")).strip()
    if not pick.isdigit() or not 1 <= int(pick) <= len(available):
        say(t("interactive.cancelled"))
        return
    jail = available[int(pick) - 1]
    say(t("interactive.will_run", {"command": f"fail2ban-client set {jail} banip {ip}"}))
    if ask(t("interactive.confirm", {"word": "BAN"})).strip() != "BAN":
        say(t("interactive.cancelled"))
        return
    with mutations(runner):
        result = runner.run(["fail2ban-client", "set", jail, "banip", ip])
        if result.ok:
            runner.run(["logger", "-t", "mail-sec-audit", "--", f"manual ban ip={ip} jail={jail} user={user}"])
    say(t("interactive.banned" if result.ok else "interactive.failed", {"ip": ip, "jail": jail}))


def _unban(runner: Runner, t: Translator, user: str, ask: Callable[[str], str], say: Callable[[str], None]) -> None:
    ip = normalize_ip(ask(t("interactive.prompt.unban")))
    if ip is None:
        say(t("interactive.refuse.invalid", {"ip": "-"}))
        return
    say(t("interactive.will_run", {"command": f"fail2ban-client unban {ip}"}))
    if ask(t("interactive.confirm", {"word": "UNBAN"})).strip() != "UNBAN":
        say(t("interactive.cancelled"))
        return
    with mutations(runner):
        result = runner.run(["fail2ban-client", "unban", ip])
        if not result.ok:
            for jail in jails(runner):
                runner.run(["fail2ban-client", "set", jail, "unbanip", ip])
        runner.run(["logger", "-t", "mail-sec-audit", "--", f"manual unban ip={ip} user={user}"])
    say(t("interactive.unbanned", {"ip": ip}))


def _show(runner: Runner, t: Translator, say: Callable[[str], None]) -> None:
    any_banned = False
    for jail in jails(runner):
        result = runner.run(["fail2ban-client", "status", jail])
        match = re.search(r"Banned IP list:\s*(.*)", result.stdout) if result.ok else None
        if match and match.group(1).strip():
            any_banned = True
            say(f"  {jail:<24} {match.group(1).strip()}")
    if not any_banned:
        say(t("interactive.none_banned"))
