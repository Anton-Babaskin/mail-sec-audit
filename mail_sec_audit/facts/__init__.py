"""Lazily collected, memoized facts. One module per source."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar, Union

from ..host import Host
from ..model import Completeness
from ..runner import Runner
from ..stacks import detect_stack
from ..stacks.base import Stack
from . import (
    accounts,
    backup,
    boot,
    disk,
    fail2ban,
    firewall,
    identity,
    keys,
    mac,
    packages,
    scans,
    schedule,
    sockets,
    sshd,
    systemd,
)
from .accounts import PasswordStatus, Sudoers
from .base import Output, Unavailable, command_lines

if TYPE_CHECKING:
    from ..cli import Config

T = TypeVar("T")

SECURITY_UNITS = (
    "fail2ban.service",
    "crowdsec.service",
    "sshguard.service",
    "dnf-automatic.timer",
    "dnf-automatic-install.timer",
    "dnf5-automatic.timer",
)


class Facts:
    def __init__(self, host: Host, runner: Runner, config: Config, completeness: Completeness) -> None:
        self.host = host
        self.runner = runner
        self.config = config
        self.completeness = completeness
        self._cache: dict[str, Any] = {}
        self.tmpdir = ""

    def memo(self, name: str, factory: Callable[[], T]) -> T:
        if name not in self._cache:
            self._cache[name] = factory()
        value: T = self._cache[name]
        return value

    def identity(self) -> identity.Identity:
        return self.memo("identity", lambda: identity.collect(self.host, self.runner))

    def stack(self) -> Stack:
        return self.memo("stack", lambda: detect_stack(self))

    def units(self, extra: tuple[str, ...] = ()) -> Union[systemd.Units, Unavailable]:
        names = tuple(dict.fromkeys(SECURITY_UNITS + tuple(s.name for s in self.stack().services) + extra))
        names = tuple(n for n in names if n.endswith((".service", ".socket", ".timer")))
        return self.memo(f"units:{','.join(names)}", lambda: systemd.units(self.host, self.runner, names))

    def failed_units(self) -> Union[systemd.Lines, Unavailable]:
        return self.memo("failed_units", lambda: systemd.failed(self.host, self.runner))

    def timers(self) -> Union[systemd.Lines, Unavailable]:
        return self.memo("timers", lambda: systemd.timers(self.host, self.runner))

    def pending_updates(self) -> Union[packages.Pending, Unavailable]:
        return self.memo("pending", lambda: packages.pending(self.runner, self.tmpdir))

    def package_manager(self) -> str | None:
        return self.memo("package_manager", lambda: packages.manager(self.runner))

    def apt_metadata(self) -> Union[packages.AptMetadata, Unavailable]:
        return self.memo("apt_metadata", lambda: packages.apt_metadata(self.host))

    def auto_updates(self) -> Union[packages.AutoUpdates, Unavailable]:
        def collect() -> Union[packages.AutoUpdates, Unavailable]:
            units = self.units()
            states = units.states if isinstance(units, systemd.Units) else {}
            return packages.auto_updates(self.host, self.runner, states)

        return self.memo("auto_updates", collect)

    def reboot(self) -> boot.RebootState:
        return self.memo("reboot", lambda: boot.collect(self.host))

    def sshd(self) -> Union[sshd.SshdConfig, sshd.NotInstalled, Unavailable]:
        return self.memo("sshd", lambda: sshd.collect(self.host, self.runner))

    def listeners(self) -> Union[sockets.Listeners, Unavailable]:
        return self.memo("listeners", lambda: sockets.collect(self.runner))

    def firewall(self) -> firewall.FirewallState:
        return self.memo("firewall", lambda: firewall.collect(self.host, self.runner))

    def fail2ban(self) -> Union[fail2ban.Fail2ban, fail2ban.NotInstalled, Unavailable]:
        return self.memo("fail2ban", lambda: fail2ban.collect(self.runner))

    def accounts(self) -> Union[accounts.Accounts, Unavailable]:
        return self.memo("accounts", lambda: accounts.passwd(self.host))

    def password_status(self) -> Union[PasswordStatus, Unavailable]:
        def collect() -> Union[PasswordStatus, Unavailable]:
            users = self.accounts()
            if isinstance(users, Unavailable):
                return users
            return accounts.password_status(self.runner, users)

        return self.memo("password_status", collect)

    def sudoers(self) -> Union[Sudoers, Unavailable]:
        return self.memo("sudoers", lambda: accounts.sudoers(self.host))

    def key_files(self) -> Union[keys.KeyFiles, Unavailable]:
        def collect() -> Union[keys.KeyFiles, Unavailable]:
            users = self.accounts()
            if isinstance(users, Unavailable):
                return users
            config = self.sshd()
            patterns: tuple[str, ...] = ()
            if isinstance(config, sshd.SshdConfig):
                patterns = tuple(p for value in config.all("authorizedkeysfile") for p in value.split())
            return keys.collect(self.host, users, patterns)

        return self.memo("key_files", collect)

    def disk_space(self) -> Union[disk.DiskUsage, Unavailable]:
        return self.memo("disk_space", lambda: disk.space(self.runner))

    def disk_inodes(self) -> Union[disk.DiskUsage, Unavailable]:
        return self.memo("disk_inodes", lambda: disk.inodes(self.runner))

    def scan(self, name: str, argv: list[str]) -> Union[scans.Scan, Unavailable]:
        return self.memo(f"scan:{name}", lambda: scans.run(self.runner, argv))

    def mac(self) -> mac.MacState:
        return self.memo("mac", lambda: mac.collect(self.host))

    def schedule(self) -> schedule.Schedule:
        return self.memo("schedule", lambda: schedule.collect(self.host))

    def backup(self) -> backup.BackupIndicators:
        return self.memo("backup", lambda: backup.collect(self.host, self.runner, self.stack().backup_hints))

    def containers(self) -> dict[str, str]:
        """Compose service name -> container state for the detected stack."""
        return self.stack().container_states

    def command(self, argv: list[str]) -> Union[Output, Unavailable]:
        return self.memo("cmd:" + " ".join(argv), lambda: command_lines(self.runner, argv))
