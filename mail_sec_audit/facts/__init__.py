"""Lazily collected, memoized facts. One module per source."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, Optional, TypeVar, Union

from ..host import Host
from ..model import Completeness
from ..runner import Runner
from ..stacks.base import Stack
from . import (
    accounts,
    backup,
    boot,
    disk,
    dns,
    dovecot,
    exim,
    fail2ban,
    firewall,
    identity,
    keys,
    mac,
    maillog,
    opensmtpd,
    packages,
    postfix,
    queue,
    scans,
    schedule,
    sendmail,
    sockets,
    sshd,
    systemd,
    tls,
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
        self.prober: tls.Prober = tls.SocketProber()

    def memo(self, name: str, factory: Callable[[], T]) -> T:
        if name not in self._cache:
            self._cache[name] = factory()
        value: T = self._cache[name]
        return value

    # --- host -------------------------------------------------------------------
    def identity(self) -> identity.Identity:
        return self.memo("identity", lambda: identity.collect(self.host, self.runner))

    def stack(self) -> Stack:
        from ..stacks import detect_stack  # the stack adapters use facts themselves

        return self.memo("stack", lambda: detect_stack(self))

    def units_for(self, names: Sequence[str]) -> Union[systemd.Units, Unavailable]:
        key = ",".join(names)
        return self.memo(f"units:{key}", lambda: systemd.units(self.host, self.runner, list(names)))

    def units(self) -> Union[systemd.Units, Unavailable]:
        names = SECURITY_UNITS + tuple(s.name for s in self.stack().services if s.kind == "systemd")
        return self.units_for(tuple(dict.fromkeys(names)))

    def failed_units(self) -> Union[systemd.Lines, Unavailable]:
        return self.memo("failed_units", lambda: systemd.failed(self.host, self.runner))

    def timers(self) -> Union[systemd.Lines, Unavailable]:
        return self.memo("timers", lambda: systemd.timers(self.host, self.runner))

    def pending_updates(self) -> Union[packages.Pending, Unavailable]:
        return self.memo("pending", lambda: packages.pending(self.runner, self.tmpdir))

    def package_manager(self) -> Optional[str]:
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

    # --- mail ---------------------------------------------------------------------
    def mail_logs(self) -> maillog.LogResult:
        return self.memo(
            "mail_logs",
            lambda: maillog.mail(
                self.host,
                self.runner,
                self.stack(),
                self.config.period_from,
                self.config.period_to,
                self.config.mail_top,
                self.completeness,
            ),
        )

    def ssh_logs(self) -> maillog.LogResult:
        return self.memo(
            "ssh_logs",
            lambda: maillog.ssh(
                self.host, self.runner, self.config.period_from, self.config.period_to, self.completeness
            ),
        )

    def postfix(self) -> Union[postfix.PostfixConfig, Unavailable]:
        return self.memo("postfix", lambda: postfix.collect(self.runner, self.stack()))

    def dovecot(self) -> dovecot.DovecotSettings:
        return self.memo("dovecot", lambda: dovecot.collect(self.runner, self.stack()))

    def queue(self) -> Union[queue.QueueSize, Unavailable]:
        return self.memo("queue", lambda: queue.collect(self.host, self.runner, self.stack()))

    def exim(self) -> Union[exim.EximOptions, Unavailable]:
        return self.memo("exim", lambda: exim.collect(self.runner))

    def opensmtpd(self) -> Union[opensmtpd.SmtpdConf, Unavailable]:
        return self.memo("opensmtpd", lambda: opensmtpd.collect(self.host))

    def sendmail(self) -> Union[sendmail.SendmailMc, Unavailable]:
        return self.memo("sendmail", lambda: sendmail.collect(self.host))

    def dns(self, rtype: str, name: str) -> Union[dns.Answer, Unavailable]:
        def collect() -> Union[dns.Answer, Unavailable]:
            if self.runner.which("dig"):
                self.completeness.external_probes.append(f"dns:{rtype} {name}")
            return dns.query(self.runner, rtype, name)

        return self.memo(f"dns:{rtype}:{name}", collect)

    def tls_targets(self) -> Union[list[tls.Target], Unavailable]:
        listeners = self.listeners()
        if isinstance(listeners, Unavailable):
            return listeners
        return tls.targets(listeners)

    def server_name(self) -> str:
        return self.config.mail_host or self.identity().fqdn

    def handshake(self, target: tls.Target) -> tls.Handshake:
        def collect() -> tls.Handshake:
            mode = f"/{target.starttls}" if target.starttls else ""
            self.completeness.local_probes.append(f"tls:{target.label}{mode}")
            return self.prober.handshake(target, self.server_name())

        return self.memo(f"tls:{target.label}", collect)

    def legacy_tls(self, target: tls.Target, version: str) -> str:
        def collect() -> str:
            self.completeness.local_probes.append(f"{version}:{target.label}")
            return self.prober.legacy(target, version)

        return self.memo(f"legacy:{version}:{target.label}", collect)

    def certificate(self, target: tls.Target) -> Union[tls.Certificate, Unavailable]:
        def collect() -> Union[tls.Certificate, Unavailable]:
            handshake = self.handshake(target)
            if not handshake.der:
                return Unavailable("no_data", f"tls:{target.label}")
            return tls.parse_certificate(self.runner, handshake.der, self.server_name())

        return self.memo(f"cert:{target.label}", collect)
