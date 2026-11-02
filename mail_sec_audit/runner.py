"""The only place that starts external processes.

Every command is matched against ``RULES`` before it runs. A rule fixes the
program, the shape of its arguments, a timeout, an output limit and the reason
the call has no side effects. Commands are executed as an argv list without a
shell, with a fixed PATH, ``LC_ALL=C`` and stdin from ``/dev/null``.

Programs in ``FORBIDDEN_PROGRAMS`` are refused with any arguments:
``/usr/local/bin/mailinabox`` sources ``setup/start.sh`` and ignores its
arguments, Mailcow ``update.sh`` pulls images and recreates containers.
"""

from __future__ import annotations

import contextlib
import enum
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Optional, Protocol, Union

FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
FORBIDDEN_PROGRAMS = frozenset({"mailinabox", "update.sh"})
MIB = 1024 * 1024


class ForbiddenCommand(Exception):
    """Raised when a command does not match the allowlist."""


class ExecState(str, enum.Enum):
    OK = "ok"
    NONZERO = "nonzero"
    MISSING = "missing"
    TIMEOUT = "timeout"
    TRUNCATED = "truncated"
    ERROR = "error"


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    state: ExecState
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.state is ExecState.OK

    @property
    def display(self) -> str:
        return " ".join(self.argv)


# --- argument matchers -------------------------------------------------------


@dataclass(frozen=True)
class Lit:
    value: str

    def match(self, arg: str) -> bool:
        return arg == self.value


@dataclass(frozen=True)
class Re:
    pattern: str

    def match(self, arg: str) -> bool:
        return re.fullmatch(self.pattern, arg) is not None


@dataclass(frozen=True)
class OneOf:
    values: frozenset[str]

    def match(self, arg: str) -> bool:
        return arg in self.values


Matcher = Union[Lit, Re, OneOf]

UNIT = Re(r"[A-Za-z0-9@_.:-]{1,128}\.(service|socket|timer)")
JAIL = Re(r"[A-Za-z0-9_.-]{1,64}")
IP = Re(r"[0-9A-Fa-f:.]{2,45}")
POSTFIX_PARAM = Re(r"[a-z0-9_]{1,64}")
DNS_NAME = Re(r"(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9])?\.?")
CONTAINER = Re(r"[0-9a-f]{12,64}|[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
ABS_DIR = Re(r"/[A-Za-z0-9_./@+-]{0,255}")
EPOCH = Re(r"[0-9]{9,11}")
JOURNAL_TIME = Re(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}")
COMPOSE_SERVICE = Re(r"label=com\.docker\.compose\.service=[a-z0-9_-]{1,64}")
COMPOSE_PROJECT = Re(r"label=com\.docker\.compose\.project=[a-z0-9_-]{1,64}")
SYSLOG_TAG_MESSAGE = Re(r"[^\x00-\x1f\x7f]{1,400}")

DOVECOT_PARAMS = frozenset(
    {"ssl", "ssl_min_protocol", "disable_plaintext_auth", "auth_allow_cleartext", "auth_mechanisms"}
)
EXIM_OPTIONS = frozenset(
    {
        "primary_hostname",
        "local_domains",
        "relay_to_domains",
        "relay_from_hosts",
        "auth_advertise_hosts",
        "tls_advertise_hosts",
    }
)
DOCKER_INSPECT_FORMATS = frozenset(
    {
        "{{.Config.Image}}",
        '{{index .Config.Labels "com.docker.compose.project"}}',
        '{{index .Config.Labels "com.docker.compose.project.working_dir"}}',
        '{{range .Mounts}}{{if eq .Destination "/var/vmail"}}{{.Source}}{{end}}{{end}}',
    }
)
DF_EXCLUDES = ("-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay")


@dataclass(frozen=True)
class Rule:
    """One allowed command shape.

    ``args`` must match the arguments after the program one by one. ``rest``
    matches every further argument; without ``rest`` no further arguments are
    allowed. ``why`` documents why the call does not change the system.
    """

    program: str
    args: tuple[Matcher, ...]
    why: str
    rest: Optional[Matcher] = None
    max_rest: int = 0
    timeout: float = 20.0
    max_bytes: int = 4 * MIB
    container: bool = False
    mutating: bool = False
    stdin: bool = False

    def matches(self, argv: Sequence[str]) -> bool:
        if not argv or argv[0] != self.program:
            return False
        args = argv[1:]
        if len(args) < len(self.args):
            return False
        if not all(m.match(a) for m, a in zip(self.args, args)):
            return False
        extra = args[len(self.args) :]
        if not extra:
            return True
        if self.rest is None or len(extra) > self.max_rest:
            return False
        return all(self.rest.match(a) for a in extra)


def L(*values: str) -> tuple[Lit, ...]:
    return tuple(Lit(v) for v in values)


RULES: tuple[Rule, ...] = (
    Rule("hostname", L("-f"), "prints the host name", timeout=8),
    Rule("hostname", L("-I"), "prints configured addresses", timeout=8),
    Rule("sshd", L("-T"), "prints the effective sshd configuration; extended test mode, no daemon start"),
    Rule("ss", L("-H", "-l", "-n", "-t", "-u"), "lists listening sockets from the kernel"),
    Rule("ss", L("-H", "-t", "-n", "state", "established"), "lists established TCP sockets from the kernel"),
    Rule(
        "systemctl",
        L("show", "--property=Id,LoadState,ActiveState,UnitFileState", "--"),
        "reads unit properties from systemd",
        rest=UNIT,
        max_rest=64,
    ),
    Rule("systemctl", L("--failed", "--no-legend", "--plain", "--no-pager"), "lists failed units"),
    Rule("systemctl", L("list-timers", "--all", "--no-legend", "--no-pager"), "lists timers"),
    Rule(
        "journalctl",
        L("--no-pager", "-q", "-o", "short-iso-precise", "--since") + (JOURNAL_TIME, Lit("--until"), JOURNAL_TIME),
        "reads the journal for the audit period",
        rest=Re(r"-u|[A-Za-z0-9@_.:-]{1,128}\.service"),
        max_rest=32,
        timeout=180,
        max_bytes=1024 * MIB,
    ),
    Rule("ufw", L("status", "verbose"), "prints firewall status; ufw status changes nothing"),
    Rule("firewall-cmd", L("--state"), "queries firewalld over D-Bus"),
    Rule("firewall-cmd", L("--list-all"), "queries firewalld over D-Bus"),
    Rule("nft", L("list", "ruleset"), "lists nftables rules; may autoload nf_tables without adding rules"),
    Rule("iptables", L("-S"), "lists rules; called only when ip_tables is already loaded"),
    Rule("ip6tables", L("-S"), "lists rules; called only when ip6_tables is already loaded"),
    Rule("fail2ban-client", L("ping"), "asks the server to answer"),
    Rule("fail2ban-client", L("status"), "lists jails"),
    Rule("fail2ban-client", L("status") + (JAIL,), "prints jail counters"),
    Rule("fail2ban-client", L("set") + (JAIL, Lit("banip"), IP), "bans an address", mutating=True),
    Rule("fail2ban-client", L("set") + (JAIL, Lit("unbanip"), IP), "unbans an address", mutating=True),
    Rule("fail2ban-client", L("unban") + (IP,), "unbans an address in all jails", mutating=True),
    Rule(
        "logger",
        L("-t", "mail-sec-audit", "--"),
        "records an interactive ban/unban in syslog",
        rest=SYSLOG_TAG_MESSAGE,
        max_rest=1,
        mutating=True,
    ),
    Rule(
        "docker",
        L("ps", "-a", "--no-trunc", "--filter") + (COMPOSE_SERVICE,) + L("--format", "{{.ID}}\t{{.State}}"),
        "lists containers",
    ),
    Rule(
        "docker",
        L("ps", "-a", "--filter") + (COMPOSE_PROJECT,) + L("--format", "{{.Names}}\t{{.State}}\t{{.Status}}"),
        "lists containers of one compose project",
    ),
    Rule("docker", L("inspect", "--format") + (OneOf(DOCKER_INSPECT_FORMATS), CONTAINER), "reads container metadata"),
    Rule(
        "docker",
        L("logs", "--timestamps", "--since") + (EPOCH, Lit("--until"), EPOCH, CONTAINER),
        "reads container logs for the audit period",
        timeout=180,
        max_bytes=1024 * MIB,
    ),
    Rule("postconf", L("-h"), "prints main.cf values", rest=POSTFIX_PARAM, max_rest=32, container=True),
    Rule("postconf", L("-x", "-h"), "prints expanded main.cf values", rest=POSTFIX_PARAM, max_rest=32, container=True),
    Rule("postconf", L("-x", "-P"), "prints master.cf -o overrides", container=True),
    Rule("doveconf", L("-h") + (OneOf(DOVECOT_PARAMS),), "prints one Dovecot setting; never -x", container=True),
    Rule("postqueue", L("-j"), "prints the queue as JSON lines (showq); read-only", container=True),
    Rule("postqueue", L("-p"), "prints the queue (mailq); read-only", container=True),
    Rule("exim4", L("-bP"), "prints Exim options", rest=OneOf(EXIM_OPTIONS), max_rest=8),
    Rule("exim", L("-bP"), "prints Exim options", rest=OneOf(EXIM_OPTIONS), max_rest=8),
    Rule("exim4", L("-bpc"), "counts queued messages"),
    Rule("exim", L("-bpc"), "counts queued messages"),
    Rule("mailq", (), "prints the Sendmail queue; used only when /etc/mail/sendmail.cf exists"),
    Rule(
        "apt-get",
        L("-s", "-o", "Debug::NoLocking=1", "dist-upgrade"),
        "simulation only; no locks, no downloads, no changes",
        timeout=120,
    ),
    Rule(
        "dnf",
        L("-C", "-q")
        + (Re(r"--setopt=logdir=/[A-Za-z0-9_./-]{1,200}/mail-sec-audit\.[A-Za-z0-9_]+/dnf"),)
        + L("check-update"),
        "cache-only query; logs go to the private temporary directory",
        timeout=120,
    ),
    Rule(
        "dig",
        L("+time=3", "+tries=2", "+noall", "+comments", "+answer")
        + (OneOf(frozenset({"MX", "A", "AAAA", "TXT"})), DNS_NAME),
        "DNS query; only with an explicit --domain",
        timeout=20,
    ),
    Rule("dig", L("+time=3", "+tries=2", "+noall", "+comments", "+answer", "-x") + (IP,), "reverse DNS query"),
    Rule(
        "openssl",
        L("x509", "-noout", "-subject", "-issuer", "-startdate", "-enddate", "-checkhost") + (DNS_NAME,),
        "parses a certificate from stdin",
        stdin=True,
        timeout=10,
    ),
    Rule(
        "git",
        L("-c", "core.fsmonitor=false", "--no-pager", "--no-optional-locks", "-C")
        + (ABS_DIR,)
        + L("describe", "--always", "--abbrev=0"),
        "reads the nearest annotated tag; no index refresh, no hooks",
        timeout=10,
    ),
    Rule(
        "git",
        L("-c", "core.fsmonitor=false", "--no-pager", "--no-optional-locks", "-C")
        + (ABS_DIR,)
        + L("describe", "--tags", "--always"),
        "reads the nearest tag; no index refresh, no hooks",
        timeout=10,
    ),
    Rule("passwd", L("-S", "-a"), "prints password status letters, not hashes"),
    Rule("passwd", L("-S") + (Re(r"[a-z_][a-z0-9_.-]{0,31}\$?"),), "prints password status letters, not hashes"),
    Rule(
        "find",
        L("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt")
        + L("-xdev", "-type", "f", "-perm", "-4000", "-print0"),
        "lists SUID files",
        timeout=120,
    ),
    Rule(
        "find",
        L("/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "-xdev", "-type", "f", "-perm", "-4000", "-print0"),
        "lists SUID files in user and temporary directories",
        timeout=120,
    ),
    Rule(
        "find",
        L("/etc", "/usr/local", "/opt", "-xdev", "(", "-type", "f", "-o", "-type", "d", ")")
        + L("-perm", "-0002", "-printf", "%y %m %p\\0"),
        "lists world-writable paths",
        timeout=120,
    ),
    Rule(
        "find",
        L("/", "-xdev", "(", "-path", "/proc", "-o", "-path", "/var/lib/docker", "-o", "-path")
        + L("/var/lib/containers", ")", "-prune", "-o", "-type", "f", "(", "-perm", "-4000", "-o")
        + L("(", "-perm", "-2000", "-perm", "/0111", ")", ")", "-print0"),
        "--deep: lists SUID and executable SGID files",
        timeout=600,
        max_bytes=16 * MIB,
    ),
    Rule(
        "find",
        L("/usr/local/bin", "/usr/local/sbin", "/opt", "/etc/systemd/system", "/etc/cron.d")
        + L("-xdev", "-type", "f", "-mtime", "-30", "-printf", "%T@ %m %u:%g %p\\0"),
        "--deep: lists recently modified files",
        timeout=120,
    ),
    Rule("df", L("-P", "-B1") + L(*DF_EXCLUDES), "reads filesystem usage"),
    Rule("df", L("-P", "-i") + L(*DF_EXCLUDES), "reads inode usage"),
    Rule("df", L("-P", "-B1") + (ABS_DIR,), "reads usage of one filesystem"),
    Rule("du", L("-s", "-x", "-B1") + (ABS_DIR,), "--deep: sums mailbox storage", timeout=300),
    Rule("last", L("-a", "-w", "-n", "20"), "reads wtmp"),
    Rule("lastb", L("-a", "-w", "-n", "20"), "reads btmp"),
    Rule("debsums", L("-s"), "--deep: verifies package checksums", timeout=900),
    Rule("rpm", L("-Va", "--noscripts"), "--deep: verifies packages without running %verifyscript", timeout=900),
)


def _program_name(arg: str) -> str:
    return arg.rsplit("/", 1)[-1]


@dataclass
class Policy:
    rules: tuple[Rule, ...] = RULES
    allow_mutating: bool = False

    def check(self, argv: Sequence[str]) -> Rule:
        """Return the matching rule or raise ``ForbiddenCommand``."""
        argv = tuple(argv)
        if not argv:
            raise ForbiddenCommand("empty command")
        if any("\x00" in a for a in argv):
            raise ForbiddenCommand("NUL byte in argument")
        if _program_name(argv[0]) in FORBIDDEN_PROGRAMS:
            raise ForbiddenCommand(f"{argv[0]} is forbidden with any arguments")
        if "/" in argv[0]:
            raise ForbiddenCommand("programs are resolved from the fixed PATH only")
        if argv[0] == "docker" and len(argv) > 1 and argv[1] == "exec":
            return self._check_docker_exec(argv)
        for rule in self.rules:
            if rule.matches(argv):
                if rule.mutating and not self.allow_mutating:
                    raise ForbiddenCommand(f"{' '.join(argv)} changes the system; interactive mode only")
                return rule
        raise ForbiddenCommand(f"not in allowlist: {' '.join(argv)}")

    def _check_docker_exec(self, argv: tuple[str, ...]) -> Rule:
        # docker exec CONTAINER COMMAND...; options such as -i, -t, -u, -e,
        # --privileged or -w are never allowed.
        if len(argv) < 4 or argv[2].startswith("-") or not CONTAINER.match(argv[2]):
            raise ForbiddenCommand("docker exec needs a container and a command, without options")
        inner = argv[3:]
        if _program_name(inner[0]) in FORBIDDEN_PROGRAMS or "/" in inner[0]:
            raise ForbiddenCommand(f"{inner[0]} is forbidden inside containers")
        for rule in self.rules:
            if rule.container and not rule.mutating and rule.matches(inner):
                return Rule(
                    "docker",
                    (),
                    f"docker exec: {rule.why}",
                    timeout=rule.timeout + 10,
                    max_bytes=rule.max_bytes,
                )
        raise ForbiddenCommand(f"not allowed inside containers: {' '.join(inner)}")


# --- execution -----------------------------------------------------------------


class Runner(Protocol):
    policy: Policy

    def run(self, argv: Sequence[str], *, input_text: Optional[str] = None) -> CommandResult: ...

    def stream(self, argv: Sequence[str]) -> contextlib.AbstractContextManager[StreamHandle]: ...

    def which(self, program: str) -> Optional[str]: ...


@dataclass
class StreamHandle:
    """Lines of a streamed command; ``result`` is final after iteration."""

    lines: Iterator[str]
    result: CommandResult = field(default_factory=lambda: CommandResult((), ExecState.ERROR))


def child_env() -> dict[str, str]:
    env = {
        "PATH": FIXED_PATH,
        "LC_ALL": "C",
        "LANG": "C",
        "NO_COLOR": "1",
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGER": "",
        "PAGER": "cat",
    }
    for name in ("HOME", "TZ", "DOCKER_HOST"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _permission_text(text: str) -> bool:
    lowered = text.lower()
    return any(
        marker in lowered
        for marker in (
            "permission denied",
            "operation not permitted",
            "must be root",
            "need to be root",
            "access denied",
            "not authorized",
            "you must be root",
            "interactive authentication required",
        )
    )


class SystemRunner:
    """Runs allowlisted commands on the real host."""

    def __init__(self, policy: Optional[Policy] = None) -> None:
        self.policy = policy or Policy()
        self.history: list[CommandResult] = []
        self._active: set[subprocess.Popen[bytes]] = set()

    def kill_all(self) -> None:
        """Kill running children; used when the audit is stopped by a signal."""
        for proc in list(self._active):
            _kill(proc)

    def which(self, program: str) -> Optional[str]:
        return shutil.which(program, path=FIXED_PATH)

    def _prepare(self, argv: Sequence[str]) -> tuple[Rule, Optional[list[str]]]:
        rule = self.policy.check(argv)
        path = self.which(argv[0])
        return rule, ([path, *argv[1:]] if path else None)

    def run(self, argv: Sequence[str], *, input_text: Optional[str] = None) -> CommandResult:
        rule, resolved = self._prepare(argv)
        argv_t = tuple(argv)
        if input_text is not None and not rule.stdin:
            raise ForbiddenCommand(f"{argv_t[0]} does not take stdin")
        if resolved is None:
            result = CommandResult(argv_t, ExecState.MISSING)
            self.history.append(result)
            return result
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                resolved,
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_env(),
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            result = CommandResult(argv_t, ExecState.ERROR, stderr=str(exc))
            self.history.append(result)
            return result
        self._active.add(proc)

        out = bytearray()
        err = bytearray()
        over_limit = threading.Event()

        def drain(stream: Optional[object], buf: bytearray, limit: int) -> None:
            if stream is None:
                return
            reader = stream.read  # type: ignore[attr-defined]
            while True:
                chunk = reader(65536)
                if not chunk:
                    return
                if len(buf) + len(chunk) > limit:
                    buf.extend(chunk[: max(0, limit - len(buf))])
                    over_limit.set()
                    _kill(proc)
                    return
                buf.extend(chunk)

        threads = [
            threading.Thread(target=drain, args=(proc.stdout, out, rule.max_bytes), daemon=True),
            threading.Thread(target=drain, args=(proc.stderr, err, MIB), daemon=True),
        ]
        for thread in threads:
            thread.start()
        if input_text is not None and proc.stdin is not None:
            with contextlib.suppress(BrokenPipeError):
                proc.stdin.write(input_text.encode("utf-8"))
            proc.stdin.close()
        timed_out = False
        try:
            proc.wait(timeout=rule.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill(proc)
            proc.wait()
        for thread in threads:
            thread.join(timeout=5)
        self._active.discard(proc)
        _close_pipes(proc)
        duration = int((time.monotonic() - started) * 1000)
        state = ExecState.OK
        if timed_out:
            state = ExecState.TIMEOUT
        elif over_limit.is_set():
            state = ExecState.TRUNCATED
        elif proc.returncode != 0:
            state = ExecState.NONZERO
        result = CommandResult(argv_t, state, proc.returncode, _decode(bytes(out)), _decode(bytes(err)), duration)
        self.history.append(result)
        return result

    @contextlib.contextmanager
    def stream(self, argv: Sequence[str]) -> Iterator[StreamHandle]:
        rule, resolved = self._prepare(argv)
        argv_t = tuple(argv)
        if resolved is None:
            handle = StreamHandle(iter(()), CommandResult(argv_t, ExecState.MISSING))
            self.history.append(handle.result)
            yield handle
            return
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                resolved,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_env(),
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            handle = StreamHandle(iter(()), CommandResult(argv_t, ExecState.ERROR, stderr=str(exc)))
            self.history.append(handle.result)
            yield handle
            return
        self._active.add(proc)

        timed_out = threading.Event()

        def expire() -> None:
            timed_out.set()
            _kill(proc)

        timer = threading.Timer(rule.timeout, expire)
        timer.daemon = True
        timer.start()
        err = bytearray()

        def drain_err() -> None:
            if proc.stderr is None:
                return
            while True:
                chunk = proc.stderr.read(65536)
                if not chunk:
                    return
                if len(err) < MIB:
                    err.extend(chunk[: MIB - len(err)])

        err_thread = threading.Thread(target=drain_err, daemon=True)
        err_thread.start()
        state: dict[str, bool] = {"truncated": False}

        def lines() -> Iterator[str]:
            if proc.stdout is None:
                return
            total = 0
            for raw in proc.stdout:
                total += len(raw)
                if total > rule.max_bytes:
                    state["truncated"] = True
                    _kill(proc)
                    return
                yield _decode(raw).rstrip("\n")

        handle = StreamHandle(lines())
        try:
            yield handle
        finally:
            if proc.poll() is None:
                _kill(proc)
            proc.wait()
            self._active.discard(proc)
            timer.cancel()
            err_thread.join(timeout=5)
            _close_pipes(proc)
            exec_state = ExecState.OK
            if timed_out.is_set():
                exec_state = ExecState.TIMEOUT
            elif state["truncated"]:
                exec_state = ExecState.TRUNCATED
            elif proc.returncode not in (0, -signal.SIGKILL):
                exec_state = ExecState.NONZERO
            handle.result = CommandResult(
                argv_t,
                exec_state,
                proc.returncode,
                "",
                _decode(bytes(err)),
                int((time.monotonic() - started) * 1000),
            )
            self.history.append(handle.result)


def _close_pipes(proc: subprocess.Popen[bytes]) -> None:
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        if pipe is not None:
            with contextlib.suppress(OSError):
                pipe.close()


def _kill(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


def failure_reason(result: CommandResult) -> str:
    """Map a failed command to an UNKNOWN reason code."""
    if result.state is ExecState.MISSING:
        return "missing_tool"
    if result.state is ExecState.TIMEOUT:
        return "timeout"
    if result.state is ExecState.TRUNCATED:
        return "truncated"
    if _permission_text(result.stderr) or _permission_text(result.stdout[:2000]):
        return "permission_denied"
    return "command_failed"
