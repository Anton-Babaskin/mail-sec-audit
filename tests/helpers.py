"""Test doubles: a fake runner that enforces the real allowlist, fixture
file trees and a one-call scenario runner."""

from __future__ import annotations

import contextlib
import datetime as dt
import os
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Optional, Union

from mail_sec_audit import cli
from mail_sec_audit.app import build_report
from mail_sec_audit.host import Host
from mail_sec_audit.i18n import Translator
from mail_sec_audit.model import Finding, Report, Status
from mail_sec_audit.runner import CommandResult, ExecState, ForbiddenCommand, Policy, StreamHandle

NOW = dt.datetime(2026, 11, 2, 12, 0, 0, tzinfo=dt.timezone.utc)


@dataclass(frozen=True)
class Resp:
    out: str = ""
    rc: int = 0
    err: str = ""
    state: Optional[ExecState] = None

    def result(self, argv: Sequence[str]) -> CommandResult:
        state = self.state or (ExecState.OK if self.rc == 0 else ExecState.NONZERO)
        return CommandResult(tuple(argv), state, None if state is ExecState.MISSING else self.rc, self.out, self.err)


MISSING = Resp(state=ExecState.MISSING)
TIMEOUT = Resp(state=ExecState.TIMEOUT, rc=-9)
DENIED = Resp(rc=1, err="Permission denied")

Response = Union[Resp, Callable[[Sequence[str]], Resp]]
Responses = Mapping[tuple[str, ...], Response]


class FakeRunner:
    """Answers allowlisted commands from a table; unknown commands are missing tools."""

    def __init__(self, responses: Optional[Responses] = None, *, prefix: bool = True) -> None:
        self.policy = Policy()
        self.responses = {tuple(k): v for k, v in (responses or {}).items()}
        self.prefix = prefix
        self.calls: list[tuple[str, ...]] = []
        self.inputs: list[Optional[str]] = []

    def which(self, program: str) -> Optional[str]:
        """A program exists when any response for it is not MISSING."""
        for key, spec in self.responses.items():
            if key[0] == program and spec is not MISSING:
                return f"/usr/bin/{program}"
        return None

    def _lookup(self, argv: tuple[str, ...]) -> Resp:
        if argv in self.responses:
            spec = self.responses[argv]
        elif self.prefix:
            matches = [k for k in self.responses if argv[: len(k)] == k]
            if not matches:
                return MISSING
            spec = self.responses[max(matches, key=len)]
        else:
            return MISSING
        return spec(argv) if callable(spec) else spec

    def run(self, argv: Sequence[str], *, input_text: Optional[str] = None) -> CommandResult:
        rule = self.policy.check(argv)
        if input_text is not None and not rule.stdin:
            raise ForbiddenCommand(f"{argv[0]} does not take stdin")
        argv_t = tuple(argv)
        self.calls.append(argv_t)
        self.inputs.append(input_text)
        return self._lookup(argv_t).result(argv_t)

    @contextlib.contextmanager
    def stream(self, argv: Sequence[str]) -> Iterator[StreamHandle]:
        result = self.run(argv)
        lines = iter(result.stdout.splitlines()) if result.state is ExecState.OK else iter(())
        yield StreamHandle(lines, CommandResult(result.argv, result.state, result.returncode, "", result.stderr))

    def called(self, *prefix: str) -> bool:
        return any(call[: len(prefix)] == prefix for call in self.calls)


def write_tree(root: str, files: Mapping[str, Union[str, bytes]]) -> None:
    for path, content in files.items():
        real = os.path.join(root, path.lstrip("/"))
        os.makedirs(os.path.dirname(real), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(real, mode) as handle:
            handle.write(content)


def config(*args: str, env: Optional[Mapping[str, str]] = None) -> cli.Config:
    parsed = cli.parse(["--lang", "en", *args], env or {}, NOW)
    assert isinstance(parsed, cli.Config)
    return parsed


@dataclass
class Scenario:
    report: Report
    runner: FakeRunner
    durations: dict[str, int]

    def get(self, finding_id: str) -> Finding:
        found = [f for f in self.report.findings if f.id == finding_id]
        assert found, f"{finding_id} not in {[f.id for f in self.report.findings]}"
        return found[0]

    def status(self, finding_id: str) -> Status:
        return self.get(finding_id).status

    def ids(self, prefix: str = "") -> list[str]:
        return [f.id for f in self.report.findings if f.id.startswith(prefix)]


def run_scenario(
    files: Optional[Mapping[str, Union[str, bytes]]] = None,
    responses: Optional[Responses] = None,
    args: Sequence[str] = (),
    *,
    euid: int = 0,
    denied: frozenset[str] = frozenset(),
    env: Optional[Mapping[str, str]] = None,
    modes: Optional[Mapping[str, int]] = None,
    mtimes: Optional[Mapping[str, float]] = None,
) -> Scenario:
    with tempfile.TemporaryDirectory(prefix="msa-fixture.") as root:
        write_tree(root, files or {})
        for path, mode in (modes or {}).items():
            os.chmod(os.path.join(root, path.lstrip("/")), mode)
        for path, mtime in (mtimes or {}).items():
            os.utime(os.path.join(root, path.lstrip("/")), (mtime, mtime))
        host = Host(root, denied=denied, now=NOW, euid=euid, env=env or {})
        runner = FakeRunner(responses)
        tmpdir = os.path.join(root, "tmp", "mail-sec-audit.test")
        os.makedirs(tmpdir, exist_ok=True)
        report, durations = build_report(config(*args), host, runner, Translator("en", strict=True), tmpdir)
        # Render every message in both languages strictly: a missing key or
        # placeholder fails the test.
        for lang in ("en", "ru"):
            t = Translator(lang, strict=True)
            for finding in report.findings:
                t(finding.key, finding.params)
                if finding.next_step:
                    t(finding.next_step)
        return Scenario(report, runner, durations)
