"""Private report files and the single-instance lock.

A new report is opened with ``O_CREAT|O_EXCL|O_NOFOLLOW`` and mode 0600 and
written through that descriptor, so the path cannot be swapped between the
check and the write. Appending requires an existing regular file owned by
the effective user, with one link and no group/other write permission.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Optional


class ReportError(Exception):
    def __init__(self, key: str, **params: str) -> None:
        super().__init__(key)
        self.key = key
        self.params = params


class LockBusy(Exception):
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.path = path


@dataclass
class ReportTarget:
    path: str
    fd: int
    created: bool = False

    def write(self, text: str) -> None:
        data = text.encode("utf-8")
        try:
            while data:
                written = os.write(self.fd, data)
                data = data[written:]
        except OSError as exc:
            raise ReportError("report.error.write", path=self.path, detail=exc.strerror or str(exc)) from None

    def discard(self) -> None:
        """Remove a report this run created and never completed."""
        try:
            info = os.fstat(self.fd)
            current = os.lstat(self.path)
            if self.created and (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino):
                os.unlink(self.path)
        except OSError:
            pass
        self.close()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            os.close(self.fd)


def open_report(path: str, *, append: bool, euid: Optional[int] = None) -> ReportTarget:
    euid = os.geteuid() if euid is None else euid
    parent = os.path.dirname(path) or "."
    try:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    except OSError:
        raise ReportError("report.error.parent", path=parent) from None
    if os.path.islink(path):
        raise ReportError("report.error.symlink", path=path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if append:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | nofollow | cloexec | os.O_NONBLOCK)
        except FileNotFoundError:
            raise ReportError("report.error.append_missing", path=path) from None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ReportError("report.error.symlink", path=path) from None
            raise ReportError("report.error.append_unsafe", path=path, detail=exc.strerror or str(exc)) from None
        info = os.fstat(fd)
        problem = None
        if not stat.S_ISREG(info.st_mode):
            problem = "not a regular file"
        elif info.st_uid != euid:
            problem = "owned by another user"
        elif info.st_nlink != 1:
            problem = "has several hard links"
        elif info.st_mode & 0o022:
            problem = "writable by group or others"
        if problem:
            os.close(fd)
            if problem == "not a regular file":
                raise ReportError("report.error.append_missing", path=path)
            raise ReportError("report.error.append_unsafe", path=path, detail=problem)
        os.set_blocking(fd, True)
        return ReportTarget(path, fd)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec, 0o600)
    except FileExistsError:
        raise ReportError("report.error.exists", path=path) from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ReportError("report.error.symlink", path=path) from None
        raise ReportError("report.error.create", path=path, detail=exc.strerror or str(exc)) from None
    os.fchmod(fd, 0o600)
    return ReportTarget(path, fd, created=True)


def default_lock_path(euid: int, env: dict[str, str]) -> str:
    if euid == 0:
        return "/run/mail-sec-audit.lock"
    runtime = env.get("XDG_RUNTIME_DIR", "")
    if runtime.startswith("/") and os.path.isdir(runtime):
        return os.path.join(runtime, "mail-sec-audit.lock")
    return os.path.join("/tmp", f"mail-sec-audit-{euid}.lock")  # noqa: S108 - checked below


@contextlib.contextmanager
def single_instance(path: str) -> Iterator[None]:
    """Hold an exclusive flock for the duration of the audit."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        raise LockBusy(path) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise LockBusy(path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise LockBusy(path) from None
        yield
    finally:
        os.close(fd)
