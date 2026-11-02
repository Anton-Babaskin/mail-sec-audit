"""Read-only access to the host file system, clock, identity and environment.

Tests construct ``Host`` with ``root`` pointing at a fixture tree, a fixed
clock, an euid and a set of paths that should behave as unreadable.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import errno
import glob
import gzip
import os
import stat as stat_mod
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import IO, Optional, cast


@dataclass(frozen=True)
class FileRead:
    path: str
    state: str  # ok | missing | denied | error | truncated
    text: str = ""
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.state in ("ok", "truncated")


class Host:
    def __init__(
        self,
        root: str = "/",
        *,
        denied: frozenset[str] = frozenset(),
        now: Optional[dt.datetime] = None,
        euid: Optional[int] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.root = os.path.abspath(root)
        self.denied = denied
        self._now = now
        self.euid = os.geteuid() if euid is None else euid
        self.env = dict(os.environ if env is None else env)

    def now(self) -> dt.datetime:
        return self._now if self._now is not None else dt.datetime.now().astimezone()

    def path(self, path: str) -> str:
        if not path.startswith("/"):
            raise ValueError(f"absolute path required: {path}")
        if self.root == "/":
            return path
        return os.path.join(self.root, path.lstrip("/"))

    def unroot(self, real: str) -> str:
        if self.root == "/":
            return real
        rel = os.path.relpath(real, self.root)
        return "/" + ("" if rel == "." else rel)

    def _check_denied(self, path: str) -> None:
        for denied in self.denied:
            if path == denied or path.startswith(denied.rstrip("/") + "/"):
                raise PermissionError(errno.EACCES, "Permission denied", path)

    def read_text(self, path: str, limit: int = 1024 * 1024) -> FileRead:
        try:
            self._check_denied(path)
            with open(self.path(path), "rb") as handle:
                data = handle.read(limit + 1)
        except FileNotFoundError:
            return FileRead(path, "missing")
        except NotADirectoryError:
            return FileRead(path, "missing")
        except PermissionError:
            return FileRead(path, "denied")
        except OSError as exc:
            return FileRead(path, "error", detail=exc.strerror or str(exc))
        state = "truncated" if len(data) > limit else "ok"
        return FileRead(path, state, data[:limit].decode("utf-8", errors="replace"))

    def exists(self, path: str) -> bool:
        return os.path.lexists(self.path(path))

    def is_file(self, path: str) -> bool:
        return os.path.isfile(self.path(path))

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(self.path(path))

    def stat(self, path: str) -> Optional[os.stat_result]:
        try:
            self._check_denied(path)
            return os.stat(self.path(path))
        except OSError:
            return None

    def lstat(self, path: str) -> Optional[os.stat_result]:
        try:
            return os.lstat(self.path(path))
        except OSError:
            return None

    def is_regular(self, path: str) -> bool:
        st = self.lstat(path)
        return st is not None and stat_mod.S_ISREG(st.st_mode)

    def listdir(self, path: str) -> Optional[list[str]]:
        try:
            self._check_denied(path)
            return sorted(os.listdir(self.path(path)))
        except OSError:
            return None

    def glob(self, pattern: str) -> list[str]:
        return sorted(self.unroot(p) for p in glob.glob(self.path(pattern)))

    def readable(self, path: str) -> bool:
        try:
            self._check_denied(path)
        except PermissionError:
            return False
        return os.access(self.path(path), os.R_OK)

    @contextlib.contextmanager
    def open_lines(self, path: str) -> Iterator[Iterator[str]]:
        """Stream decoded lines; ``.gz`` files are decompressed on the fly.

        Raises ``PermissionError`` or ``FileNotFoundError`` like ``open``.
        """
        self._check_denied(path)
        real = self.path(path)
        handle = cast(IO[bytes], gzip.open(real, "rb") if path.endswith(".gz") else open(real, "rb"))  # noqa: SIM115
        try:
            yield (raw.decode("utf-8", errors="replace").rstrip("\r\n") for raw in handle)
        finally:
            handle.close()
