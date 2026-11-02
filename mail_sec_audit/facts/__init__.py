"""Lazily collected, memoized facts. One module per source."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar

from ..host import Host
from ..model import Completeness
from ..runner import Runner
from ..stacks import detect_stack
from ..stacks.base import Stack
from . import identity

if TYPE_CHECKING:
    from ..cli import Config

T = TypeVar("T")


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
