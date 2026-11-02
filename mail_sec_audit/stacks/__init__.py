"""Mail stack detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Stack

if TYPE_CHECKING:
    from ..facts import Facts


def detect_stack(facts: Facts) -> Stack:
    platform = facts.config.platform
    return Stack(name="generic" if platform == "auto" else platform, detection="cli" if platform != "auto" else "")
