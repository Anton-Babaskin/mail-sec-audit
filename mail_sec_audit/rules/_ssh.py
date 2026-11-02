"""Shared sshd lookup for SSH.* rules."""

from __future__ import annotations

from typing import Union

from ..facts.base import Unavailable
from ..facts.sshd import NotInstalled, SshdConfig
from ..model import Finding
from .base import Builder, Ctx


def sshd_or_finding(ctx: Ctx, builder: Builder) -> Union[SshdConfig, Finding]:
    config = ctx.facts.sshd()
    if isinstance(config, NotInstalled):
        return builder.na("na", key="ssh.na.not_installed")
    if isinstance(config, Unavailable):
        return builder.unavailable(config)
    return config
