"""SSH.ROOT_LOGIN: direct root login over SSH"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from ._ssh import sshd_or_finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("SSH.ROOT_LOGIN")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    config = sshd_or_finding(ctx, B)
    if isinstance(config, Finding):
        return [config]
    permit = config.get("permitrootlogin") or ""
    password = config.get("passwordauthentication") == "yes"
    evidence = [
        ev(
            config.source,
            f"permitrootlogin {permit}",
            f"passwordauthentication {(password and 'yes') or 'no'}",
            "Match blocks present; per-user values may differ" if config.has_match_blocks else "",
        )
    ]
    if permit == "yes" and password:
        return [B.fail("root_password", evidence=evidence)]
    if permit == "yes":
        return [B.warn("root_yes", evidence=evidence)]
    if permit in ("prohibit-password", "without-password"):
        return [B.warn("root_key", evidence=evidence)]
    if permit in ("no", "forced-commands-only"):
        return [B.ok(value=permit, evidence=evidence)]
    return [B.unknown("parse_error", source=config.source)]
