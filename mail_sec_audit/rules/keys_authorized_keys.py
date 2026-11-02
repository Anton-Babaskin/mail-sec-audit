"""KEYS.AUTHORIZED_KEYS: authorized_keys ownership and write permissions"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("KEYS.AUTHORIZED_KEYS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    files = ctx.facts.key_files()
    if isinstance(files, Unavailable):
        return [B.unavailable(files)]
    findings = []
    for item in files.items:
        line = f"{item.path} owner_uid={item.owner_uid} mode={item.mode:04o} keys={item.key_lines}"
        if item.writable_by_others or item.owner_uid not in (item.expected_uid, 0):
            findings.append(
                B.warn(
                    subject=item.path, path=item.path, mode=f"{item.mode:04o}", evidence=[ev(f"file:{item.path}", line)]
                )
            )
    if files.unreadable_homes:
        findings.append(B.unknown("permission_denied", source=f"file:{files.unreadable_homes[0]}"))
        return findings
    keys = sum(i.key_lines or 0 for i in files.items)
    lines = [f"{i.path} keys={i.key_lines}" for i in files.items]
    findings.append(
        B.info(
            files=len(files.items),
            keys=keys,
            evidence=[ev("sshd:authorizedkeysfile " + " ".join(files.patterns), *lines, limit=30)],
        )
    )
    return findings
