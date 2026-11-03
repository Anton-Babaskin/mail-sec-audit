"""MAC.FRAMEWORK: AppArmor or SELinux enforcement"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("MAC.FRAMEWORK")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    state = ctx.facts.mac()
    if state.selinux == "enforcing":
        return [B.ok("selinux", evidence=[ev("file:/sys/fs/selinux/enforce", "1")])]
    if state.selinux in ("permissive", "disabled"):
        return [B.warn("selinux_off", mode=state.selinux, evidence=[ev("file:/sys/fs/selinux/enforce", state.selinux)])]
    if state.apparmor:
        profiles = state.apparmor_profiles
        detail = f"enforce={profiles[0]} complain={profiles[1]}" if profiles else "profiles not readable"
        return [
            B.ok("apparmor", detail=detail, evidence=[ev("file:/sys/module/apparmor/parameters/enabled", "Y", detail)])
        ]
    return [B.info("none", evidence=[ev("file:/sys", "no AppArmor or SELinux enforcement detected")])]
