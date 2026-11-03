"""PATCH.REBOOT_REQUIRED: a reboot is pending (marker or newer kernel)"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("PATCH.REBOOT_REQUIRED")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    state = ctx.facts.reboot()
    findings = []
    if state.marker:
        findings.append(
            B.warn(
                "marker",
                packages=", ".join(state.marker_packages[:10]) or "-",
                evidence=[ev("file:/var/run/reboot-required", *state.marker_packages)],
            )
        )
    if state.kernel_outdated:
        findings.append(
            B.warn(
                "kernel",
                running=state.running_kernel,
                newest=state.newest_kernel or "-",
                evidence=[ev("file:/boot", f"running {state.running_kernel}", f"newest {state.newest_kernel}")],
            )
        )
    if findings:
        return findings
    if state.kernel_outdated is None and ctx.facts.package_manager() != "apt":
        return [B.unknown("no_data", source="file:/boot")]
    return [B.ok(running=state.running_kernel, evidence=[ev("file:/boot", f"running {state.running_kernel}")])]
