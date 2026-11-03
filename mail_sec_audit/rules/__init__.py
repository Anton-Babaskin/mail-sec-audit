"""Rule registry. One check per module, listed explicitly in report order."""

from __future__ import annotations

import time
import traceback
from collections.abc import Sequence

from ..model import Finding, Reason
from . import (
    backup_indicators,
    brute_fail2ban,
    brute_fail2ban_jails,
    brute_protection,
    ctx_fqdn,
    ctx_privileges,
    disk_inodes,
    disk_usage,
    fw_host_firewall,
    keys_authorized_keys,
    login_recent,
    mac_failed_units,
    mac_framework,
    net_listeners,
    patch_apt_metadata_age,
    patch_auto_updates,
    patch_pending_updates,
    patch_reboot_required,
    perms_world_writable,
    pkg_integrity,
    recent_modified,
    sched_inventory,
    ssh_kbd_interactive,
    ssh_max_auth_tries,
    ssh_password_auth,
    ssh_pubkey_auth,
    ssh_root_login,
    ssh_x11_forwarding,
    suid_full_scan,
    suid_standard_paths,
    suid_unexpected_locations,
    users_empty_password,
    users_interactive_accounts,
    users_sudo_nopasswd,
    users_uid0,
)
from .base import Builder, Ctx, RuleModule

SECTIONS = (
    "CTX",
    "PATCH",
    "STACK",
    "SSH",
    "NET",
    "FW",
    "BRUTE",
    "AUTH",
    "FLOW",
    "MTA",
    "TLS",
    "DNS",
    "USERS",
    "KEYS",
    "DISK",
    "QUEUE",
    "SUID",
    "PERMS",
    "MAC",
    "SCHED",
    "BACKUP",
    "LOGIN",
    "PKG",
    "RECENT",
)

REGISTRY: tuple[RuleModule, ...] = (
    ctx_privileges,
    ctx_fqdn,
    patch_pending_updates,
    patch_apt_metadata_age,
    patch_auto_updates,
    patch_reboot_required,
    ssh_root_login,
    ssh_password_auth,
    ssh_pubkey_auth,
    ssh_kbd_interactive,
    ssh_x11_forwarding,
    ssh_max_auth_tries,
    net_listeners,
    fw_host_firewall,
    brute_protection,
    brute_fail2ban,
    brute_fail2ban_jails,
    users_uid0,
    users_empty_password,
    users_interactive_accounts,
    users_sudo_nopasswd,
    keys_authorized_keys,
    disk_usage,
    disk_inodes,
    suid_unexpected_locations,
    suid_standard_paths,
    suid_full_scan,
    perms_world_writable,
    mac_failed_units,
    mac_framework,
    sched_inventory,
    backup_indicators,
    login_recent,
    pkg_integrity,
    recent_modified,
)


def run_checks(ctx: Ctx, modules: Sequence[RuleModule] = REGISTRY) -> list[Finding]:
    """Run every applicable rule; a crashing rule becomes UNKNOWN."""
    findings: list[Finding] = []
    durations: dict[str, int] = ctx.extra.setdefault("durations", {})
    for module in modules:
        check = module.CHECK
        if check.deep and not ctx.config.deep:
            continue
        started = time.monotonic()
        try:
            findings.extend(module.run(ctx))
        except Exception as exc:  # noqa: BLE001 - one failing check must not stop the report
            frame = traceback.extract_tb(exc.__traceback__)[-1] if exc.__traceback__ else None
            where = f" at {frame.filename.rsplit('/', 1)[-1]}:{frame.lineno}" if frame else ""
            findings.append(
                Builder(check).unknown(
                    Reason.INTERNAL_ERROR, source=f"rule:{check.id}", detail=f"{type(exc).__name__}{where}"
                )
            )
        durations[check.id] = durations.get(check.id, 0) + int((time.monotonic() - started) * 1000)
    return findings
