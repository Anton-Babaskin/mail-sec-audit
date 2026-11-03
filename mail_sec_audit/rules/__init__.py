"""Rule registry. One check per module, listed explicitly in report order."""

from __future__ import annotations

import time
import traceback
from collections.abc import Sequence

from ..model import Finding, Reason
from . import (
    auth_mail_failures,
    auth_ssh_failures,
    backup_indicators,
    brute_fail2ban,
    brute_fail2ban_jails,
    brute_protection,
    ctx_fqdn,
    ctx_platform,
    ctx_privileges,
    disk_inodes,
    disk_mail_storage,
    disk_usage,
    dns_dkim,
    dns_dkim_key,
    dns_dmarc,
    dns_mta_sts,
    dns_mx,
    dns_ptr,
    dns_spf,
    dns_tls_rpt,
    flow_stats,
    fw_host_firewall,
    keys_authorized_keys,
    login_recent,
    mac_failed_units,
    mac_framework,
    mta_exim_relay_hosts,
    mta_external_test,
    mta_mynetworks,
    mta_opensmtpd_relay,
    mta_relay_restrictions,
    mta_sendmail_relay,
    net_listeners,
    patch_apt_metadata_age,
    patch_auto_updates,
    patch_pending_updates,
    patch_reboot_required,
    perms_world_writable,
    pkg_integrity,
    queue_size,
    recent_modified,
    sched_inventory,
    ssh_kbd_interactive,
    ssh_max_auth_tries,
    ssh_password_auth,
    ssh_pubkey_auth,
    ssh_root_login,
    ssh_x11_forwarding,
    stack_containers_health,
    stack_imap_detected,
    stack_mta_detected,
    stack_service,
    suid_full_scan,
    suid_standard_paths,
    suid_unexpected_locations,
    tls_cert_expiry,
    tls_cert_name,
    tls_dovecot_min_protocol,
    tls_handshake,
    tls_legacy_protocols,
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
    ctx_platform,
    patch_pending_updates,
    patch_apt_metadata_age,
    patch_auto_updates,
    patch_reboot_required,
    stack_mta_detected,
    stack_imap_detected,
    stack_service,
    stack_containers_health,
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
    auth_ssh_failures,
    auth_mail_failures,
    flow_stats,
    mta_relay_restrictions,
    mta_mynetworks,
    mta_exim_relay_hosts,
    mta_opensmtpd_relay,
    mta_sendmail_relay,
    mta_external_test,
    tls_handshake,
    tls_cert_expiry,
    tls_cert_name,
    tls_dovecot_min_protocol,
    tls_legacy_protocols,
    dns_mx,
    dns_spf,
    dns_dmarc,
    dns_dkim,
    dns_dkim_key,
    dns_mta_sts,
    dns_tls_rpt,
    dns_ptr,
    users_uid0,
    users_empty_password,
    users_interactive_accounts,
    users_sudo_nopasswd,
    keys_authorized_keys,
    disk_usage,
    disk_inodes,
    disk_mail_storage,
    queue_size,
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
