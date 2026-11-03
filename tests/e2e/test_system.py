"""End-to-end scenarios for host checks with a fake runner and fixture trees.

Command outputs follow the documented formats of the tools; they are not
captured from a production host (tests/fixtures/shapes/ does not exist yet).
"""

from __future__ import annotations

import os
import unittest

from mail_sec_audit.model import Status
from tests.helpers import DENIED, NOW, TIMEOUT, Resp, Responses, run_scenario

# Fixture files are owned by whoever runs the tests; give alice that UID so
# ownership checks behave the same for every runner (root-owned is accepted).
ALICE_UID = os.getuid() or 1000
PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    f"alice:x:{ALICE_UID}:1000:Alice:/home/alice:/bin/bash\n"
    "postfix:x:110:116::/var/spool/postfix:/usr/sbin/nologin\n"
)
SSHD_OK = (
    "port 22\npermitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\n"
    "kbdinteractiveauthentication no\nx11forwarding no\nmaxauthtries 3\n"
    "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n"
)
APT_SIM = (
    "Reading package lists...\n"
    "Inst openssl [3.0.2-0ubuntu1.18] (3.0.2-0ubuntu1.19 Ubuntu:22.04/jammy-security [amd64])\n"
    "Inst vim [2:8.2.3995-1ubuntu2.20] (2:8.2.3995-1ubuntu2.21 Ubuntu:22.04/jammy-updates [amd64])\n"
    "Conf openssl (3.0.2-0ubuntu1.19 Ubuntu:22.04/jammy-security [amd64])\n"
)
SS = (
    "tcp LISTEN 0 100 0.0.0.0:25 0.0.0.0:*\n"
    "tcp LISTEN 0 100 [::]:993 [::]:*\n"
    "tcp LISTEN 0 128 127.0.0.1:10025 0.0.0.0:*\n"
    "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n"
    "udp UNCONN 0 0 0.0.0.0%eth0:68 0.0.0.0:*\n"
    "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
)
DF = (
    "Filesystem 1-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 100000 50000 50000 50% /\n"
    "/dev/sdb1 100000 96000 4000 96% /var/vmail\n"
    "/dev/sdc1 100000 86000 14000 86% /srv/backup data\n"
)
DFI = "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/sda1 1000 100 900 10% /\n"


def base_files() -> dict[str, str]:
    return {
        "/etc/passwd": PASSWD,
        "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\n',
        "/etc/sudoers": "root ALL=(ALL:ALL) ALL\n%admins ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *\n",
        "/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
        "/var/lib/apt/lists/archive.ubuntu.com_dists_jammy_InRelease": "x",
        "/var/run/reboot-required": "*** System restart required ***\n",
        "/var/run/reboot-required.pkgs": "linux-image-5.15.0-125-generic\n",
        "/boot/vmlinuz-5.15.0-124-generic": "",
        "/root/.profile": "",
        "/home/alice/.ssh/authorized_keys": "ssh-ed25519 AAAA alice@laptop.example\n",
        "/run/systemd/system/.keep": "",
        "/sys/module/apparmor/parameters/enabled": "Y\n",
        "/sys/kernel/security/apparmor/profiles": "/usr/sbin/sshd (enforce)\n/usr/sbin/dovecot (complain)\n",
        "/etc/cron.d/certbot": "0 */12 * * * root certbot -q renew\n",
        "/var/spool/cron/crontabs/alice": "# comment\n15 3 * * * /usr/local/bin/restic backup /home\n",
        "/etc/systemd/system/custom.service": "[Service]\nExecStart=/bin/true\n",
    }


def base_responses() -> Responses:
    return {
        ("hostname", "-f"): Resp("mx1.example.org\n"),
        ("apt-get",): Resp(APT_SIM),
        ("sshd", "-T"): Resp(SSHD_OK),
        ("ss", "-H", "-l", "-n", "-t", "-u"): Resp(SS),
        ("ufw", "status", "verbose"): Resp("Status: active\nDefault: deny (incoming), allow (outgoing)\n"),
        ("fail2ban-client", "ping"): Resp("Server replied: pong\n"),
        ("fail2ban-client", "status"): Resp("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, postfix-sasl\n"),
        ("fail2ban-client", "status", "sshd"): Resp(
            "|  `- Total failed:\t9\n   |- Currently banned:\t2\n   |- Total banned:\t40\n"
        ),
        ("fail2ban-client", "status", "postfix-sasl"): Resp("   |- Currently banned:\t0\n   |- Total banned:\t3\n"),
        ("systemctl", "show"): Resp(
            "Id=fail2ban.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\n"
            "Id=crowdsec.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n"
        ),
        ("systemctl", "--failed"): Resp(""),
        ("systemctl", "list-timers"): Resp("Mon 2026-11-02 apt-daily.timer apt-daily.service\n"),
        ("passwd", "-S", "-a"): Resp("root P 2026-01-01 0 99999 7 -1\nalice P 2026-01-01 0 99999 7 -1\n"),
        ("df", "-P", "-B1"): Resp(DF),
        ("df", "-P", "-i"): Resp(DFI),
        ("find", "/home"): Resp(""),
        ("find", "/bin"): Resp("/usr/bin/sudo\0/usr/bin/passwd\0"),
        ("find", "/etc"): Resp("d 1777 /opt/app/tmp\0"),
        ("last",): Resp("alice pts/0 Mon Nov  2 09:00 still logged in 203.0.113.50\n"),
        ("lastb",): Resp(""),
        ("restic",): Resp(""),
    }


class SystemScenarioTest(unittest.TestCase):
    def test_debian_root_host(self) -> None:
        s = run_scenario(base_files(), base_responses())
        self.assertEqual(s.status("PATCH.PENDING_UPDATES"), Status.WARN)
        self.assertEqual(s.get("PATCH.PENDING_UPDATES").params["count"], 1)
        self.assertEqual(s.status("PATCH.APT_METADATA_AGE"), Status.INFO)
        self.assertEqual(s.status("PATCH.AUTO_UPDATES"), Status.INFO)
        self.assertEqual(s.get("PATCH.AUTO_UPDATES").key, "patch.auto_updates.enabled")
        self.assertEqual(s.status("PATCH.REBOOT_REQUIRED"), Status.WARN)
        for check in (
            "SSH.ROOT_LOGIN",
            "SSH.PASSWORD_AUTH",
            "SSH.PUBKEY_AUTH",
            "SSH.X11_FORWARDING",
            "SSH.MAX_AUTH_TRIES",
        ):
            self.assertEqual(s.status(check), Status.OK, check)
        self.assertEqual(s.ids("NET."), ["NET.LISTENERS@tcp/0.0.0.0:8080"])
        self.assertEqual(s.status("FW.HOST_FIREWALL"), Status.OK)
        self.assertEqual(s.status("BRUTE.FAIL2BAN"), Status.OK)
        self.assertEqual(s.get("BRUTE.FAIL2BAN_JAILS").params["banned"], 2)
        self.assertEqual(s.status("BRUTE.PROTECTION"), Status.OK)
        self.assertEqual(s.status("USERS.UID0"), Status.OK)
        self.assertEqual(s.status("USERS.EMPTY_PASSWORD"), Status.OK)
        self.assertEqual(s.status("USERS.SUDO_NOPASSWD"), Status.INFO)
        self.assertEqual(s.get("KEYS.AUTHORIZED_KEYS").params["files"], 1)
        self.assertEqual(s.status("DISK.USAGE@/var/vmail"), Status.FAIL)
        self.assertEqual(s.status("DISK.USAGE@/srv/backup data"), Status.WARN)
        self.assertEqual(s.status("DISK.INODES"), Status.OK)
        self.assertEqual(len(s.report.filesystems if s.report.filesystems else []), 3)
        self.assertEqual(s.status("SUID.UNEXPECTED_LOCATIONS"), Status.OK)
        self.assertEqual(s.get("SUID.STANDARD_PATHS").params["count"], 2)
        self.assertEqual(s.get("PERMS.WORLD_WRITABLE").key, "perms.world_writable.sticky")
        self.assertEqual(s.status("MAC.FAILED_UNITS"), Status.OK)
        self.assertEqual(s.get("MAC.FRAMEWORK").key, "mac.framework.apparmor")
        self.assertEqual(s.get("SCHED.INVENTORY").params["crontabs"], 1)
        self.assertEqual(s.status("BACKUP.INDICATORS"), Status.INFO)
        self.assertEqual(s.status("LOGIN.RECENT"), Status.INFO)
        self.assertNotIn("PKG.INTEGRITY", s.ids())
        self.assertNotIn("SUID.FULL_SCAN", s.ids())
        self.assertEqual(s.report.exit_code, 2)

    def test_sshd_failure_is_unknown_not_ok(self) -> None:
        responses = dict(base_responses())
        responses[("sshd", "-T")] = Resp("", rc=255, err="Missing privilege separation directory: /run/sshd")
        s = run_scenario(base_files(), responses)
        for check in ("SSH.ROOT_LOGIN", "SSH.PASSWORD_AUTH", "SSH.X11_FORWARDING"):
            self.assertEqual(s.status(check), Status.UNKNOWN, check)
            self.assertEqual(s.get(check).reason, "command_failed")

    def test_ssh_risky_values(self) -> None:
        responses = dict(base_responses())
        responses[("sshd", "-T")] = Resp(
            "port 22\npermitrootlogin yes\npasswordauthentication yes\npubkeyauthentication no\n"
            "x11forwarding yes\nmaxauthtries 10\nkbdinteractiveauthentication yes\n"
        )
        s = run_scenario(base_files(), responses)
        self.assertEqual(s.status("SSH.ROOT_LOGIN"), Status.FAIL)
        self.assertEqual(s.status("SSH.PASSWORD_AUTH"), Status.WARN)
        self.assertEqual(s.status("SSH.PUBKEY_AUTH"), Status.WARN)
        self.assertEqual(s.status("SSH.X11_FORWARDING"), Status.WARN)
        self.assertEqual(s.status("SSH.MAX_AUTH_TRIES"), Status.WARN)
        self.assertEqual(s.status("SSH.KBD_INTERACTIVE"), Status.INFO)

    def test_docker_only_iptables_is_not_a_firewall(self) -> None:
        files = base_files()
        files["/proc/net/ip_tables_names"] = "filter\nnat\n"
        responses = dict(base_responses())
        del responses[("ufw", "status", "verbose")]
        responses[("iptables", "-S")] = Resp(
            "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-N DOCKER\n-N DOCKER-USER\n"
            "-A FORWARD -j DOCKER-USER\n-A DOCKER-USER -j RETURN\n-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n"
        )
        responses[("nft", "list", "ruleset")] = Resp(
            "table ip filter {\n\tchain DOCKER {\n\t}\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n"
        )
        s = run_scenario(files, responses)
        self.assertEqual(s.status("FW.HOST_FIREWALL"), Status.FAIL)

    def test_default_drop_counts_as_firewall(self) -> None:
        responses = dict(base_responses())
        del responses[("ufw", "status", "verbose")]
        responses[("nft", "list", "ruleset")] = Resp(
            "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n"
            "\t\tct state established,related accept\n\t}\n}\n"
        )
        self.assertEqual(run_scenario(base_files(), responses).status("FW.HOST_FIREWALL"), Status.OK)

    def test_unreadable_firewall_is_unknown(self) -> None:
        responses = dict(base_responses())
        responses[("ufw", "status", "verbose")] = Resp("", rc=1, err="ERROR: You need to be root to run this script")
        responses[("nft", "list", "ruleset")] = Resp("", rc=1, err="Operation not permitted (you must be root)")
        s = run_scenario(base_files(), responses, euid=1000)
        self.assertEqual(s.status("FW.HOST_FIREWALL"), Status.UNKNOWN)
        self.assertEqual(s.get("FW.HOST_FIREWALL").reason, "permission_denied")
        self.assertIn(
            ("ufw status verbose", "denied"),
            [(x.source.split(":", 1)[1], x.state) for x in s.report.completeness.sources],
        )

    def test_fail2ban_permission_and_absence(self) -> None:
        responses = dict(base_responses())
        responses[("fail2ban-client", "ping")] = Resp(
            "", rc=255, err="Permission denied to socket: /var/run/fail2ban/fail2ban.sock, (you must be root)"
        )
        s = run_scenario(base_files(), responses, euid=1000)
        self.assertEqual(s.status("BRUTE.FAIL2BAN"), Status.UNKNOWN)
        responses = dict(base_responses())
        for key in [k for k in responses if k[0] == "fail2ban-client"]:
            del responses[key]
        s = run_scenario(base_files(), responses)
        self.assertEqual(s.status("BRUTE.FAIL2BAN"), Status.NA)

    def test_dnf_error_is_unknown_and_updates_warn(self) -> None:
        responses = dict(base_responses())
        del responses[("apt-get",)]
        responses[("dnf",)] = Resp("", rc=1, err="Error: Cache-only enabled but no cache for 'baseos'")
        s = run_scenario(base_files(), responses)
        self.assertEqual(s.status("PATCH.PENDING_UPDATES"), Status.UNKNOWN)
        self.assertEqual(s.status("PATCH.APT_METADATA_AGE"), Status.NA)
        responses[("dnf",)] = Resp("\nopenssl.x86_64  1:3.0.7-28.el9  baseos\n", rc=100)
        s = run_scenario(base_files(), responses)
        self.assertEqual(s.status("PATCH.PENDING_UPDATES"), Status.WARN)
        dnf_call = next(c for c in s.runner.calls if c[0] == "dnf")
        self.assertTrue(dnf_call[3].startswith("--setopt=logdir=") and dnf_call[3].endswith("/dnf"))

    def test_rhel_kernel_comparison(self) -> None:
        files = base_files()
        del files["/var/run/reboot-required"]
        del files["/var/run/reboot-required.pkgs"]
        files["/boot/vmlinuz-6.8.0-51-generic"] = ""  # newer than the running 6.8.0-45-generic
        files["/boot/vmlinuz-99.0.0-1.el9.x86_64"] = ""  # other flavour: not compared
        s = run_scenario(files, base_responses())
        self.assertEqual(s.get("PATCH.REBOOT_REQUIRED").key, "patch.reboot_required.kernel")

    def test_empty_password_and_extra_uid0(self) -> None:
        files = base_files()
        files["/etc/passwd"] = PASSWD + "toor:x:0:0::/root:/bin/sh\n"
        responses = dict(base_responses())
        responses[("passwd", "-S", "-a")] = Resp("root P\nalice NP 2026-01-01 0 99999 7 -1\n")
        s = run_scenario(files, responses)
        self.assertEqual(s.status("USERS.UID0"), Status.FAIL)
        self.assertEqual(s.status("USERS.EMPTY_PASSWORD"), Status.FAIL)
        self.assertEqual(s.get("USERS.EMPTY_PASSWORD").params["names"], "alice")

    def test_world_writable_and_suid_in_tmp(self) -> None:
        responses = dict(base_responses())
        responses[("find", "/etc")] = Resp("f 666 /etc/cron.d/evil\0d 777 /opt/drop\0")
        responses[("find", "/home")] = Resp("/tmp/.x/bash\0")
        s = run_scenario(base_files(), responses)
        self.assertEqual(s.status("PERMS.WORLD_WRITABLE"), Status.WARN)
        self.assertEqual(s.status("SUID.UNEXPECTED_LOCATIONS"), Status.FAIL)
        responses[("find", "/home")] = TIMEOUT
        self.assertEqual(run_scenario(base_files(), responses).status("SUID.UNEXPECTED_LOCATIONS"), Status.UNKNOWN)

    def test_key_file_writable_by_group(self) -> None:
        s = run_scenario(base_files(), base_responses(), modes={"/home/alice/.ssh/authorized_keys": 0o664})
        self.assertEqual(s.ids("KEYS.AUTHORIZED_KEYS@"), ["KEYS.AUTHORIZED_KEYS@/home/alice/.ssh/authorized_keys"])
        self.assertEqual(s.status("KEYS.AUTHORIZED_KEYS@/home/alice/.ssh/authorized_keys"), Status.WARN)
        s = run_scenario(base_files(), base_responses(), modes={"/home/alice/.ssh/authorized_keys": 0o644})
        self.assertEqual(s.ids("KEYS.AUTHORIZED_KEYS@"), [], "0644 is accepted by sshd StrictModes")

    def test_stale_apt_lists(self) -> None:
        stamp = NOW.timestamp() - 20 * 86400
        s = run_scenario(
            base_files(),
            base_responses(),
            mtimes={"/var/lib/apt/lists/archive.ubuntu.com_dists_jammy_InRelease": stamp},
        )
        self.assertEqual(s.status("PATCH.APT_METADATA_AGE"), Status.WARN)
        self.assertEqual(s.get("PATCH.APT_METADATA_AGE").params["days"], 20)

    def test_no_systemd_and_deep_checks(self) -> None:
        files = base_files()
        del files["/run/systemd/system/.keep"]
        responses = dict(base_responses())
        responses[("debsums", "-s")] = Resp(
            "", rc=2, err="debsums: changed file /usr/bin/ls (from coreutils package)\n"
        )
        responses[("find", "/")] = Resp("/usr/bin/sudo\0")
        responses[("find", "/usr/local/bin")] = Resp("1762070400.0 755 root:root /usr/local/bin/tool\0")
        s = run_scenario(files, responses, args=("--deep",))
        self.assertEqual(s.status("MAC.FAILED_UNITS"), Status.NA)
        self.assertEqual(s.status("PKG.INTEGRITY"), Status.UNKNOWN)  # stderr is not stdout: command failed
        self.assertEqual(s.status("SUID.FULL_SCAN"), Status.INFO)
        self.assertEqual(s.status("RECENT.MODIFIED"), Status.INFO)

    def test_non_root_reports_unknown_not_ok(self) -> None:
        responses = dict(base_responses())
        responses[("passwd", "-S", "-a")] = DENIED
        s = run_scenario(base_files(), responses, euid=1000, denied=frozenset({"/etc/sudoers", "/root"}))
        self.assertEqual(s.status("CTX.PRIVILEGES"), Status.WARN)
        self.assertEqual(s.status("USERS.EMPTY_PASSWORD"), Status.UNKNOWN)
        self.assertEqual(s.status("USERS.SUDO_NOPASSWD"), Status.UNKNOWN)
        self.assertIn(Status.UNKNOWN, [f.status for f in s.report.findings if f.check_id == "KEYS.AUTHORIZED_KEYS"])


if __name__ == "__main__":
    unittest.main()
