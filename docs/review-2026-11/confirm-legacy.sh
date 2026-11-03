#!/usr/bin/env bash
# Review experiments E1-E20 against the legacy script (main @ 33f2d51).
# Usage: bash confirm-legacy.sh /path/to/checkout-of-33f2d51
# Runs as an unprivileged user; nothing here needs root. Commands are replaced
# with exported bash functions, which take precedence over the script's fixed
# PATH in the child shell (commands run through `timeout` are not affected).
set -u
REPO="${1:?usage: $0 /path/to/checkout-of-33f2d51}"
S="$REPO/mail-sec-audit.sh"
OUT="$(mktemp -d /tmp/msa-review.XXXXXX)"
export MARKER="$OUT/e1.marker"

run_audit() { # name, args...
  local name="$1"; shift
  timeout 240 bash "$S" --no-color --days 1 "$@" >"$OUT/$name.txt" 2>&1
  echo "rc=$?" >>"$OUT/$name.txt"
}

echo "== E1 mailinabox --version is executed =="
(
  mailinabox() { printf 'CALLED: mailinabox %s\n' "$*" >>"$MARKER"; }
  export -f mailinabox
  run_audit e1 --platform mailinabox --format json
)
cat "$MARKER" 2>/dev/null || echo "not called"

echo "== E2 python3 imports from the current directory =="
mkdir -p "$OUT/cwd"
printf 'open("%s", "w").write("imported from cwd\\n")\n' "$OUT/e2.PWNED" >"$OUT/cwd/ipaddress.py"
( cd "$OUT/cwd" && run_audit e2 )
cat "$OUT/e2.PWNED" 2>/dev/null || echo "not imported"

echo "== E3 SIGTERM: the script continues after its trap removed TMPROOT =="
(
  sshd() { sleep 20; }
  export -f sshd
  timeout -s TERM 3 bash "$S" --no-color --days 1 >"$OUT/e3.txt" 2>&1
  echo "timeout rc=$?" >>"$OUT/e3.txt"
)
grep -c 'No such file or directory' "$OUT/e3.txt"
grep -E '^\[[0-9]+\]' "$OUT/e3.txt" | tail -1
grep -E 'RESULT|timeout rc=' "$OUT/e3.txt"

echo "== E4 --redact replaces clock times with <redacted-ipv6> =="
run_audit e4 --redact
grep -m3 -E 'redacted-ipv6' "$OUT/e4.txt"

echo "== E6 sshd -T failure produces OK findings =="
(
  sshd() { echo "Missing privilege separation directory: /run/sshd" >&2; return 255; }
  export -f sshd
  run_audit e6 --format json
)
grep -E '"message": "SSH' "$OUT/e6.txt"

echo "== E7 unreadable firewall state produces FAIL =="
(
  ufw() { echo "ERROR: You need to be root to run this script" >&2; return 1; }
  nft() { echo "Operation not permitted (you must be root)" >&2; return 1; }
  iptables() { echo "iptables: Permission denied (you must be root)." >&2; return 4; }
  export -f ufw nft iptables
  run_audit e7 --format json
)
grep -E 'firewall|UFW' "$OUT/e7.txt"

echo "== E8 Docker-only iptables chains count as a host firewall =="
(
  iptables() { [[ "$1" == -S ]] && printf -- '-P INPUT ACCEPT\n-P FORWARD DROP\n-N DOCKER\n-A FORWARD -j DOCKER-USER\n-A DOCKER-USER -j RETURN\n'; return 0; }
  export -f iptables
  run_audit e8 --format json
)
grep -E 'iptables|firewall' "$OUT/e8.txt"

echo "== E9 finding IDs depend on which earlier checks fired =="
for kbd in no yes; do
  (
    eval "sshd() { printf 'port 22\npermitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\nkbdinteractiveauthentication $kbd\nx11forwarding no\nmaxauthtries 3\n'; }"
    export -f sshd
    run_audit "e9-$kbd" --format json
  )
  python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[2], [f["id"] for f in d["findings"] if "X11" in f["message"]])' \
    <(sed '/^rc=/d' "$OUT/e9-$kbd.txt") "kbd=$kbd"
done

echo "== E11 long Postfix queue IDs are not counted =="
(
  postqueue() {
    printf -- '-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\n'
    for i in $(seq 1 1500); do
      printf '4Xyz%07dBcDfz  1234 Mon Nov  2 10:00:00  sender@example.org\n                                         rcpt@example.net\n\n' "$i"
    done
    printf -- '-- 1851 Kbytes in 1500 Requests.\n'
  }
  postconf() { echo ""; }
  export -f postqueue postconf
  run_audit e11 --format json --platform generic
)
grep -E '"message": "Размер Postfix queue' "$OUT/e11.txt"

echo "== E14 DHCP client UDP socket is an unknown public listener =="
(
  ss() { if [[ "$*" == "-H -lntu" ]]; then printf 'udp UNCONN 0 0 0.0.0.0%%eth0:68 0.0.0.0:*\ntcp LISTEN 0 100 0.0.0.0:25 0.0.0.0:*\n'; else command ss "$@"; fi; }
  export -f ss
  run_audit e14 --format json
)
grep -E 'listener' "$OUT/e14.txt" | head -3

echo "== E15 openssl -tls1 fails on the client side with OpenSSL 3 =="
(
  cd "$OUT" || exit 1
  openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 2 -subj /CN=mail.example.org >/dev/null 2>&1
  openssl s_server -accept 127.0.0.1:44330 -cert c.pem -key k.pem -tls1 -cipher 'DEFAULT:@SECLEVEL=0' -quiet >/dev/null 2>&1 &
  srv=$!; sleep 1
  echo "script's command:"
  timeout 8 openssl s_client -connect 127.0.0.1:44330 -tls1 </dev/null 2>&1 | grep -E 'Protocol|no protocols' | head -2
  echo "client with SECLEVEL=0:"
  timeout 8 openssl s_client -connect 127.0.0.1:44330 -tls1 -cipher 'DEFAULT:@SECLEVEL=0' </dev/null 2>&1 | grep -E 'Protocol *:' | head -1
  kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
)

echo "== E20 progress messages are exported as JSON findings =="
run_audit e20 --format json
grep -E '"message": "(Анализирую|Управление блокировками)' "$OUT/e20.txt"

echo "Outputs: $OUT"
