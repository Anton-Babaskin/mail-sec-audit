#!/usr/bin/env bash
# Regression tests for hidden side effects in the legacy Bash auditor:
# Python imports from the caller's working directory, signal handling that
# continued the audit after cleanup, and commands that run foreign code or
# send mail (sendmail -bv, rpm -V scriptlets).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${repo_root}/mail-sec-audit.sh"

fail() {
  echo "$1" >&2
  exit 1
}

test_root="$(mktemp -d /tmp/mail-sec-audit-hardening.XXXXXX)"
cleanup() {
  if [[ "$test_root" == /tmp/mail-sec-audit-hardening.* && -d "$test_root" && ! -L "$test_root" ]]; then
    rm -rf -- "$test_root"
  fi
}
trap cleanup EXIT

# 1. Static checks.
if grep -nE '^[^#]*\bpython3 +(-[^I]|"|\$)' "$script"; then
  fail "every python3 invocation must use isolated mode (-I)"
fi
if grep -nE '^[^#]*\bsendmail +-' "$script"; then
  fail "sendmail must not be executed: -bv mails a report with Postfix's sendmail"
fi
if grep -nE '^[[:space:]]*rpm[[:space:]]+-V' "$script" | grep -v -- '--noscripts'; then
  fail "rpm -V must use --noscripts: it runs package %verifyscript otherwise"
fi

# 2. Modules in the caller's working directory must not be imported.
mkdir -p "$test_root/cwd"
for module in ipaddress json collections re subprocess datetime; do
  printf 'open(%s, "a").write("%s\\n")\n' "'$test_root/imported'" "$module" >"$test_root/cwd/$module.py"
done
set +e
(cd "$test_root/cwd" && timeout 240 bash "$script" --days 1 --format json --no-color >/dev/null 2>&1)
status=$?
set -e
case "$status" in 0|1|2) ;; *) fail "audit from a planted working directory exited with $status" ;; esac
if [[ -e "$test_root/imported" ]]; then
  fail "python imported modules from the working directory: $(tr '\n' ' ' <"$test_root/imported")"
fi

# 3. SIGTERM stops the audit; it must not continue with a deleted TMPROOT.
#    sshd is called directly (not through timeout), so an exported function
#    keeps the audit busy until the signal arrives.
# shellcheck disable=SC2317,SC2329  # invoked by the child shell through export -f
sshd() { sleep 30; }
export -f sshd
set +e
timeout -s TERM 5 bash "$script" --days 1 --no-color >"$test_root/term.txt" 2>&1
status=$?
set -e
unset -f sshd
[[ "$status" == 124 ]] || fail "expected timeout status 124 after SIGTERM, got $status"
if grep -q 'No such file or directory' "$test_root/term.txt"; then
  fail "audit continued after SIGTERM: $(grep -m1 'No such file or directory' "$test_root/term.txt")"
fi
if grep -q 'SUMMARY' "$test_root/term.txt"; then
  fail "audit printed SUMMARY after SIGTERM"
fi
if compgen -G '/tmp/mail-sec-audit.??????' >/dev/null; then
  for leftover in /tmp/mail-sec-audit.??????; do
    [[ "$leftover" -nt "$test_root" ]] && fail "temporary directory left after SIGTERM: $leftover"
  done
fi

echo "Legacy hardening checks passed."
