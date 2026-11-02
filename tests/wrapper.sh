#!/usr/bin/env bash
# Checks for the Bash entry point:
#   - it never names mailinabox or update.sh in a command position;
#   - Python always runs in isolated mode (-I), so modules planted in the
#     caller's working directory are never imported;
#   - the runner refuses the forbidden programs with any arguments.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${repo_root}/mail-sec-audit.sh"

fail() {
  echo "$1" >&2
  exit 1
}

test_root="$(mktemp -d /tmp/mail-sec-audit-wrapper.XXXXXX)"
cleanup() {
  if [[ "$test_root" == /tmp/mail-sec-audit-wrapper.* && -d "$test_root" && ! -L "$test_root" ]]; then
    rm -rf -- "$test_root"
  fi
}
trap cleanup EXIT

# 1. Static scan of the wrapper.
if grep -nE '(^|[;&|({`[:space:]])(/[^[:space:]]*/)?(mailinabox|update\.sh)([[:space:];&|)]|$)' "$script"; then
  fail "the wrapper must not run mailinabox or update.sh"
fi
# shellcheck disable=SC2016  # the pattern matches the literal text "$python"
if grep -nE '"\$python"( |$)' "$script" | grep -v -- ' -I'; then
  fail "every Python invocation in the wrapper must use -I"
fi

# 2. Planted modules in the working directory are not imported.
mkdir -p "$test_root/cwd"
for module in json re subprocess datetime mail_sec_audit; do
  if [[ "$module" == mail_sec_audit ]]; then
    mkdir -p "$test_root/cwd/mail_sec_audit"
    printf 'open(%s, "a").write("package\\n")\n' "'$test_root/imported'" >"$test_root/cwd/mail_sec_audit/__init__.py"
  else
    printf 'open(%s, "a").write("%s\\n")\n' "'$test_root/imported'" "$module" >"$test_root/cwd/$module.py"
  fi
done
(cd "$test_root/cwd" && bash "$script" --version >/dev/null)
(cd "$test_root/cwd" && PYTHONPATH="$test_root/cwd" bash "$script" --help >/dev/null)
if [[ -e "$test_root/imported" ]]; then
  fail "modules were imported from the working directory: $(tr '\n' ' ' <"$test_root/imported")"
fi

# 3. The runner refuses forbidden programs (also inside docker exec).
python3 -I -c '
import sys
sys.path.insert(0, sys.argv[1])
from mail_sec_audit.runner import ForbiddenCommand, Policy
for argv in (["mailinabox", "--version"], ["/usr/local/bin/mailinabox"], ["update.sh", "--check"],
             ["docker", "exec", "abcdef123456", "mailinabox"], ["docker", "exec", "-it", "abcdef123456", "postconf"]):
    try:
        Policy().check(argv)
    except ForbiddenCommand:
        continue
    raise SystemExit(f"allowed: {argv}")
' "$repo_root"

echo "Wrapper checks passed."
