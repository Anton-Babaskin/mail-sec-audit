#!/usr/bin/env bash
# Guards against commands that change the system even when called with
# "read-only" looking arguments:
#   - /usr/local/bin/mailinabox wraps `source setup/start.sh` and ignores
#     arguments, so any invocation runs the Mail-in-a-Box setup;
#   - Mailcow update.sh pulls images and recreates containers.
# The audit script resets PATH, so a PATH shim cannot intercept these calls.
# This test uses a static scan plus exported bash functions, which take
# precedence over PATH lookups in the child shell.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${repo_root}/mail-sec-audit.sh"

fail() {
  echo "$1" >&2
  exit 1
}

test_root="$(mktemp -d /tmp/mail-sec-audit-forbidden.XXXXXX)"
cleanup() {
  if [[ "$test_root" == /tmp/mail-sec-audit-forbidden.* && -d "$test_root" && ! -L "$test_root" ]]; then
    rm -rf -- "$test_root"
  fi
}
trap cleanup EXIT

# 1. Static scan. Comments are ignored; reading the wrapper with sed is allowed.
python3 - "$script" <<'PY'
import re
import sys

path = sys.argv[1]
problems = []
command_position = re.compile(
    r"(?P<pre>^|[;&|({]|\$\(|`|\bthen\b|\bdo\b|\belse\b|\btimeout\s+\d+)\s*"
    r"(?:sudo\s+|command\s+|exec\s+|env\s+)*"
    r"(?P<cmd>(?:[\w./-]*/)?(?:mailinabox|update\.sh))(?=\s|$|[;&|)])"
)
case_label = re.compile(r"^\s*[\w|*-]*\bmailinabox\b[\w|*-]*\)")
with open(path, encoding="utf-8") as handle:
    for number, raw in enumerate(handle, 1):
        line = raw.split("#", 1)[0] if raw.lstrip().startswith("#") else raw
        if "update.sh" in line:
            problems.append(f"{number}: mentions update.sh: {raw.strip()}")
            continue
        if case_label.match(line):
            continue
        for match in command_position.finditer(line):
            # `a|mailinabox)` is a case alternative, not a pipeline.
            if match.group("pre") == "|" and line[match.end():match.end() + 1] == ")":
                continue
            problems.append(f"{number}: executes {match.group('cmd')}: {raw.strip()}")
        if "/usr/local/bin/mailinabox" in line and not re.search(r"\bsed -n\b|wrapper=", line):
            problems.append(f"{number}: touches /usr/local/bin/mailinabox outside the sed reader: {raw.strip()}")
if problems:
    print("Forbidden command usage found:", *problems, sep="\n  ", file=sys.stderr)
    raise SystemExit(1)
PY

# 2. The version helper reads the wrapper and the git checkout without running setup.
eval "$(sed -n '/^miab_setup_dir() {/,/^}/p' "$script")"
setup_dir="$test_root/mailinabox"
git init -q "$setup_dir"
# Mail-in-a-Box release tags are annotated; plain `git describe` ignores lightweight tags.
git -C "$setup_dir" -c user.name=test -c user.email=test@example.invalid \
  commit -q --allow-empty -m init
git -C "$setup_dir" -c user.name=test -c user.email=test@example.invalid \
  tag -a -m release v77
printf '#!/bin/bash\ncd %s\nsource setup/start.sh\n' "$setup_dir" >"$test_root/wrapper"
[[ "$(miab_setup_dir "$test_root/wrapper")" == "$setup_dir" ]] \
  || fail "miab_setup_dir did not read the checkout path from the wrapper"
version="$(git -c core.fsmonitor=false --no-pager --no-optional-locks -C "$setup_dir" describe --always --abbrev=0)"
[[ "$version" == v77 ]] || fail "unexpected git describe output: $version"
printf '#!/bin/bash\ncd relative/path\nsource setup/start.sh\n' >"$test_root/bad-wrapper"
if miab_setup_dir "$test_root/bad-wrapper" >/dev/null; then
  fail "miab_setup_dir accepted a relative checkout path"
fi

# 3. Dynamic interception: the forced Mail-in-a-Box adapter must not call these.
export FORBIDDEN_MARKER="$test_root/called"
mailinabox() { printf 'mailinabox %s\n' "$*" >>"$FORBIDDEN_MARKER"; return 0; }
update.sh() { printf 'update.sh %s\n' "$*" >>"$FORBIDDEN_MARKER"; return 0; }
export -f mailinabox update.sh

set +e
timeout 240 bash "$script" --platform mailinabox --days 1 --format json --no-color \
  >"$test_root/audit.json" 2>"$test_root/audit.err"
status=$?
set -e
case "$status" in
  0|1|2) ;;
  *) fail "audit with --platform mailinabox exited with $status: $(tail -5 "$test_root/audit.err")" ;;
esac
if [[ -e "$FORBIDDEN_MARKER" ]]; then
  fail "forbidden command executed: $(cat "$FORBIDDEN_MARKER")"
fi

echo "Forbidden command checks passed."
