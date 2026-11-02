#!/usr/bin/env bash
# mail-sec-audit 3.x entry point.
#
# Usage stays the same as in 2.x:
#   sudo bash mail-sec-audit.sh [options]
#
# The audit itself is the Python package next to this script (or the
# single-file mail-sec-audit.pyz). It runs with the system Python 3.9+ in
# isolated mode (-I): no PYTHON* variables, no user site, and the current
# directory is never on sys.path.
set -u
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
python="$(command -v python3 || true)"

if [[ -z "$python" ]] || ! "$python" -I -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' 2>/dev/null; then
  printf '%s\n' \
    'mail-sec-audit: Python 3.9 or newer is required as python3.' \
    'mail-sec-audit: нужен Python 3.9 или новее (python3).' >&2
  exit 69
fi

if [[ -f "$script_dir/mail_sec_audit/__main__.py" ]]; then
  exec "$python" -I -c \
    'import sys; sys.path.insert(0, sys.argv.pop(1)); from mail_sec_audit.app import main; raise SystemExit(main(sys.argv[1:]))' \
    "$script_dir" "$@"
fi
if [[ -f "$script_dir/mail-sec-audit.pyz" ]]; then
  exec "$python" -I "$script_dir/mail-sec-audit.pyz" "$@"
fi

printf 'mail-sec-audit: the mail_sec_audit package or mail-sec-audit.pyz was not found next to %s\n' "$0" >&2
exit 69
