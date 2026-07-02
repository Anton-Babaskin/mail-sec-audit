#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${repo_root}/mail-sec-audit.sh"

bash -n "$script"

help_output="$(bash "$script" --help)"
if [[ -z "$help_output" ]]; then
  echo "Expected --help to print usage output" >&2
  exit 1
fi

if ! grep -q -- "--days" <<<"$help_output"; then
  echo "Expected --help output to mention --days" >&2
  exit 1
fi

echo "Smoke checks passed."

