#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'check-host: %s\n' "$*" >&2
  exit 1
}

[[ "$(uname -m)" == "arm64" ]] || fail "this topology requires an Apple Silicon host"
command -v prlctl >/dev/null || fail "Parallels Desktop command-line tools are not installed"
prlctl --version
license_status="$(prlsrvctl info --license)"
grep -q 'No license installed' <<<"$license_status" && \
  fail "Parallels is installed but its Pro trial or license has not been activated"

available_kib="$(df -Pk . | awk 'NR == 2 {print $4}')"
(( available_kib >= 220 * 1024 * 1024 )) || fail "at least 220 GiB of free disk is required"

physical_bytes="$(sysctl -n hw.memsize)"
(( physical_bytes >= 40 * 1024 * 1024 * 1024 )) || fail "at least 40 GiB of host RAM is required"

printf 'host architecture: %s\n' "$(uname -m)"
printf 'host memory:       %s GiB\n' "$(( physical_bytes / 1024 / 1024 / 1024 ))"
printf 'free disk:         %s GiB\n' "$(( available_kib / 1024 / 1024 ))"
