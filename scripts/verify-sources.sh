#!/usr/bin/env bash
set -euo pipefail

windows_iso="/Users/rcw/Downloads/Win11_25H2_English_Arm64_v2.iso"
windows_sha="638aa2c88e94385b00f4f178d071e3df0b7d9e335577a83bd533b7f2eb65adf0"

[[ -f "$windows_iso" ]] || { printf 'missing Windows ISO: %s\n' "$windows_iso" >&2; exit 1; }
printf '%s  %s\n' "$windows_sha" "$windows_iso" | shasum -a 256 --check

for repo in \
  /Users/rcw/home/code/jobman \
  /Users/rcw/home/code/jobman-control \
  /Users/rcw/home/code/jobman-diagnose
do
  [[ -d "$repo/.git" ]] || { printf 'missing product repository: %s\n' "$repo" >&2; exit 1; }
  printf '%-48s %s\n' "$repo" "$(git -C "$repo" rev-parse HEAD)"
done
