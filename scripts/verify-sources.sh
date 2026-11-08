#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lab-config.sh
source "$lab_root/scripts/lab-config.sh"
windows_iso="$(lab_config_value versions.images.windows_iso --absolute)"
windows_sha="$(lab_config_value versions.images.windows_iso_sha256)"

[[ -f "$windows_iso" ]] || { printf 'missing Windows ISO: %s\n' "$windows_iso" >&2; exit 1; }
printf '%s  %s\n' "$windows_sha" "$windows_iso" | shasum -a 256 --check

for product in jobman jobman_control jobman_diagnose jobman_dashboard
do
  repo="$(lab_config_value "versions.products.${product}_repo" --absolute)"
  [[ -e "$repo/.git" ]] || { printf 'missing product repository: %s\n' "$repo" >&2; exit 1; }
  printf '%-48s %s\n' "$repo" "$(git -C "$repo" rev-parse HEAD)"
done
