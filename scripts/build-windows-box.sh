#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state_root="$lab_root/.lab"
# shellcheck source=scripts/lab-config.sh
source "$lab_root/scripts/lab-config.sh"
iso="$(lab_config_value versions.images.windows_iso --absolute)"
iso_sha="$(lab_config_value versions.images.windows_iso_sha256)"
box="$state_root/boxes/windows-11-arm64-parallels.box"

"$lab_root/scripts/init-state.sh"
printf '%s  %s\n' "$iso_sha" "$iso" | shasum -a 256 --check

if [[ -f "$box" ]]; then
  printf 'Windows box already exists: %s\n' "$box"
  exit 0
fi

PACKER_PLUGIN_PATH="$state_root/packer/plugins" packer init "$lab_root/packer"
PACKER_PLUGIN_PATH="$state_root/packer/plugins" packer validate \
  -var "windows_iso=$iso" -var "windows_iso_sha256=$iso_sha" "$lab_root/packer"
PACKER_PLUGIN_PATH="$state_root/packer/plugins" packer build \
  -var "windows_iso=$iso" -var "windows_iso_sha256=$iso_sha" "$lab_root/packer"

[[ -f "$box" ]] || { printf 'Packer did not create %s\n' "$box" >&2; exit 1; }
