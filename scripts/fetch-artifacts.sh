#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="$lab_root/.lab/cache"
# shellcheck source=scripts/lab-config.sh
source "$lab_root/scripts/lab-config.sh"
archive="$cache/slurm-$(lab_config_value versions.guest_software.slurm).tar.bz2"
url="$(lab_config_value versions.guest_software.slurm_url)"
sha="$(lab_config_value versions.guest_software.slurm_sha256)"

mkdir -p "$cache"
if [[ ! -f "$archive" ]] || ! printf '%s  %s\n' "$sha" "$archive" | shasum -a 256 --check --status; then
  temporary="$archive.partial"
  curl --fail --location --show-error --proto '=https' --proto-redir '=https' --output "$temporary" --url "$url"
  printf '%s  %s\n' "$sha" "$temporary" | shasum -a 256 --check
  mv "$temporary" "$archive"
fi
printf '%s  %s\n' "$sha" "$archive" | shasum -a 256 --check
