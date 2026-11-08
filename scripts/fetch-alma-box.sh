#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lab-config.sh
source "$lab_root/scripts/lab-config.sh"
box_name="$(lab_config_value versions.images.alma_box)"
box_version="$(lab_config_value versions.images.alma_box_version)"
box_checksum="$(lab_config_value versions.images.alma_box_sha256)"

if vagrant box list --machine-readable | awk -F, \
  -v expected_name="$box_name" \
  -v expected_version="$box_version" '
    $3 == "box-name" { box_name = $4 }
    $3 == "box-provider" { box_provider = $4 }
    $3 == "box-version" { box_version = $4 }
    $3 == "box-architecture" {
      if (box_name == expected_name &&
          box_provider == "parallels" &&
          box_version == expected_version &&
          $4 == "arm64") {
        found = 1
      }
    }
    END { exit(found ? 0 : 1) }
  '; then
  printf '%s %s is already installed\n' "$box_name" "$box_version"
  exit 0
fi

vagrant box add "$box_name" \
  --box-version "$box_version" \
  --provider parallels \
  --architecture arm64 \
  --checksum-type sha256 \
  --checksum "$box_checksum"
