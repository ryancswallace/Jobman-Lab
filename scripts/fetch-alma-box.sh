#!/usr/bin/env bash
set -euo pipefail

box_name='almalinux/9'
box_version='9.8.20260810'
box_checksum='8f10c585e8ed38738dd3150ee06c45206c1ebf33444fe699fbc4f72d8be36380'

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
