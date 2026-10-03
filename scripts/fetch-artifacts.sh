#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="$lab_root/.lab/cache"
archive="$cache/slurm-25.05.8.tar.bz2"
url='https://download.schedmd.com/slurm/slurm-25.05.8.tar.bz2'
sha='21ddc614396e7e0b1ba792841f182b4c5b24949b116cb509a3a650fc6fcc22b6'

mkdir -p "$cache"
if [[ ! -f "$archive" ]] || ! printf '%s  %s\n' "$sha" "$archive" | shasum -a 256 --check --status; then
  temporary="$archive.partial"
  curl --fail --location --show-error --output "$temporary" "$url"
  printf '%s  %s\n' "$sha" "$temporary" | shasum -a 256 --check
  mv "$temporary" "$archive"
fi
printf '%s  %s\n' "$sha" "$archive" | shasum -a 256 --check
