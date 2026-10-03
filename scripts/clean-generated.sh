#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state_root="$lab_root/.lab"

printf '%s\n' 'This removes ignored lab artifacts, caches, certificates, and synthetic credentials. It does not remove VMs.'
if [[ "${JOBMAN_LAB_CONFIRM_CLEAN:-}" != yes ]]; then
  read -r -p 'Type clean-jobman-lab-state to continue: ' answer
  [[ "$answer" == clean-jobman-lab-state ]] || { printf 'clean cancelled\n'; exit 1; }
fi

[[ "$state_root" == "$lab_root/.lab" && -d "$state_root" ]] || {
  printf 'refusing to remove unexpected state path: %s\n' "$state_root" >&2
  exit 1
}
find "$state_root" -mindepth 1 -delete
printf 'removed regenerable lab state beneath %s\n' "$state_root"
