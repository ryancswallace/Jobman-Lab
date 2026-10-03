#!/usr/bin/env bash
set -euo pipefail

lab_group="${1:?lab group is required}"
max_attempts=2

export JOBMAN_LAB_GROUP="$lab_group"
export VAGRANT_DEFAULT_PROVIDER=parallels

for attempt in $(seq 1 "$max_attempts"); do
  if vagrant up --provider=parallels; then
    exit 0
  fi

  if (( attempt == max_attempts )); then
    printf 'Vagrant startup failed after %d attempts\n' "$max_attempts" >&2
    exit 1
  fi

  printf 'Vagrant startup attempt %d failed; retrying transient guest startup once\n' "$attempt" >&2
  sleep 5
done
