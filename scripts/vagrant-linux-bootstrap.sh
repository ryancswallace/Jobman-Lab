#!/usr/bin/env bash
set -euo pipefail

short_name="${1:?short hostname is required}"
if [[ "$(hostname -s)" != "$short_name" ]]; then
  hostnamectl set-hostname "$short_name.lab.test"
fi

if ! command -v python3 >/dev/null; then
  dnf -y install python3
fi

install -d -m 0755 /etc/jobman-lab
printf '%s\n' "$short_name" > /etc/jobman-lab/node
