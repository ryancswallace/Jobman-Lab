#!/usr/bin/env bash
set -euo pipefail
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"
./scripts/init-dashboard.sh
./scripts/dashboard-inventory.rb
export ANSIBLE_SSH_ARGS="-o UserKnownHostsFile=.lab/dashboard/known_hosts -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519"
ANSIBLE_CONFIG="$lab_root/ansible/ansible.cfg" \
  ansible-playbook -i "$lab_root/.lab/dashboard/inventory.yml" "$lab_root/ansible/dashboard-infra.yml" --limit pg01,storage01,control01 "$@"
