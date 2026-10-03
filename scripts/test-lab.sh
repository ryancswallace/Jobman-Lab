#!/usr/bin/env bash
set -euo pipefail

# WinRM's proxy discovery enters macOS frameworks from Ansible worker processes.
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"
lab_group="${JOBMAN_LAB_GROUP:-full}"
case "$lab_group" in
  core|full) ;;
  *)
    printf 'unsupported JOBMAN_LAB_GROUP: %s\n' "$lab_group" >&2
    exit 2
    ;;
esac

"$lab_root/scripts/configure-control.sh"
"$lab_root/scripts/enroll-agents.sh"

ANSIBLE_CONFIG="$lab_root/ansible/ansible.cfg" \
  ansible-playbook "$lab_root/ansible/validate.yml"

# The exhaustive cross-host SSH matrix can outlive Keycloak's short default
# access-token lifetime. Refresh synthetic credentials immediately before E2E.
"$lab_root/scripts/configure-control.sh"

JOBMAN_LAB_GROUP="$lab_group" VAGRANT_DEFAULT_PROVIDER=parallels \
  vagrant ssh submit01 -c "sudo -u alice env HOME=/home/alice PATH=/usr/local/bin:/usr/bin:/bin JOBMAN_LAB_GROUP=$lab_group /bin/bash -c 'cd /home/alice || exit; exec /bin/bash -s'" \
  < "$lab_root/scripts/jobman-e2e-remote.sh"

printf 'all Jobman lab validation checks passed\n'
