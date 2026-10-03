#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"

printf '%s\n' 'This destroys only the Vagrant-managed VMs whose Parallels names begin with jobman-lab-.'
if [[ "${JOBMAN_LAB_CONFIRM_DESTROY:-}" != yes ]]; then
  read -r -p 'Type destroy-jobman-lab to continue: ' answer
  [[ "$answer" == destroy-jobman-lab ]] || { printf 'destroy cancelled\n'; exit 1; }
fi

JOBMAN_LAB_GROUP=full VAGRANT_DEFAULT_PROVIDER=parallels vagrant destroy --force
