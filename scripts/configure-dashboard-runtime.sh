#!/usr/bin/env bash
set -euo pipefail
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"
[[ $# -ge 1 && "${1-}" == /* ]] || { printf 'Provide an absolute exact build directory followed by optional --reports and --notifications.\n' >&2; exit 1; }
for option in "${@:2}"; do
  [[ "$option" == --reports || "$option" == --notifications ]] || { printf 'Unknown runtime option.\n' >&2; exit 1; }
done
python3 scripts/verify-dashboard-build.py "$1"
./scripts/dashboard-inventory.rb
./scripts/init-dashboard-runtime.sh "${@:2}"
export ANSIBLE_SSH_ARGS="-o UserKnownHostsFile=.lab/dashboard/known_hosts -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519"
ANSIBLE_CONFIG="$lab_root/ansible/ansible.cfg" ansible-playbook \
  -i "$lab_root/.lab/dashboard/inventory.yml" "$lab_root/ansible/dashboard-runtime.yml" \
  --limit control01,storage01 --extra-vars "$(python3 -c 'import json,sys;print(json.dumps({"dashboard_application_build":sys.argv[1],"dashboard_reports_enabled":"--reports" in sys.argv[2:],"dashboard_notifications_enabled":"--notifications" in sys.argv[2:]}))' "$@")"
