#!/usr/bin/env bash
set -euo pipefail
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"
[[ $# == 1 && "$1" == /* ]] || { printf 'Usage: %s /absolute/path/to/exact-control-build-directory\n' "$0" >&2; exit 1; }
python3 - "$1" <<'PY'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]);meta=json.loads((root/'build.json').read_text())
assert meta['platform']=='linux/arm64' and len(meta['revision'])==40
for name in ['jobman-control','jobman-control-lab-helper']:
 assert hashlib.sha256((root/name).read_bytes()).hexdigest()==meta['sha256'][name]
print('Verified exact Control fixture build '+meta['revision'])
PY
./scripts/dashboard-inventory.rb
export ANSIBLE_SSH_ARGS="-o UserKnownHostsFile=.lab/dashboard/known_hosts -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519"
ANSIBLE_CONFIG="$lab_root/ansible/ansible.cfg" ansible-playbook \
  -i "$lab_root/.lab/dashboard/inventory.yml" "$lab_root/ansible/dashboard-source.yml" \
  --limit control01 --extra-vars "$(python3 -c 'import json,sys;print(json.dumps({"dashboard_control_build":sys.argv[1]}))' "$1")"
