#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"

for command_name in ansible-playbook packer ruby shellcheck; do
  command -v "$command_name" >/dev/null || {
    printf 'missing CI dependency: %s\n' "$command_name" >&2
    exit 1
  }
done

for script in scripts/*.sh; do
  bash -n "$script"
done
shellcheck scripts/*.sh

ruby -c Vagrantfile >/dev/null
ruby -c scripts/generate-inventory.rb >/dev/null
ruby -c scripts/dashboard-inventory.rb >/dev/null
python3 -c "import ast, pathlib; [ast.parse(p.read_text()) for root in ['scripts', 'ansible/roles'] for p in pathlib.Path(root).rglob('*.py')]"
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-dashboard-provisioning.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-dashboard-build.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-dashboard-directory.py
ruby -r rexml/document -e 'REXML::Document.new(File.read(ARGV.fetch(0)))' \
  packer/http/Autounattend.xml

packer fmt -check -recursive packer

mkdir -p .lab/ansible/tmp .lab/ssh
touch .lab/ssh/known_hosts
export ANSIBLE_CONFIG="$lab_root/ansible/ansible.cfg"
export ANSIBLE_LOCAL_TEMP="$lab_root/.lab/ansible/tmp"

for playbook in \
  ansible/site.yml \
  ansible/dashboard-infra.yml \
  ansible/dashboard-source.yml \
  ansible/dashboard-runtime.yml \
  ansible/tokens.yml \
  ansible/enroll.yml \
  ansible/validate.yml
do
  ansible-playbook --syntax-check -i ansible/inventory.ci.yml "$playbook"
done

printf 'Jobman Lab static validation passed\n'
