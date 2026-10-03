#!/usr/bin/env bash
set -euo pipefail

required_version() {
  local command_name="$1" expected="$2" actual="$3"
  if [[ "$actual" != "$expected" ]]; then
    printf '%s version mismatch: expected %s, found %s\n' "$command_name" "$expected" "$actual" >&2
    return 1
  fi
  printf '%-20s %s\n' "$command_name" "$actual"
}

if ! command -v vagrant >/dev/null; then
  printf '%s\n' \
    'Vagrant requires an interactive macOS administrator prompt.' \
    'Run this once in Terminal, then rerun make bootstrap:' \
    '  brew install --cask vagrant' >&2
  exit 1
fi

required_version vagrant 2.4.9 "$(vagrant --version | awk '{print $2}')"
required_version packer 1.16.0 "$(packer version | awk 'NR == 1 {sub(/^Packer v/, ""); print}')"
mkdir -p .lab/ansible/tmp
required_version ansible-community 14.3.1 "$(ansible-community --version | awk 'NR == 1 {print $4}')"
required_version ansible-core 2.21.3 "$(ANSIBLE_LOCAL_TEMP=.lab/ansible/tmp ansible --version | awk 'NR == 1 {gsub(/[][]/, "", $3); print $3}')"

plugin_version="$(vagrant plugin list | awk '$1 == "vagrant-parallels" {gsub(/[(),]/, "", $2); print $2}')"
if [[ -z "$plugin_version" ]]; then
  printf '%s\n' 'Installing pinned vagrant-parallels plugin 2.4.9...'
  vagrant plugin install vagrant-parallels --plugin-version 2.4.9
  plugin_version="$(vagrant plugin list | awk '$1 == "vagrant-parallels" {gsub(/[(),]/, "", $2); print $2}')"
fi
required_version vagrant-parallels 2.4.9 "$plugin_version"
