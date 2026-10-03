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
state_root="$lab_root/.lab"
control_root="$state_root/control"
enrollment_root="$state_root/credentials/enrollment"
mkdir -p "$enrollment_root"
umask 077

"$lab_root/scripts/configure-control.sh"

auth_config="$state_root/credentials/control-curl.conf"
issuer='https://oidc.lab.test:8443/realms/jobman-lab'

issue_token() {
  local target="$1" username="$2" subject="$3" expected_user="$4"
  local request response key status
  request="$control_root/requests/enroll-$target-$username.json"
  response="$enrollment_root/$target-$username.json"
  key="lab-enroll-$target-$username-$(openssl rand -hex 8)"
  jq -n --arg issuer "$issuer" --arg subject "$subject" --arg user "$expected_user" \
    '{apiVersion:"jobman.control/v1alpha1",kind:"AgentEnrollmentToken",spec:{principal:{issuer:$issuer,subject:$subject},expectedUser:$user}}' \
    > "$request"
  status="$(curl --config "$auth_config" \
    --request POST --header 'Content-Type: application/json' --header "Idempotency-Key: $key" \
    --data-binary "@$request" --output "$response" --write-out '%{http_code}' \
    "https://control01.lab.test:8080/v1/namespaces/research/targets/$target/enrollment-tokens")"
  [[ "$status" == 200 || "$status" == 201 ]] || {
    printf 'could not issue enrollment for %s/%s (HTTP %s)\n' "$target" "$username" "$status" >&2
    exit 1
  }
  jq -e '.spec.token | strings | length > 0' "$response" >/dev/null
  chmod 600 "$response"
}

for username in alice bob; do
  if [[ "$username" == alice ]]; then
    subject='11111111-1111-4111-8111-111111111111'
  else
    subject='22222222-2222-4222-8222-222222222222'
  fi
  issue_token onprem-slurm "$username" "$subject" "$username"
done

if [[ "$lab_group" == full ]]; then
  for username in alice bob; do
    if [[ "$username" == alice ]]; then
      subject='11111111-1111-4111-8111-111111111111'
    else
      subject='22222222-2222-4222-8222-222222222222'
    fi
    issue_token linux-workstation "$username" "$subject" "$username"
    issue_token windows-workstation "$username" "$subject" "WINWS01\\$username"
  done
fi

ANSIBLE_CONFIG="$lab_root/ansible/ansible.cfg" \
  ansible-playbook "$lab_root/ansible/enroll.yml"
printf 'enrolled and started per-user Jobman agents\n'
