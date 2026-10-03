#!/usr/bin/env bash
set -euo pipefail

# WinRM's proxy discovery enters macOS frameworks from Ansible worker processes.
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"
state_root="$lab_root/.lab"
credentials="$state_root/credentials/lab.env"
control_root="$state_root/control"

[[ -f "$credentials" ]] || "$lab_root/scripts/init-state.sh"
set -a
# shellcheck disable=SC1090
source "$credentials"
set +a

mkdir -p "$control_root/requests" "$control_root/responses"
umask 077

urlencode() {
  jq -nr --arg value "$1" '$value|@uri'
}

oidc_token() {
  local username="$1" password="$2" output="$3" form
  form="grant_type=password&client_id=jobman-control&username=$(urlencode "$username")&password=$(urlencode "$password")"
  printf '%s' "$form" | curl --fail --silent --show-error \
    --resolve oidc.lab.test:8443:10.77.0.21 \
    --cacert "$state_root/certs/lab-ca.crt" \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary @- \
    https://oidc.lab.test:8443/realms/jobman-lab/protocol/openid-connect/token \
    | jq -er '.access_token' > "$output"
  chmod 600 "$output"
}

oidc_token alice "$JOBMAN_LAB_ALICE_PASSWORD" "$state_root/credentials/alice.token"
oidc_token bob "$JOBMAN_LAB_BOB_PASSWORD" "$state_root/credentials/bob.token"

auth_config="$state_root/credentials/control-curl.conf"
{
  printf 'header = "Authorization: Bearer %s"\n' "$(<"$state_root/credentials/alice.token")"
  printf 'cacert = "%s"\n' "$state_root/certs/lab-ca.crt"
  printf 'resolve = "control01.lab.test:8080:10.77.0.21"\n'
  printf 'silent\nshow-error\nfail-with-body\n'
} > "$auth_config"
chmod 600 "$auth_config"

api_put_or_post() {
  local method="$1" path="$2" body="$3" response="$4" idempotency_key="$5" status
  status="$(curl --config "$auth_config" \
    --request "$method" \
    --header 'Content-Type: application/json' \
    --header "Idempotency-Key: $idempotency_key" \
    --data-binary "@$body" \
    --output "$response" \
    --write-out '%{http_code}' \
    "https://control01.lab.test:8080$path")"
  [[ "$status" == 200 || "$status" == 201 ]] || {
    printf 'Control API request failed with HTTP %s: %s\n' "$status" "$path" >&2
    return 1
  }
}

cat > "$control_root/requests/bob-membership.json" <<'JSON'
{"apiVersion":"jobman.control/v1alpha1","kind":"Membership","spec":{"principal":{"issuer":"https://oidc.lab.test:8443/realms/jobman-lab","subject":"22222222-2222-4222-8222-222222222222","displayName":"Bob Lab"},"role":"submitter"}}
JSON
api_put_or_post PUT "/v1/namespaces/research/memberships" \
  "$control_root/requests/bob-membership.json" "$control_root/responses/bob-membership.json" \
  lab-bob-membership-v1

write_target() {
  local name="$1" kind="$2" backend="$3" os_name="$4" partitions="$5"
  jq -n \
    --arg name "$name" --arg kind "$kind" --arg backend "$backend" --arg os "$os_name" \
    --argjson partitions "$partitions" \
    '{apiVersion:"jobman.control/v1alpha1",kind:"Target",metadata:{name:$name},spec:{kind:$kind,executionBackend:$backend,runtimes:["native"],operatingSystems:[$os],architectures:["arm64"],partitions:$partitions,logStore:{name:"lab-nfs",version:1},artifactStores:[{name:"lab-nfs",version:1}],provider:{kind:"on-prem"}}}' \
    > "$control_root/requests/target-$name.json"
  api_put_or_post POST "/v1/namespaces/research/targets" \
    "$control_root/requests/target-$name.json" "$control_root/responses/target-$name.json" \
    "lab-target-$name-v1"
}

write_target onprem-slurm slurm slurm linux '[{"name":"cpu","isDefault":true}]'
write_target linux-workstation host subprocess linux '[]'
write_target windows-workstation host subprocess windows '[]'

jq -s 'map({key:.metadata.name,value:.metadata.generationId})|from_entries' \
  "$control_root"/responses/target-*.json > "$control_root/target-generations.json"
chmod 600 "$control_root/target-generations.json"

ANSIBLE_CONFIG="$lab_root/ansible/ansible.cfg" \
  ansible-playbook "$lab_root/ansible/tokens.yml"
printf 'configured synthetic namespace, membership, profiles, and targets\n'
