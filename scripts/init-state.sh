#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state_root="$lab_root/.lab"
umask 077

mkdir -p \
  "$state_root/ansible/collections" \
  "$state_root/ansible/tmp" \
  "$state_root/artifacts/bin/linux-arm64" \
  "$state_root/artifacts/bin/windows-arm64" \
  "$state_root/boxes" \
  "$state_root/cache" \
  "$state_root/certs" \
  "$state_root/credentials" \
  "$state_root/packer/plugins" \
  "$state_root/ssh/users"
: > "$state_root/ssh/known_hosts"

for lab_user in alice bob; do
  key_path="$state_root/ssh/users/$lab_user"
  if [[ ! -f "$key_path" ]]; then
    ssh-keygen -q -t ed25519 -N '' -C "$lab_user@jobman-lab" -f "$key_path"
  fi
done

ca_key="$state_root/certs/lab-ca.key"
ca_cert="$state_root/certs/lab-ca.crt"
if [[ ! -f "$ca_key" || ! -f "$ca_cert" ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -subj '/CN=Jobman Lab Development CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$ca_key" -out "$ca_cert" 2>/dev/null
fi

agent_ca_key="$state_root/certs/agent-ca.key"
agent_ca_cert="$state_root/certs/agent-ca.crt"
agent_ca_valid=false
if [[ -f "$agent_ca_key" && -f "$agent_ca_cert" ]] &&
  openssl x509 -in "$agent_ca_cert" -noout -text 2>/dev/null | grep -q 'CA:TRUE' &&
  openssl x509 -in "$agent_ca_cert" -noout -text 2>/dev/null | grep -q 'Certificate Sign'; then
  agent_ca_valid=true
fi
if [[ "$agent_ca_valid" != true ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -subj '/CN=Jobman Lab Agent CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign' \
    -keyout "$agent_ca_key" -out "$agent_ca_cert" 2>/dev/null
fi

python3 "$lab_root/scripts/ensure-oidc-tls.py"

if [[ ! -f "$state_root/credentials/lab.env" ]]; then
  pg_password="$(openssl rand -hex 24)"
  mariadb_password="$(openssl rand -hex 24)"
  keycloak_password="$(openssl rand -hex 24)"
  alice_password="$(openssl rand -base64 18 | tr -d '=+/')"
  bob_password="$(openssl rand -base64 18 | tr -d '=+/')"
  agent_token_key="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')"
  cat > "$state_root/credentials/lab.env" <<EOF
JOBMAN_LAB_POSTGRES_PASSWORD=$pg_password
JOBMAN_LAB_MARIADB_PASSWORD=$mariadb_password
JOBMAN_LAB_KEYCLOAK_ADMIN_PASSWORD=$keycloak_password
JOBMAN_LAB_ALICE_PASSWORD=$alice_password
JOBMAN_LAB_BOB_PASSWORD=$bob_password
JOBMAN_LAB_AGENT_TOKEN_KEY=$agent_token_key
EOF
fi
if ! grep -q '^JOBMAN_LAB_AGENT_TOKEN_KEY=' "$state_root/credentials/lab.env"; then
  agent_token_key="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')"
  printf 'JOBMAN_LAB_AGENT_TOKEN_KEY=%s\n' "$agent_token_key" >> "$state_root/credentials/lab.env"
fi

if [[ ! -f "$state_root/credentials/munge.key" ]]; then
  openssl rand 1024 > "$state_root/credentials/munge.key"
fi

chmod 600 "$state_root/credentials/lab.env" "$state_root/credentials/munge.key" \
  "$state_root"/certs/*.key "$state_root"/ssh/users/*
printf 'initialized ignored lab state under %s\n' "$state_root"
