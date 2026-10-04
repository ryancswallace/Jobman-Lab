#!/usr/bin/env bash
set -euo pipefail
lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
umask 077
state_root="$lab_root/.lab"
[[ -s "$state_root/certs/lab-ca.crt" && -s "$state_root/certs/lab-ca.key" && -s "$state_root/credentials/lab.env" ]] || {
  printf 'Initialize the existing Lab first; this command never replaces its CA or credentials.\n' >&2
  exit 1
}
mkdir -p "$state_root/dashboard" "$state_root/credentials"
credentials="$state_root/credentials/dashboard.env"
touch "$credentials"
for name in JOBMAN_LAB_DASHBOARD_PASSWORD JOBMAN_LAB_DASHBOARD_DDL_PASSWORD \
  JOBMAN_LAB_DASHBOARD_CONTROL_PASSWORD JOBMAN_LAB_DASHBOARD_WEB_SECRET \
  JOBMAN_LAB_DASHBOARD_ALICE_PASSWORD JOBMAN_LAB_DASHBOARD_BOB_PASSWORD; do
  if ! grep -q "^${name}=" "$credentials"; then
    printf '%s=%s\n' "$name" "$(openssl rand -hex 32)" >> "$credentials"
  fi
done
chmod 600 "$credentials"
cert="$state_root/certs/pg01.lab.test.crt"
key="$state_root/certs/pg01.lab.test.key"
if [[ ! -e "$cert" && ! -e "$key" ]]; then
  openssl req -new -newkey rsa:3072 -nodes -subj '/CN=pg01.lab.test' \
    -addext 'subjectAltName=DNS:pg01.lab.test,IP:10.77.0.20,IP:127.0.0.1' \
    -addext 'extendedKeyUsage=serverAuth' -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -keyout "$key" -out "$state_root/dashboard/pg01.csr" 2>/dev/null
  openssl x509 -req -sha256 -days 365 -in "$state_root/dashboard/pg01.csr" \
    -CA "$state_root/certs/lab-ca.crt" -CAkey "$state_root/certs/lab-ca.key" \
    -CAserial "$state_root/dashboard/pg01-ca.srl" -CAcreateserial \
    -copy_extensions copyall -out "$cert" 2>/dev/null
fi
[[ -s "$cert" && -s "$key" ]] || { printf 'Incomplete PostgreSQL key/certificate pair; repair explicitly.\n' >&2; exit 1; }
openssl verify -CAfile "$state_root/certs/lab-ca.crt" "$cert" >/dev/null
openssl x509 -in "$cert" -checkend 86400 -noout >/dev/null
chmod 600 "$key"
printf 'Dashboard synthetic credentials and PostgreSQL certificate are ready under .lab/.\n'
