#!/usr/bin/env bash
set -euo pipefail
lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"
for option in "$@"; do
  [[ "$option" == --reports || "$option" == --notifications ]] || { printf 'Usage: %s [--reports] [--notifications]\n' "$0" >&2; exit 1; }
done
umask 077
runtime_root="$lab_root/.lab/dashboard/runtime"
[[ -s .lab/dashboard/fixture-info.json && -s .lab/dashboard/oidc-public.json ]] || { printf 'Prepare the isolated Control source first.\n' >&2; exit 1; }
mkdir -p "$runtime_root"
chmod 700 "$runtime_root"
make_certificate() {
  local name="$1" common_name="$2" purpose="$3" alternatives="$4"
  local key="$runtime_root/$name.key" cert="$runtime_root/$name.crt"
  if [[ ! -e "$key" && ! -e "$cert" ]]; then
    openssl req -new -newkey rsa:3072 -nodes -subj "/CN=$common_name" \
      -addext "extendedKeyUsage=$purpose" \
      -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
      -addext "subjectAltName=$alternatives" -keyout "$key" -out "$runtime_root/$name.csr" 2>/dev/null
    openssl x509 -req -sha256 -days 7 -in "$runtime_root/$name.csr" \
      -CA .lab/certs/lab-ca.crt -CAkey .lab/certs/lab-ca.key \
      -CAserial "$runtime_root/ca.srl" -CAcreateserial -copy_extensions copyall -out "$cert" 2>/dev/null
  fi
  [[ -s "$key" && -s "$cert" ]] || { printf 'Incomplete runtime certificate pair; inspect private material.\n' >&2; exit 1; }
  openssl verify -CAfile .lab/certs/lab-ca.crt "$cert" >/dev/null
  openssl x509 -in "$cert" -checkend 3600 -noout >/dev/null
  chmod 600 "$key" "$cert"
}
make_certificate dashboard-server dashboard.lab.test serverAuth 'DNS:dashboard.lab.test,IP:10.77.0.10'
make_certificate broker-server dashboard-lab-broker serverAuth 'IP:10.77.0.21,IP:127.0.0.1'
make_certificate dashboard-broker-client dashboard-lab-broker-caller clientAuth 'URI:urn:jobman:dashboard-lab:broker-caller'
if [[ ! -f "$runtime_root/dashboard-broker-signing-key.pem" ]]; then
  openssl genpkey -algorithm ED25519 -out "$runtime_root/dashboard-broker-signing-key.pem" 2>/dev/null
fi
openssl pkey -in "$runtime_root/dashboard-broker-signing-key.pem" -pubout -out "$runtime_root/dashboard-broker-signing-public.pem" 2>/dev/null
if [[ ! -f "$runtime_root/encryption-key" ]]; then openssl rand 32 > "$runtime_root/encryption-key"; fi
python3 scripts/render-dashboard-runtime.py "$@"
printf 'Private runtime trust/configuration is ready under .lab/dashboard/runtime; no secrets printed.\n'
