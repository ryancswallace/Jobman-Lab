#!/bin/bash
# Exercise only newly created paths on the synthetic Lab storage and submit guests.
set -euo pipefail

if [[ $# != 1 || ! -f "$1" || ! -r "$1" ]]; then
    echo 'Provide the Linux ARM64 Core artifact integration test binary.' >&2
    exit 2
fi
binary=$1
run=$(uuidgen | tr '[:upper:]' '[:lower:]')
[[ "$run" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]]
name=".jobman-filesystem-drill-$run"
storage=jobman-lab-storage01
submit=jobman-lab-submit01
local_root="/var/tmp/$name"
export_root="/srv/lab/shared/$name"
client_root="/shared/$name"
guest_binary="/var/tmp/$name.test"
local_owned=0 export_owned=0 storage_binary_owned=0 submit_binary_owned=0
cleanup() {
    local result=$?
    trap - EXIT
    if (( submit_binary_owned )); then
        prlctl exec "$submit" "rm -f -- '$guest_binary/probe' && rmdir -- '$guest_binary'" || result=1
    fi
    if (( storage_binary_owned )); then
        prlctl exec "$storage" "rm -f -- '$guest_binary/probe' && rmdir -- '$guest_binary'" || result=1
    fi
    if (( local_owned )); then
        prlctl exec "$storage" "rm -rf --one-file-system -- '$local_root'" || result=1
    fi
    if (( export_owned )); then
        prlctl exec "$storage" "rm -rf --one-file-system -- '$export_root'" || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

writer='setpriv --reuid=21001 --regid=21001 --clear-groups'
reader='setpriv --reuid=21901 --regid=21901 --clear-groups'
denied='setpriv --reuid=21002 --regid=21002 --clear-groups'
execution='namespaces/research/jobs/01990000-0000-4000-8000-000000000001/executions/01990000-0000-4000-8000-000000000002'
chunk="$execution/logs/stdout/00000001.chunk"
retry="$execution/logs/stdout/00000002.chunk"
private="$execution/artifacts/result"
log_shaped="$execution/logs/stdout/00000003.chunk"

printf 'Filesystem drill %s\n' "$run"
shasum -a 256 "$binary"
prlctl exec "$storage" "mkdir -m 0700 -- '$local_root'"
local_owned=1
prlctl exec "$storage" "mkdir -m 0700 -- '$export_root'"
export_owned=1
prlctl exec "$storage" "mkdir -m 0700 -- '$guest_binary'"
storage_binary_owned=1
prlctl exec "$submit" "mkdir -m 0700 -- '$guest_binary'"
submit_binary_owned=1

# Transfer only the synthetic executable, through the guest command channel.
for guest in "$storage" "$submit"; do
    prlctl exec "$guest" "cat > '$guest_binary/probe' && chmod 0555 '$guest_binary/probe' && chmod 0711 '$guest_binary'" < "$binary"
    expected=$(shasum -a 256 "$binary" | cut -d ' ' -f 1)
    actual=$(prlctl exec "$guest" "sha256sum '$guest_binary/probe'" | cut -d ' ' -f 1)
    [[ "$expected" == "$actual" ]]
done

probe() {
    local guest=$1 root=$2 server_root=$3
    prlctl exec "$storage" "setfacl -b -k '$server_root' &&
        chown 21001:21001 '$server_root' &&
        chmod g-s '$server_root' &&
        setfacl -m u::rwx,u:21901:r-x,g::---,m::r-x,o::--- '$server_root' &&
        setfacl -m d:u::rwx,d:u:21901:r-x,d:g::---,d:m::r-x,d:o::--- '$server_root'"
    prlctl exec "$guest" "findmnt -rno FSTYPE -T '$root' &&
        $writer env JOBMAN_TEST_LOG_READER_ROOT='$root' '$guest_binary/probe' -test.v -test.run '^TestLogReaderProvisionedFilesystem$' &&
        $writer stat -c 'root mode=%a writer=%u' '$root' &&
        $reader env JOBMAN_TEST_LOG_READER_READ_ROOT='$root' '$guest_binary/probe' -test.v -test.run '^TestLogReaderProvisionedRead$' &&
        $reader grep -qx 'retry after interruption' '$root/$retry' &&
        ! $denied test -r '$root/$chunk' &&
        ! $reader test -w '$root/$chunk' &&
        ! $reader test -r '$root/$private' &&
        ! $reader test -r '$root/$log_shaped' &&
        ! $reader test -r '$root/.jobman-log-reader.json'"

    # Agent credentials and runner bundles use explicit modes. An inherited
    # default ACL can override umask alone. The files here are stand-ins.
    prlctl exec "$guest" "$writer sh -c 'umask 077; mkdir -m 0700 \"$root/private-state\" &&
        printf synthetic > \"$root/private-state/credentials.json\" &&
        printf synthetic > \"$root/private-state/runner-bundle.json\" &&
        chmod 0600 \"$root/private-state/credentials.json\" \"$root/private-state/runner-bundle.json\"' &&
        $writer test -r '$root/private-state/runner-bundle.json' &&
        ! $reader test -r '$root/private-state/credentials.json' &&
        ! $reader test -r '$root/private-state/runner-bundle.json' &&
        ! $denied test -r '$root/private-state/runner-bundle.json'"
    if [[ "$guest" == "$submit" ]]; then
        prlctl exec "$guest" "! test -r '$root/$chunk'"
    fi

    # Revoke only this test reader on the owned disposable tree, at the ACL server.
    prlctl exec "$storage" "setfacl -R -P -x u:21901 '$server_root' &&
        find '$server_root' -xdev -type d -exec setfacl -x d:u:21901 {} +"
    prlctl exec "$guest" "$writer env JOBMAN_TEST_LOG_READER_REVOKED_ROOT='$root' '$guest_binary/probe' -test.v -test.run '^TestLogReaderProvisionedRevoked$'"
    prlctl exec "$guest" "! $reader test -r '$root/$chunk' &&
        ! $denied test -r '$root/$chunk' && $writer grep -qx 'shared synthetic log' '$root/$chunk'"
    printf 'Cross-user probe passed on %s\n' "$guest"
}

probe "$storage" "$local_root" "$local_root"
prlctl exec "$submit" "test \"\$(findmnt -rno FSTYPE -T /shared)\" = nfs4"
probe "$submit" "$client_root" "$export_root"
