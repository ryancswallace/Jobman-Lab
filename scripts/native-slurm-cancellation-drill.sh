#!/bin/bash
# Run as a synthetic unprivileged user on an authorized Slurm submission host.
set -euo pipefail
[[ $(id -u) != 0 ]]
export TZ=UTC
cd /tmp
name=jobman-followup-$(cat /proc/sys/kernel/random/uuid)
account=$(id -un)
parent=
queue() { timeout 5 squeue --array --noheader --jobs="$parent" --format='%i|%j|%u|%T'; }
owned() {
    awk -F'|' -v id="$1" -v n="$name" -v u="$account" -v state="${2:-}" '
        $1 == id && $2 == n && $3 == u && (state == "" || $4 == state) { yes=1 }
        END { exit !yes }
    '
}
cleanup() {
    [[ -n "$parent" ]] || return 0
    local items
    items=$(queue 2>/dev/null) || return 0
    for index in 0 1 2 3 4; do
        if owned "${parent}_$index" <<< "$items"; then timeout 5 scancel "${parent}_$index" || true; fi
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stamp() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$1"; }
snapshot() {
    stamp queue
    queue 2>/dev/null || true
    stamp accounting
    timeout 5 sacct --allocations --array --noheader --parsable2 --jobs="$parent" \
        --format=JobIDRaw,JobID,JobName%64,User,State%40,ExitCode,Start,End
}
# Slurm expands the task ID on the compute node.
# shellcheck disable=SC2016
result=$(timeout 10 sbatch --parsable --partition=cpu --array=0-4%1 --time=00:02:00 \
    --deadline=now+5minutes --cpus-per-task=1 --mem=128M --job-name="$name" --chdir=/tmp \
    --output=/dev/null --error=/dev/null --export=NIL \
    --wrap='case "$SLURM_ARRAY_TASK_ID" in 0) /bin/sleep 20;; 1|3) exec /bin/sleep 90;; 2) exit 7;; 4) exit 0;; *) exit 64;; esac')
[[ "$result" =~ ^([1-9][0-9]*)(\;[a-zA-Z0-9._-]+)?$ ]]
parent=${BASH_REMATCH[1]}
stamp "submitted ${parent} ${name} ${account}"
deadline=$((SECONDS+30))
while ((SECONDS < deadline)); do
    items=$(queue)
    if owned "${parent}_1" PENDING <<< "$items" && owned "${parent}_3" PENDING <<< "$items"; then
        snapshot
        stamp "cancel-request ${parent}_1 ${parent}_3"
        timeout 5 scancel "${parent}_1" "${parent}_3"
        snapshot
        break
    fi
    sleep 1
done
((SECONDS < deadline))
for _ in {1..12}; do
    sleep 4
    snapshot
done
