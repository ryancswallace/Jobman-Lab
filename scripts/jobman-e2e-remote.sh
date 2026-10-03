#!/usr/bin/env bash
set -euo pipefail
lab_group="${JOBMAN_LAB_GROUP:-full}"
job_wait_timeout="${JOBMAN_LAB_JOB_WAIT_TIMEOUT:-180s}"
stage="initialization"
trap 'printf "Jobman E2E failed during %s\n" "$stage" >&2' ERR

wait_for_job() {
  timeout --foreground "$job_wait_timeout" \
    jobman shared wait --poll-interval 1s --json "$1" >/dev/null
}

stage="Slurm submission"
submission="$(jobman shared run --name slurm-smoke --target onprem-slurm --partition cpu --cpu 1 --memory 256MiB --wall-time 5m --json -- /usr/bin/printf 'jobman-slurm-smoke\n')"
stage="Slurm submission response validation"
job_id="$(jq -er '.data.job.metadata.id' <<<"$submission")"
stage="Slurm job completion wait"
wait_for_job "$job_id"
stage="Slurm log retrieval"
logs="$(jobman shared logs "$job_id")"
stage="Slurm log validation"
grep -q 'jobman-slurm-smoke' <<<"$logs"
printf 'Jobman Slurm smoke job completed: %s\n' "$job_id"

stage="Linux workstation target discovery"
if [[ "$lab_group" == full ]] && jobman shared target show linux-workstation >/dev/null 2>&1; then
  stage="Linux workstation submission"
  submission="$(jobman shared run --name linux-smoke --target linux-workstation --json -- /usr/bin/printf 'jobman-linux-smoke\n')"
  stage="Linux workstation submission response validation"
  job_id="$(jq -er '.data.job.metadata.id' <<<"$submission")"
  stage="Linux workstation job completion wait"
  wait_for_job "$job_id"
  stage="Linux workstation log validation"
  jobman shared logs "$job_id" | grep -q 'jobman-linux-smoke'
  printf 'Jobman Linux workstation smoke job completed: %s\n' "$job_id"
fi

stage="Windows workstation target discovery"
if [[ "$lab_group" == full ]] && jobman shared target show windows-workstation >/dev/null 2>&1; then
  stage="Windows workstation submission"
  submission="$(jobman shared run --name windows-smoke --target windows-workstation --json -- C:\\Windows\\System32\\cmd.exe /c echo jobman-windows-smoke)"
  stage="Windows workstation submission response validation"
  job_id="$(jq -er '.data.job.metadata.id' <<<"$submission")"
  stage="Windows workstation job completion wait"
  wait_for_job "$job_id"
  stage="Windows workstation log validation"
  jobman shared logs "$job_id" | grep -q 'jobman-windows-smoke'
  printf 'Jobman Windows workstation smoke job completed: %s\n' "$job_id"
fi
