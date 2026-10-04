# Dashboard actual Slurm acceptance

This scenario exercises real synthetic Slurm execution against the isolated Dashboard Control service at `https://10.77.0.21:18443`. It does not import scheduler observations or reset existing jobs. The original Control service, agents, Slurm configuration, shared application directory, and NFS exports are preserved.

Actual execution evidence is now complete for the separate no-cancellation scenario: `TestLabActualCompleteSlurmArrayAndDiagnosis` passed in 45.16 seconds (race-enabled package 46.467 seconds). Native array 48 executed all five literal task indexes; four workloads succeeded and task 2 failed with exit 7. The graph, paged Dashboard views, access denials, immutable logs, and sealed metadata/redacted-log reports passed. Source bytes were unchanged after diagnosis, and post-run verification preserved source identity/epoch and all revision 6 configuration hashes.

The first sparse-cancellation scenario failed and remains preserved. Queued tasks 1/3 had no individual terminal accounting record; they remain unresolved. Its executed tasks 0/2/4 recovered verified success/failure/success after the narrowly reviewed Core repair. This original failure is not presented as passing terminal-array acceptance.

## Separate executor

The minimal additional guests are `slurmctl01`, `submit01`, and `compute01`, resumed without provisioning. Existing `compute02` and workstation suspensions are preserved. Verify synchronized UTC, Munge, NFS, accounting, and an empty scheduler queue before submission. The initial resume needed one scoped `compute01` slurmd restart to return naturally to `IDLE`; no controller restart, node-state reset, or scheduler configuration change was used.

The executor uses:

- Alice's new target `dashboard-execution-slurm` in `dashboard-operations`.
- New state `/var/lib/jobman-dashboard-execution/alice-slurm` and unit `jobman-dashboard-execution-slurm.service` on `submit01`.
- The same content-addressed runner under `/usr/local/libexec/jobman-dashboard-lab/` on `submit01` and `compute01`. The original clean 21701b1 runner SHA-256 is `e955472e6174a03503548137397328a4570e8e257372ac4409ed75a8130dfa72`; it remains installed for original bundles. The reviewed repair 807f1f2 runner SHA-256 is `9ecc9fe75c404b85eb7b4349b55db736885db5eddd024826a4d0dbf73720a47e`. Both copies and their protected ancestors are verified before use.
- Private NFS assignment bundles at `/data/jobman/alice/dashboard-slurm-bundles`, without a log-reader ACL.
- Logs at `/data/jobman/alice/dashboard-slurm-logs`, with the existing narrowly configured reader UID 21901 policy. No blanket permission change is applied.

Existing files are validation-only. A mismatch stops preparation rather than replacing or repairing pre-existing content. Enrollment uses ordinary Control APIs and a single-use token passed through stdin. Public receipts contain IDs and hashes, never that token.

The first preparation plan attempted a runner beneath the existing group-writable `/shared/apps`; its immutable-parent check rejected that layout before creating paths or targets. The revised plan preserves `/shared/apps` unchanged and uses the local copies above.

## Prepare and review

`dashboard-slurm-inventory.py` creates a dedicated pinned SSH inventory from the three already-running managed VMs. `dashboard-slurm-plan.py plan` renders a plan from a clean Core build and the existing isolated-source fixture. Review the exact plan SHA before the opt-in preparation test:

```sh
JOBMAN_DASHBOARD_LAB_ROOT=/path/to/jobman-lab \
JOBMAN_DASHBOARD_LAB_SLURM_PREPARE=1 \
JOBMAN_DASHBOARD_LAB_SLURM_PLAN=/absolute/reviewed/plan.json \
JOBMAN_DASHBOARD_LAB_SLURM_PLAN_SHA256=<reviewed-sha256> \
JOBMAN_DASHBOARD_LAB_SLURM_BUILD=/absolute/clean-core-build \
go test -race -tags integration -run '^TestLabPrepareActualSlurmExecutor$' -count=1 -v -timeout=4m ./internal/auth
```

Run Go commands from the Dashboard repository with its pinned toolchain. The test invokes `prepare-dashboard-slurm.py` and writes `.lab/dashboard/slurm-fixture.json`. It does not submit workloads or change Dashboard/broker configuration.

After the split runtime's report and event recovery checks pass, `stage-dashboard-slurm-mappings.py` can read the reviewed revision 5 API, worker and broker files and render private local revision 6 proposals. It never applies them. Each proposal appends exactly one source-qualified target-generation mapping, preserves all other fields and credentials, and records before/after hashes, owners and modes.

Before a separately reviewed apply, recheck all original hashes and source identity, validate all staged configurations with the installed candidate, and coordinate configuration writers and service restarts. Preserve the notification delivery hold. Never restore revision 5 after revision 6 has been observed: any fallback must use a fresh current-state proposal at revision 7 or later. No automatic rollback or notification resume is provided by the staging helper.

## Mapping apply phases and interruption handling

`apply-dashboard-slurm-mappings.py` consumes the exact reviewed staging directory and an implementation digest covering the host helper, guest helper, Slurm planner and execution planner. It takes a single host lock across all mapping staging directories. Use the same explicit arguments for each separately authorized phase:

```sh
python3 scripts/apply-dashboard-slurm-mappings.py \
  --lab-root /absolute/jobman-lab \
  --staging /absolute/reviewed-mapping-directory \
  --expected-review-sha256 <review-json-sha256> \
  --expected-implementation-sha256 <canonical-implementation-map-sha256> \
  --phase preflight
```

Run `stage`, `apply`, and `restart` sequentially with `--apply`; finish with read-only `verify`. Preflight and apply must occur within fifteen minutes. Each stage validates every role's current hash before any guest staging; all installed candidates validate their private staged configuration before the apply phase can begin. All three current or provably already-applied states are checked before any swap. The restart phase requires all three swaps complete and restarts only the broker, API and worker, in that order. It verifies the actual running revision from the private observation socket; liveness alone does not establish that the new configuration was loaded. The broker phase checks the pinned source TLS capabilities, instance, epoch and original service start identities. No phase starts or restarts Control, LDAP, Keycloak, Slurm or an agent.

Guest backups and staged files use the original role owner and mode 0600. Newly created files and directories get explicit modes independent of root's umask; existing files are validation-only. File and directory fsync precede completion receipts. A partial application retains its exact original backup and pending receipt. Retrying an interrupted swap accepts only the exact reviewed new bytes with that receipt. A lost restart response is recoverable without another restart only if a different service process is already running the reviewed revision. If that proof is unavailable, stop for operator inspection; do not issue an automatic second restart. No phase rewrites an uncertain receipt or rolls back to a lower revision.

Operator receipts are private under the staging directory and on each guest under `/var/lib/jobman-dashboard-slurm-mapping-operator/`. Output exposes bounded IDs/hashes/status, not configuration bytes or command errors. The transport pins SSH host keys and bounds input, both output pipes, and deadlines. Offline boundary and interrupted-phase checks run with `python3 scripts/test-dashboard-slurm-mappings.py`.

## Isolated agent repair and rollout

The initial real array exposed two Core issues: `squeue` rejected departed IDs before accounting could be queried, and `JobIDRaw` returned allocation IDs rather than native array task IDs. One unavailable observation also blocked sibling publication. [Core PR55](https://github.com/ryancswallace/Jobman/pull/55), exact commit `807f1f2f4a89b0b400891c622d2a2cf21606e5d5`, adds verified accounting fallback with expanded `JobID`, strict exact matching, and independent sibling reconciliation. It never converts missing accounting or a cancellation acknowledgement into a terminal outcome. Independent review and hosted CI passed.

`apply-dashboard-slurm-upgrade.py` and `dashboard-slurm-upgrade-guest.py` implement separately authorized `preflight`, `install`, `swap`, `restart`, and `verify` phases. The reviewed plan SHA is `e03a18361b5b368722d545ce7080bc2b0b95c06900a3f2056d769c5183970d2c`; implementation SHA is `1c5d405fdd8f9b48801676c1d73bbad446420ed0785e5f2e77ea47f818659a3c`. The binary built twice identically from the clean commit archive with Go1.26.6/CGO disabled.

The rollout installed new content-addressed copies on compute01 and submit01, replaced only the two runner paths in the isolated unit, and restarted that unit once. It preserved the original runner, enrollment, target generation, spool, bundles, logs, ACLs, source configuration, and Dashboard revision 6. Exclusive no-follow files, exact modes, file/directory fsync, process/unit CAS, and immutable pending/completion receipts protect each phase. An uncertain restart requires positive new-process proof; the driver never blindly reissues it or automatically rolls back. API/worker checks run on storage01, broker/source checks on control01.

All five phases passed. Post-upgrade read-only checks recovered original array 45 tasks 0/2/4 and their exact stdout/stderr through Control manifests and Dashboard broker with Bob denied. Tasks1/3 remain unresolved without fabricated start/completion timestamps. These original jobs, failure logs, and receipts remain unchanged.

## Original sparse-cancellation experiment

`TestLabActualSlurmArrayAndDiagnosis` is retained as the failed original experiment with its original request documents and keys. Its five-task array used a 20-second task 0 window to cancel queued tasks 1/3. Actual allocations existed for 0/2/4 only. The test incorrectly required five terminal accounting records and expected the batch wrapper to carry workload exit 7; those assumptions are not generally valid. The runner can successfully persist a failed workload result and then exit 0 itself. Its graph/report stages were not reached before the failure.

Do not rerun this scenario expecting missing rows to become evidence, mutate its results, reset its jobs, or create new cancellation keys to hide the failed assertion. Arbitrary sparse-index submission is not claimed. The source and UI preserve literal task indexes and missing observations.

## Complete array, graph, logs and diagnosis

`TestLabActualCompleteSlurmArrayAndDiagnosis` is a separate reviewed scenario with distinct fixed request names and idempotency keys. It submits five literal indexes 0–4 with concurrency one and no cancellation. All members have a 30-second execution limit, one run, one CPU, one node, 128 MiB memory, and a one-minute scheduler wall-time limit. Three-second commands keep the scenario bounded. A task can finish between polls: a missing start timestamp remains missing; when present, its provenance must be `scheduler.observed`.

The test requires a completed exact upgrade receipt plus a live repaired-binary/unit/empty-queue preflight. All five accounting allocations must identify the exact native parent/task and run on compute01. Each wrapper is `COMPLETED` with exit 0; a separate bounded read of the exact immutable runner completion proves task 2's workload failure 7 and the other four successes. Completion reads use exact execution UUIDs and no-follow descriptors; they emit only result facts and checksums.

The graph executes a failure node, its failure-dependent successor, and a terminal-dependent successor. A success-only branch is skipped without inventing an execution. Assertions cover immutable source/target/run identities, paged Dashboard array indexes and graph dependencies, Alice ownership and Bob denials, producer-published NFS checksums and exact log bytes, and sealed metadata/redacted-log diagnosis reports. Source log bytes are verified again after diagnosis.

Only after exact-harness review and rollout verification:

```sh
JOBMAN_DASHBOARD_LAB_ROOT=/path/to/jobman-lab \
JOBMAN_DASHBOARD_LAB_SLURM_COMPLETE_RUN=1 \
JOBMAN_DASHBOARD_LAB_SLURM_UPGRADE=/absolute/reviewed-upgrade/inputs \
JOBMAN_DASHBOARD_LAB_SLURM_COMPLETE_RESULT=/absolute/new/public-receipt.json \
go test -race -tags integration -run '^TestLabActualCompleteSlurmArrayAndDiagnosis$' -count=1 -v -timeout=7m ./internal/auth
```

The successful source array is `a67631d7-6ff0-42e7-a1a8-5ecf05e52242` (native 48); graph `23d57e32-31d4-4f9f-8adb-cda32af8de69`. Metadata report task `0ea52989-9d5e-45d4-a66e-c09fc59860ca` and log-profile report task `c7061caa-4ba0-4c44-ac33-544a37751e8b` contain sealed original evidence/citations with no external provider call. The public result receipt `jobman-dashboard-actual-slurm-complete-acceptance-v1.json` SHA-256 is `186719a51c266e8d48157a508d5e485382811e7a60b1fbc32b1a2f1ab2107801`. Original failure and recovery evidence is retained separately.

Offline checks:

```sh
python3 scripts/test-dashboard-slurm.py
python3 scripts/test-dashboard-slurm-upgrade.py
python3 scripts/test-dashboard-slurm-complete.py
```

From Dashboard, run `go test -race -tags integration -run '^TestLabSlurm' ./internal/auth` without live opt-ins. These tests validate stable bounded requests, truthful omission of unobserved starts, exact native accounting identities, rejection of duplicate/unrelated rows, and deployment interruption boundaries. The Lab uses synthetic Keycloak identities; this evidence does not establish production AD FS or phone notification acceptance.
