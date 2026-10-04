# Actual Dashboard workload acceptance staging

This adds an ordinary Alice-owned subprocess agent to the isolated Dashboard
Control source on control01. The reviewed preparation was applied on 2026-10-04: a real agent is enrolled and
its separate unit is active. The additive Dashboard/broker mappings and the
11-job actual subprocess acceptance scenario also passed, as recorded below.
Slurm executor preparation and native-array acceptance remain a separate phase.

The original Control 8080, original agent services/enrollments, fixture seed jobs,
directory mappings, and existing NFS objects remain unchanged. The new executor
uses Control 18443, namespace `dashboard-operations`, target
`dashboard-execution-host`, and the existing Alice UID/GID 21001. It has no
database credential and receives launch authority through normal agent mTLS.

## Exact staging artifacts

The initial staged agent uses clean Core commit
`21701b191cd4e4e063d26cad7dae31c35db6bc8c`, Go 1.26.6, linux/arm64, CGO disabled.
The four pre-existing dirty Core agent/Slurm files are excluded by `git archive`.
Keep the source tar checksum, full commit, build flags and executable digest in
`build.json`. Never replace `/usr/local/bin/jobman-agent` or
`/shared/apps/jobman/jobman-agent`; the new unit names its content-addressed binary
under `/usr/local/libexec/jobman-dashboard-lab/jobman-agent-execution-<sha256>`.

Create a fresh review directory using the exact current **isolated** Control
revision (read only `source-current.json`; do not read its private environment):

```sh
python3 scripts/dashboard-execution-plan.py plan \
  --build /absolute/exact-core-build \
  --fixture /absolute/jobman-lab/.lab/dashboard/fixture-info.json \
  --source-revision EXACT_CURRENT_CONTROL_COMMIT \
  --output /absolute/new-plan-directory
```

This command creates only local `plan.json` and a new unit file. It does not
connect to a guest. A concurrent source upgrade requires an explicit new plan.

Provisioning creates only:

- `/var/lib/jobman-dashboard-execution`, a root-owned plan/receipt/public-CA
  directory, and its Alice-owned 0700 `alice-host` state/work directories;
- `/data/jobman/alice/dashboard-execution`, a new NFS subroot under the existing
  designated-reader ACL, and a private `.jobman-log-reader.json` policy there;
- the content-addressed agent binary and
  `/etc/systemd/system/jobman-dashboard-execution-host.service`.

The NFS server checks the exact inherited access/default ACL. No existing ACL,
mode, owner, policy or log chunk is repaired or overwritten. Root squashing
remains enabled. The new unit grants writable `/data` at its existing mount root
because root cannot traverse root-squashed Alice subdirectories while building
the mount namespace; ordinary Alice ownership and the exact producer ACL still
control byte access. Private credentials stay in the separate0700 agent state.

## Reviewed apply sequence

Root coordinates timing with source upgrades and the API/worker split. Do not
run broad Lab converge, configure-control or enroll-agents scripts for this
slice. They address original services and are outside this executor change.

1. Record the reviewed SHA256 of `plan.json`, the exact source/build revisions,
   current original-service health, and the current broker/API config digests.
2. Run only Dashboard's opt-in `TestLabPrepareActualExecutionHost` with
   `JOBMAN_DASHBOARD_LAB_ROOT`, `JOBMAN_DASHBOARD_LAB_EXECUTION_PREPARE=1`,
   `JOBMAN_DASHBOARD_LAB_EXECUTION_PLAN`,
   `JOBMAN_DASHBOARD_LAB_EXECUTION_PLAN_SHA256`, and
   `JOBMAN_DASHBOARD_LAB_EXECUTION_BUILD`. The test performs synthetic native
   PKCE, verifies Alice/current Control identity, then calls the reviewed
   preparation script. No bearer token is written or passed to a subprocess.
3. Provisioning prepares the new unit but does not start it. The test uses normal
   authenticated target and enrollment-token APIs with fixed idempotency keys.
   It passes only the one-time enrollment token to the helper through stdin.
   The helper enrolls Alice, verifies secret-free agent status, persists the
   exact generation/agent receipt, then starts only the new unit.
4. Retain `.lab/dashboard/execution-fixture.json`. It contains only public source,
   target, generation, agent, revision and storage identities. A retry preserves
   all identities. An ambiguous enrollment without usable local status requires
   inspection of the private pending state; never reset or silently reenroll.
5. Prepare a new configuration file for each relevant API/report worker and
   broker with the command below. Root validates and applies these separate
   deltas during the split deployment sequence; the executor script never edits
   or restarts Dashboard/broker processes.

```sh
python3 scripts/dashboard-execution-plan.py mapping \
  --config /absolute/current-config.json \
  --receipt /absolute/jobman-lab/.lab/dashboard/execution-fixture.json \
  --role api \
  --expected-revision CURRENT_REVISION \
  --expected-sha256 CURRENT_CONFIG_SHA256 \
  --output /absolute/new-config.json
```

Use `broker` for its `logRoots` and `reports` for a report worker's `logMappings`.
The patch verifies source instance/namespace/broker, preserves every existing
field and mapping, appends only the new generation, and increments the current
revision. The broker root is the dedicated subroot, not the existing Alice
artifact root. Existing exact mappings replay without another increment.
Changed config digests/revisions require fresh review; never overwrite a
concurrent split configuration or decrement a persisted revision.

## First acceptance workload set

The opt-in Dashboard harness seals portable requests through public Jobman
protocol APIs and admits them through ordinary Control HTTP APIs. A fixed
scenario receipt plus per-intent idempotency keys bounds retries to the same
jobs; maximum 12 jobs and 30 seconds per run, with agent log/artifact caps of 1 MiB.

The verified first set is four individual success/failure/timeout/cancellation
jobs, a three-child non-array collection with `maxActive=2` and `continue`, and a
four-node host graph covering satisfied failure/any-terminal dependencies and
one unsatisfied success branch. Cancel only the named synthetic job after its
actual running observation. Verify real run/execution IDs, native execution
results, exact collection/graph child identities and dispositions, immutable
NFS stream manifests/checksums, broker reads and unrelated-user denial. Generate
metadata and redacted-log diagnosis from an actual failed job; verify original
evidence/report IDs and sealed citations, without modifying original bytes.
Read and render those exact source-qualified objects through Dashboard web and
iPhone fixtures/live transport as appropriate; distinguish simulator fixtures
from deployed API acceptance in the final evidence.

Slurm follows only after root checks resource/VM coordination and resumes the
existing scheduler/submit/compute guests. It needs a separate target/enrollment,
state and private NFS bundle root, plus an immutable agent runner at one shared
path on submit and compute hosts. Preserve original Slurm agents and runners.
Require actual `sbatch`/`sacct` identities and a native `arrayPolicy=require`
collection; seeded observations or imported history do not satisfy that gate.

## Rollback and partial failure

Before workloads exist, stop only `jobman-dashboard-execution-host.service` and
leave target/agent/state/receipts for inspection. After admission, cancel only
the job/collection/graph IDs recorded by this scenario through normal Control
APIs, wait for observed terminal states, then stop the new unit. Target draining
or disable uses its current revision and a new explicit idempotency key; no
database reset or deletion is used.

Retain immutable log/report bytes and public receipts. Do not remove the NFS
subroot or agent journal during uncertain execution. To retire mapping access,
derive a new higher-revision config from the actual current config and remove
only this exact target generation after jobs/reads are quiescent. Keep all other
fields, source pins and mappings. Do not restore an older configuration revision
or delete the target to make a rerun appear new. Remove only the named new unit
after stopping it; original services and binary paths remain untouched.

Offline checks: `python3 scripts/test-dashboard-execution.py`, Python syntax of
the three embedded preparation scripts, and compilation/skipped execution of
Dashboard's integration-tag preparation test. Actual execution, corporate AD FS,
APNs and managed-device deployment remain separate acceptance gates.

## Recorded preparation result

The explicit preparation integration test passed in 1.610 seconds against source
`d332a2b569333ae8aed9c2fc9ebc648d8eb5ba4e`, original Control instance
`e633cf92-258d-48ff-965a-fda88d68ef3a`, recovery epoch 1. It used clean Core
`21701b191cd4e4e063d26cad7dae31c35db6bc8c` agent SHA256
`e955472e6174a03503548137397328a4570e8e257372ac4409ed75a8130dfa72`.

The ordinary Control API returned target
`5556dce0-1ede-4e24-913b-cf91f6a6a7c0`, generation
`3ae8ed72-6d05-4af6-9fce-2f1c54df4b02`, and enrolled agent
`d9388e4c-e993-4ae4-91cc-62e4daf94228`. Source instance/epoch were checked before
and after. A separate health read confirmed original Control, Keycloak, isolated
Control/directory and the new agent remained active. The immutable public receipt
is `.lab/dashboard/execution-fixture.json`; no enrollment token is retained by
these scripts. The agent's normal private mTLS/session credentials stay in its
own 0700 state directory.

The API revision 3→4 and broker revision 2→3 mapping patches were independently
reviewed and applied using exact live byte digests, retained private backups,
configuration validation and scoped service restarts. The source instance/epoch
and original services remained unchanged. Future patches must start from the
actual current configuration; do not reuse those historical revisions.

## Recorded actual workload acceptance

On 2026-10-04, Dashboard's `TestLabActualHostWorkloadsAndDiagnosis` passed in
29.38 seconds (race package 30.714 seconds), using deployed Dashboard
`6aa32eb89989e79e9f5bb31a59a04801fdeca961`, source Control `d332a2b` above and
the exact clean Core agent above. Dashboard harness commit
`49de336c11f4e180047e8b747e3dffb81edc6f74` records the test and commands in
`docs/LAB_EXECUTION.md` in the Dashboard repository.

Eleven fixed-idempotency jobs cover real success/failure/timeout/running
cancellation, the three-child collection, graph predicates and the skipped
branch without a fabricated run. New NFS log manifests and exact checksums/bytes,
empty stdout, cross-namespace denial, both deterministic report profiles and
redacted citation byte offsets pass. Original source bytes are unchanged after
diagnosis. No database-inserted observations substitute for this execution.

Collection `b14c7512-8c10-42fa-bc1e-db62b21e77fd`, graph
`03c9e4f4-db13-4142-8d10-2a90845db54d`, failed job
`4cb16535-7551-4312-8b84-29549e880ebb`, and the source-qualified public receipt
remain retained. This result does not establish Slurm, multi-Control, split
runtime, real AD FS, APNs or company-managed-phone acceptance.
