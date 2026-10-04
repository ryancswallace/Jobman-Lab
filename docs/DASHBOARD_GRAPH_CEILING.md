# Inert graph at the client ceiling

This scoped fixture supports live HTTP traversal of one synthetic graph with
10,000 nodes and 100,000 edges. The graph uses normal Control Store admission in
the existing primary `dashboard-operations` namespace. It creates one dedicated
host target without an agent or enrollment. The jobs remain accepted with no run,
execution or scheduler submission. This does not represent 10,000 executed jobs.

The wrapper preserves the original Control, Keycloak, both isolated Control and
directory services, broker, existing metadata and source configuration. It never
restarts services, migrates a database, installs directory grants, rewrites API or
broker configuration, modifies event-feed recovery or changes the delivery hold.
Alice already has namespace administrator access; Bob is denied. The existing
scale viewer groups gain no additional namespace access.

## Immutable inputs and boundaries

Use the reviewed clean Linux ARM64 helper build, separately from the running
Control service. `build.json` contains exactly `revision`, `os`, `architecture`,
`binarySHA256` and `twiceIdentical`; the last field records two independently built
identical binaries. The sibling executable is `jobman-control-lab-helper`.
The wrapper validates its hash, ELF architecture and linked revision before
installing a new immutable path under
`/usr/local/libexec/jobman-dashboard-graph-ceiling/<sha256>/`.

The existing primary service must remain at Control commit
`04bd83db28bc24155c87e0ceea61c047320fca07`, schema 21, recovery epoch 1 and instance
`e633cf92-258d-48ff-965a-fda88d68ef3a`. The dedicated database is
`jobman_dashboard_control`. No original or secondary database is mutated.
The source has a verified-TLS DSN in its existing root-only credential file;
it is read privately on the guest and never passed in command arguments.

Archive these four scripts together before taking a snapshot:

- `prepare-dashboard-graph-ceiling.py`
- `dashboard-graph-ceiling-plan.py`
- `dashboard-graph-ceiling-guest.py`
- The existing `dashboard-scale-source-common.py`, unchanged

The plan binds each implementation hash. The test and this runbook accompany the
archive but are not executed remotely. The explicit `--lab-root` locates the
existing private pinned SSH inventory/known-hosts file even when the driver is
run from an archived directory. Only `control01` and `pg01` are reachable through
its fixed commands. Private files require the expected owner, mode, one hard
link, no symlink and stable inode; private roots require their exact owner/mode.

## Review and phased execution

Keep other source mutations paused from preflight through verification. The
wrapper will stop if retained source process/configuration or existing immutable
metadata differs, including unrelated new jobs or agents. Do not weaken a guard
to continue across another task's mutation; retain the failed evidence and
prepare a new reviewed operation where appropriate.

Obtain the implementation digest without guest access:

```sh
python3 /private/archive/scripts/prepare-dashboard-graph-ceiling.py \
  --phase digest --lab-root /Users/rcw/home/code/jobman-lab
```

Use one new host staging directory below an existing private owned parent.
The following phases require the returned `--implementation-sha256`, an explicit
`--lab-root`, and the same `--staging` directory:

1. `stage --helper-build <private-build-directory> --apply` installs only the
   exact helper executable. Existing identical bytes may be verified again;
   changed bytes are refused. It preserves source process/configuration hashes.
2. `preflight --helper-build <private-build-directory>` performs read-only
   source/policy and database observations and writes local `plan.json`. Review
   its exact SHA, source identities, existing job count, queue headroom, schema,
   six source-file hashes and seven process snapshots before mutation.
3. `quota --plan-sha256 <reviewed-plan-sha> --apply` requires a preflight no older
   than 15 minutes. The normal namespace policy CAS changes only `maxQueuedJobs`
   by exactly 10,000 if current headroom requires it. Otherwise the exact policy
   stays unchanged. `maxGraphNodes` must already permit 10,000; it is never raised.
4. `seed --plan-sha256 <same-sha> --apply` uses the normal Store target/graph
   methods and admits the one fixed graph. The helper verifies all bounded node
   and dependency pages and absence of runs/executions/agents before completion.
5. `verify --plan-sha256 <same-sha>` reads the completed helper evidence and live
   facts, repeats preservation checks and exports the public source-qualified
   manifest to the private host `handoff/` directory. It requires existing guest
   state; it does not create a missing operation.

These phase names are arguments to `--phase`. The helper's canonical graph
request is larger than the source HTTP admission limit; calling normal Store
admission privately does not change that public limit. Each SQL preservation
snapshot is read-only with a 15-second statement limit. Guest commands receive
the remaining phase deadline, including a late-success check. Guest seed/verify
are bounded to 520 seconds and their host transport to 560 seconds; other phases
use 100/120 seconds. A failure does not imply the remote mutation was rolled back.

Exclusive host and root-owned guest locks prevent competing invocations. Durable
pending records precede quota/seed mutations. If the remote action completed but
the reply was lost, repeating the same phase verifies its exact completion
receipt and current facts without reissuing admission. If only a pending receipt
exists, the wrapper stops for inspection. Preserve all archives, plans, pending
and completion receipts. Do not remove them, reset a database, regenerate a key,
reduce a quota, cancel prior jobs or create a second graph to force a retry.

## Handoff and acceptance

The private handoff contains `graph.json`, both quota intent/completion files,
both seed intent/completion files and `driver-receipt.json`. Hashes bind the helper
revision, approved quota, source instance/namespace, actual graph and node IDs,
manifest revision and exact 10,000-index mapping. It contains no credential,
workload command, token or log content. Existing metadata hashes are private
operational evidence, not user-facing API fields.

The root neighborhood contains 10,000 nodes and 100,000 edges. The induced
one-hop neighborhood of node index 1 contains 12 nodes and 66 edges; index 9,999
contains two nodes and one edge. Bounded HTTP traversal must preserve exact
source/run-free facts, current authorization and opaque cursor binding. Alice's
access and Bob's denial must be checked independently. A complete HTTP traversal
is separate evidence from a rendered client test.

No live graph has been admitted by authoring or running the offline suite:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-dashboard-graph-ceiling.py
```

The Control helper's disposable verified-TLS PostgreSQL test passed full ordinary
admission, all node/edge pages, neighborhood totals, existing-job preservation
and no execution in 81.52 seconds (race process 83.005 seconds). Earlier verifier
SQL/projection test failures remain retained. Browser rendering remains subject
to the existing recorded browser block; do not switch browser/driver/origin to
bypass it. Native simulator fixtures and physical-device accessibility are
separate from this source fixture's repository/HTTP evidence.
