# Prepared API/worker split for the synthetic Lab

This is a staged migration plan, not a record that the split has been applied.
Preparation makes no guest connection, database change or service change. The
reviewed exact candidate and a fresh live preflight are required before a separate
apply operation. Production systems are outside this plan.

The first split keeps one API and one worker bundle on storage01. The worker runs
ingestion, rule activation/evaluation, diagnosis and retention. It has no APNs
provider, delivery component, browser secret, server TLS key, authentication master
key, or device-token decryption key. The source/broker grant union is correspondingly
limited. This proves no physical iPhone/APNs or actual AD FS acceptance.

| Scope | New identity / location |
| --- | --- |
| API | `jobman-dashboard-api`, proposed UID/GID21904; `/etc/jobman-dashboard-api-lab` |
| Worker | `jobman-dashboard-worker`, proposed UID/GID21905; `/etc/jobman-dashboard-worker-lab` |
| Report readers | dedicated proposed GID21906; API and worker only |
| API database | `jobman_dashboard_api`, reviewed `api` grants |
| Worker database | `jobman_dashboard_worker`, reviewed ingestion+notifications+reports+retention grants |
| Observation database | `jobman_dashboard_operator`, exact read-only operator grants |
| Operator configuration | root-only `/etc/jobman-dashboard-operator-lab` |
| Immutable candidate | `/opt/jobman-dashboard-lab/releases/<full-commit>` |
| Shared report objects | `/var/lib/jobman-dashboard-reports-lab`, worker-owned0750, reader group |
| Private health/metrics | per-process `/run/jobman-dashboard-{api,worker}-lab/observe.sock` |

Proposed numeric IDs are **not yet verified free** on the guests. Apply must check
both numeric and named identities before creation. A conflict fails; the script
must not repurpose an existing account. Keep the original combined UID21903,
broker21901 and source21902 identities, configurations, keys and binaries. Keep
original Control8080, Keycloak8443 and all existing agents running unchanged.

## Prepare a new private plan

First apply/review any pending additive execution mapping using its receipt and
SHA/revision compare-and-swap seam. Capture the actual combined Dashboard and
broker config bytes into private0600 files using the pinned Lab SSH mechanism.
The local `.lab/dashboard/runtime` copies are usable only when independently
proven equal to those guest files. Preserve the exact `fixture-info.json` bytes.
Do not rerun the old renderer: it reconstructs the earlier mapping set.

The candidate must be the reviewed arm64 archive produced by Dashboard's release
builder. Verify its SHA256 against the exact trusted build/CI record. Stage into
a **new** child of a private0700 operator directory:

```sh
python3 scripts/prepare-dashboard-split.py \
  --candidate /absolute/reviewed/jobman-dashboard_v0.1.0-rc.1_linux_arm64.tar.gz \
  --candidate-sha256 <reviewed-archive-sha256> \
  --app-config /private/operator/current-dashboard.json \
  --broker-config /private/operator/current-broker.json \
  --fixture /absolute/jobman-lab/.lab/dashboard/fixture-info.json \
  --output-directory /private/operator/new-split-staging
```

This verifies the archive's exact internal checksums, bounds, safe paths, arm64
executables, candidate/commit/toolchain identity and schema18 grant manifest. It
extracts a private copy, creates separate CSR+Ed25519 pairs for each API/worker
Control/broker connection, and generates three independent database passwords.
The reviewed grant renderer supplies explicit SQL plans for the three roles.
It clones current mappings, namespace/source pins, report policy and device key
IDs; no new source authority is inferred. API and worker share a single new
configuration revision. The broker preserves its existing caller and outbound
Control identity while adding two scoped caller entries.

The command writes `plan.json` last. It contains only identities, paths, digests,
required preconditions and rollback instructions, never key/password bytes. The
private staging directory as a whole **contains secrets** and must not be uploaded
as a CI artifact, attached to a PR or committed. A partial destination is retained
for inspection and never overwritten. CSRs are not certificates and the output
does not claim the configs are runnable yet. No `--apply` option is provided.

Run offline regression checks with:

```sh
python3 scripts/test-dashboard-split.py
```

## Exact apply prerequisites and order

Prepare a separately reviewed apply receipt with the completed staging plan
digest, exact guest inputs and backup digests. All private transfer uses pinned
SSH/Ansible and protected stdin/files, never password-bearing command arguments
or printed environment values. Retain receipts outside service-writable paths.

1. Verify all three existing VMs, host key pins, synchronized UTC and source
   instance/recovery epoch. Compare actual app/broker config bytes with the plan's
   input hashes; snapshot source delegation policy, unit files, binary hashes,
   current schema ledger, role ownership/membership and current hold generation.
   Require schema17, expected owner `jobman_dashboard_ddl`, and absent new role
   names. Verify free IDs, target mounts and space for the database/report backup.
   The plan caps both database size and dump output at 1 GiB. On the backup and
   PostgreSQL data filesystems it requires room for the 1 GiB capped dump, twice
   the current database size for migration rewrites, and a 256 MiB reserve. This
   conservative check also covers the case where container data and guest backup
   share the same physical filesystem. Candidate stage/release copies and the
   current report inventory are summed per filesystem with the same reserve.
   Capacity is rechecked before staging, dumping, report copying and migration;
   preflight does not reserve disk space against other writers.
   Fresh supplemental mappings or source changes make the plan stale; regenerate.
2. Preserve the current combined build/config/unit and broker build/config. Stage
   immutable candidate files without replacing the original binary paths. Verify
   installed files against candidate hashes. Complete CSR signing using only the
   existing trust roots: Control client CSRs are signed on control01 with its
   fixture CA; broker client CSRs use the existing synthetic Lab CA. Private CA
   keys remain on their existing host. Verify leaf public key, clientAuth, SAN,
   chain and expiry; derive exact certificate thumbprints for source registration.
3. Stop the combined Dashboard and any split API/worker processes. Confirm there
   are no writer/retention processes for this object root. A planned split uses an
   **ordinary global delivery hold with no restore cutoff**. Establish/retain the
   hold through the current schema-compatible operator binary and record its
   generation before backup. Do not fabricate a restore floor or reset a feed.
   Snapshot the Dashboard database using the existing owner credential and
   `pg_dump`, stored root-only with digest/size, and validate its archive listing.
4. Inventory only the existing report root's canonical `UUID.json` objects, with
   original21903 ownership,0700/0600 modes, one hard link, no access/default ACL,
   no temporary/unknown entry, at most10,000 files and1GiB total. These are explicit
   Lab conversion bounds; exceeding them requires a revised plan, not truncation.
   Verify supported local filesystem and enough free space. Make a byte-for-byte
   private backup and compare every size/SHA256 before conversion. The helper
   `dashboard-split-files.py` implements bounded descriptor-based inventory,
   backup and receipt-bound conversion; its module has no standalone apply CLI.
5. Run the new candidate's reviewed `keys export` against the unchanged legacy
   config into a **new root-owned0700 directory**. Preserve token key IDs including
   previous read keys. Copy legacy browser TLS/OIDC/master material only into the
   API directory. Copy exported token keys only to API; exported policy/log keys
   plus report redaction policy to API and worker. Add their own source/broker
   keys, certificates and separate DSNs. Worker receives no master/token/Apple
   material. Root-only operator DSN/config is not mounted into either process.
6. Create ordinary LOGIN/NOINHERIT/nonowner database roles with no elevated flags,
   memberships or cross-database privileges. Add a Dashboard-specific TLS/SCRAM
   HBA block for those exact role names, preserving all existing rules; validate
   HBA parser before reload. Roles connect only to `jobman_dashboard`. Apply
   migration18 with the separate DDL identity, then each candidate-rendered exact
   grant transaction as DBA. PostgreSQL17 rewrites the15 guarded tables: this is
   a stopped-writer maintenance window, not a zero-downtime claim. Never broaden
   a grant after a failure. Remove guest temporary DDL credentials afterward.
7. With a synced root-only conversion receipt, rename the stopped verified report
   root on the **same filesystem** to `/var/lib/jobman-dashboard-reports-lab`.
   Destination must be absent, or already the exact receipt-bound inode from an
   interrupted rename. Set only known files to worker21905:reader21906/0640 and
   that root to0750. Verify all original bytes/inode and final metadata. Keep the
   legacy0700 parent unchanged. The conversion helper accepts only the old/new
   path pair; it cannot recursively chmod arbitrary directories. It handles
   interrupted exact chown/chmod work through the immutable receipt, never by
   silently adopting unrelated files.
8. Append distinct source registrations through a fresh SHA compare-and-swap.
   API operations: namespace/jobs/groups/targets/logs/artifacts/evidence/events
   reads. Worker: namespace/jobs/logs/evidence/events reads. Namespaces and Control
   audience remain exact current values. Preserve both legacy registrations.
   Install the two public broker caller certificates/keys, validate its prepared
   config and preserve all physical mappings and the identity ledger. Restart
   only isolated Control if registry loading requires it and the isolated broker
   for its reviewed new binary/config. Original services and directory identities
   remain unchanged.
9. Verify `check-config` as each new UID. Validate full config/key/schema access,
   worker denial of API credentials and API denial of worker secrets. Start API
   then the worker bundle with `deliveryHold=true`; this **asserts** the existing
   hold and does not give runtime roles permission to alter it. Keep the old
   combined unit stopped. Unix observation sockets are process-owned0700-parent
   surfaces; stored source/report status initially stays root-only through the
   read-only operator CLI. Do not expose a TCP metrics listener.
10. Retain acceptance evidence: actual API authentication/metadata/logs/report
    reads, enqueue with worker stopped then completion after restart, rule/event
    processing, cancellation, role denial, filesystem writer/reader boundaries,
    process modes/UIDs/loaded-file ownership, source pins and unchanged original
    units. A root-controlled explicit resume requires fresh source checkpoints
    and the exact persisted hold generation. No preparer/runtime startup releases
    the hold. This no-provider worker still proves no APNs delivery.

No SQL, remote registration, systemd operation or report conversion is performed
by preparation. `apply-dashboard-split.py` supplies the separately reviewed
ordered phases. Its implementation/helper hashes are sealed into the prepared
plan, alongside staged file digests. Run preflight only after the exact candidate
and plan review; it reads the three pinned guests and creates local receipts:

```sh
python3 scripts/apply-dashboard-split.py preflight --staging /private/operator/new-split-staging --expected-plan-sha256 <reviewed-plan-digest>
```

Mutating phases require explicit `--apply`. The stage phase creates only new
private identities/material, separate login roles and an additive HBA block; it
does not restart running services. Preflight must be no older than15minutes.
Cutover stops Dashboard processes, establishes the ordinary hold, takes backups,
exports keys, migrates schema18, applies exact grants, converts report storage,
appends source registrations, and starts the new processes in that order:

```sh
python3 scripts/apply-dashboard-split.py stage --apply --staging /private/operator/new-split-staging --expected-plan-sha256 <reviewed-plan-digest>
python3 scripts/apply-dashboard-split.py cutover --apply --staging /private/operator/new-split-staging --expected-plan-sha256 <reviewed-plan-digest>
python3 scripts/apply-dashboard-split.py verify --apply --staging /private/operator/new-split-staging --expected-plan-sha256 <reviewed-plan-digest>
```

Before standalone API/worker `check-config`, the driver creates the exact private
observation socket parents declared by each systemd RuntimeDirectory. Otherwise
API static-root exclusion checks correctly reject an unresolved socket parent.
The systemd units subsequently manage those same directories.

New directories and files receive their exact reviewed owner/group/mode through
open descriptors, independent of the caller's umask. Existing paths are checked;
the driver does not silently repair different permissions. One nonblocking local
file lock serializes phases for each staging tree.

Database dumps stream into an exclusive `.partial` file with a 1 GiB output cap
and 120-second deadline. A failed partial remains with a bounded failure receipt
and is never adopted, even if its archive table of contents is readable. Only a
successful dump process, synced bytes, archive validation and a synced checksum
completion receipt permit promotion to the final dump. A retry can finish that
promotion only when the completed receipt and exact bytes match. An unexplained
partial or final file requires private inspection and a new reviewed attempt.

Each completed phase retains a private local receipt. Guest backups and phase
records live under root-only `/var/lib/jobman-dashboard-split-lab/<plan-digest>`.
Interrupted state is not automatically deleted or adopted. Exact completed
phases can be skipped using their retained receipt, and their dependent phases
still enforce current hashes, schema, stopped writers and hold where required.
A failure between an external commit and its receipt may need inspection rather
than blind retry. A migration retry first runs `events hold-status` with the
candidate binary: this calls the exact embedded migration name/checksum checker,
not merely a count of 18 rows. Schema 18 is accepted only with this plan's synced
migration intent and the same backup hash; schema 17 uses the preserved binary.
A lost activation response can be inspected without stopping or restarting the
running split processes using the explicit read-only guest probe below. It only
recovers local receipts after exact guest completion records, config/unit hashes,
full candidate schema verification, persisted hold and service health match:

```sh
python3 scripts/apply-dashboard-split.py recover-receipts --apply --staging /private/operator/new-split-staging --expected-plan-sha256 <reviewed-plan-digest>
```

If the process started but its guest completion record was never synced, this
probe fails closed; inspect that ambiguous state rather than starting again. The driver never releases delivery, restores a database, or
guesses a new source checkpoint. Verification checks individual service states,
private Unix liveness, actual restricted TLS logins, denied protected SQL/private
file access, and preserved original Control/Keycloak/directory start identities.
It does not replace authenticated application acceptance.

### Required explicit event service rebind

Control feed cursors bind the service identity as well as its namespace set.
Changing ingestion from `dashboard-lab` to `dashboard-worker-lab` therefore
intentionally raises `event_cursor_scope_changed` and pauses the retained feed.
This is expected even when the Control instance/epoch and namespaces are unchanged.
It is not permission to reset ingestion to a current head.

The prepared **root-only** `configs/recovery.json` is an API-shaped operator
configuration that uses the preserved legacy operator database access but the
**new worker** Control credentials and new configuration revision. Use this exact
shape for the explicit `events gap/plan/step/reconcile/apply` procedure so the
committed recovered cursor belongs to the service that will consume it. A recovery
performed with API service credentials would bind the cursor to the wrong service
and immediately pause the worker again. Review the retained replay/gap evidence;
do not suppress or skip events implicitly. Keep the global hold throughout.

Only after recovery/application checks should the operator prepare an explicit
resume configuration (`events.deliveryHold=false`), obtain fresh checkpoints,
and release the exact hold generation. That operator action and the ensuing
runtime config update are separate from this driver. Rollback to the legacy
service identity similarly requires its own explicit cursor-scope recovery;
merely starting combined mode does not establish resumed notification processing.

## Rollback without schema downgrade

Before migration18, stop any new processes and retain the original service/state.
After migration18, the old schema17 binary cannot pass the current ledger check.
Use the **reviewed new candidate in combined mode** with preserved UID21903,
original credentials and the prepared higher-revision rollback config. The old
binary is retained as evidence, not falsely described as forward-compatible.

Keep/establish the ordinary persisted hold. Stop split API and all workers. Make
a fresh bounded inventory and backup of the current shared root, including objects
created after cutover. Create a new reversed conversion receipt, verify exact
bytes, return known objects/root to21903/0600/0700, and rename the directory back
under its unchanged private parent. Do not restore the old report backup over new
objects. Keep added registrations and role identities available for inspection;
disable them explicitly only after the fallback is proven, without deleting data.

Start the new candidate with the preserved legacy identity and higher config
revision. Keep new units stopped and the hold set. Its broad **legacy** grant
remains a documented compatibility boundary; never present rollback as split
isolation. Database restore, source epoch repair, history replay or old-binary
downgrade require their separate recovery procedure, external restore cutoff and
approval receipt. No automatic database restore is part of this plan.

The explicit fallback command is:

```sh
python3 scripts/apply-dashboard-split.py rollback --apply --staging /private/operator/new-split-staging --expected-plan-sha256 <reviewed-plan-digest>
```

It requires a completed migration receipt, reestablishes the ordinary hold using
the schema18-compatible binary, backs up/converts current objects and starts the
new binary as UID21903. It never replaces the original config or old binary and
does not drop the new roles, credentials, registrations or backup evidence.


## Recorded primary Lab cutover (2026-10-04)

The initial cutover used candidate `b8f25afdd90f83b4602f32440a89e74dfa866b6c`
(`v0.1.0-rc.1`, Linux ARM64) with archive SHA256
`bf25fb55c84e33cef09de22378ddb154b45e68b3e16c60153f7087c007939f2b`
and prepared plan `b429f3dd8a6fa3aaad8772357be686c36614f8f959829f49ec7f23a192ffcbf5`.
Preflight verified exact app4/broker3 config hashes, unchanged source instance and
epoch1, unused new identities, schema17 and ample capacity. Stage retained all
running services. Cutover established ordinary hold generation2, made a verified
175,297-byte database dump and copied six report objects (77,285 bytes), exported
purpose keys, applied schema18/restricted grants and converted the shared report
root. Original Control, Keycloak and synthetic directory process starts remained
unchanged. API/worker/broker run the exact candidate with configuration revision5.

The first activation stopped at API `check-config` because systemd had not yet
created its observation socket parent. A separately reviewed, receipt-recorded
repair created only the two planned private `/run` directories. Retrying the
unchanged plan completed. This source includes the corresponding future-driver
ordering fix and regression. The exact applied implementation and supplemental
repair were archived privately with per-file SHA256 checksums before that fix.

Mechanical checks passed for individual service states, private liveness sockets,
actual restricted TLS database logins and denied protected SQL/private file reads.
A separate deployed report-worker restart acceptance passed: admitted durable
work completed after stopping/restarting only the worker and returned its sealed
report through the API. Subsequent private readiness checks returned HTTP200 for
API, worker and broker with `local_required_dependencies` scope. Each metrics
response remained bounded and reported configuration revision5.

The expected service-bound cursor gap was explicitly planned and replayed using
the new worker identity: one page scanned15 original events and added1 historical
terminal event belonging to the earlier diagnostic fixture. All14 pre-cutover
event identity hashes, all4 inbox identities and0 delivery identities were
preserved. Exact recovery `13de49fa-ef97-49e8-b7eb-36aba0be36fa` was applied at
ready revision2 with explicit incomplete-reconciliation acknowledgement: there
were zero enabled rules and no eligible current scope owners, so both namespaces
reported unavailable current-state coverage. The feed became active with no
unresolved gap. This is retained-replay/deduplication evidence, not complete
historical-delivery coverage.

A separately reviewed resume plan
`480df065e95eac21b19c7c4366eb92751dc1dc70ea2e9fd14b6591c192d7e141`
changed only API/worker startup hold flags at unchanged configuration revision5,
validated exact unit/config ownership and running candidate identities, then
restarted those two processes while retaining database hold2. Fresh source,
readiness and metrics checks preceded the separately authorized explicit resume.
The resulting persisted state was held=false, generation3. The recovered historical
event finished evaluation with no enabled rules and no additional inbox/delivery;
all original identity digests remained unchanged. An operational hold toggle does
not change source registration, mapping, key or policy, so it does not advance the
registry revision. Any future fallback must use a revision greater than both live
and stored registry revisions; the archived revision6 fallback must be regenerated
if subsequent changes have consumed that revision.

A fresh nonce scenario `fcfa6fa7078d2c8df29726fe464a8829` then passed the actual
integration race test (scenario13.64s; package14.961s). Two new normally submitted
and cancelled synthetic jobs proved durable Control events, service-only ingestion,
active overlapping personal rules, one inbox per account, owner/outcome filtering,
read/unread updates, cross-account denial and immediate rule stop. The public
scenario and exact event receipts remain under `.lab/dashboard/notifications/`;
only that scenario's six personal rules were cleaned up. No APNs, physical-phone
or actual workload execution is claimed by this cancellation scenario.
