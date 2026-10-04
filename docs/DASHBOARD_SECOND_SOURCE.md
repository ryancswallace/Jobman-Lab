# Second isolated Dashboard Control source

The public planner remains prepare-only. A separate phased apply driver is provided for independent review and explicit later use; it has not been run against a guest. The driver can create only the second source's isolated database, identities, files and services. It does not edit Dashboard/broker configuration. The original Control and first Dashboard-isolated source remain unchanged.

## Verified baseline

Read-only pinned SSH and TLS PostgreSQL inspection on 2026-10-04 verified the first source's exact binary revision `d332a2b569333ae8aed9c2fc9ebc648d8eb5ba4e`, SHA-256 `38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e`, database `jobman_dashboard_control`, instance `e633cf92-258d-48ff-965a-fda88d68ef3a`, and final migration `000021_monitoring_events.sql`. Existing source/directory, original Control and Keycloak services were active. Proposed ports 28443/28636 had no listener; UID 21907/21908 were unused. These observations must be checked again before eventual apply.

The first source's supplemental notification helper is separately pinned at `cb1bfa66816694c2727f5c1e21fae4bd68067095`; it is not a source upgrade. The API/worker split preparation currently targets only the first source. Finish and verify that split before extending its source registry, or explicitly revise/review its inputs; never silently rebuild old configuration over a newer revision.

## Proposed boundaries

| Resource | Secondary value |
| --- | --- |
| Dashboard deployment | `72000000-0000-4000-8000-000000000002` |
| PostgreSQL database / isolated owner role | `jobman_dashboard_control_secondary` |
| Schema | `public` inside the new database only |
| Control | `https://10.77.0.21:28443`, source UID/GID 21907 |
| Synthetic LDAPS | `ldaps://127.0.0.1:28636`, directory UID/GID 21908 |
| Private roots | `/etc/jobman-dashboard-secondary/control` and `/etc/jobman-dashboard-secondary/directory` |
| Local spool | `/var/lib/jobman-dashboard-secondary/seed-logs` |
| Separate NFS subtree | `/data/jobman/alice/dashboard-secondary`, logical `lab-nfs` version 1 |
| Directory source/base | `synthetic-dashboard-lab-secondary`, `DC=dashboard-secondary,DC=lab,DC=test` |
| Delegation audience | `urn:jobman:dashboard-lab-secondary:control` |

Generate a fresh Control instance through normal migrations. Never copy a database, migration ledger, instance ID, replay/recovery state, CA, TLS client key, signing key, directory bind secret or agent token key from the first source. Use separate non-superuser/non-CREATEROLE/non-CREATEDB database credentials, TLS `verify-full`, and additive HBA rules restricted to this database and Lab hosts. Deny the role access to original Control, primary fixture and Dashboard state databases. Keep synthetic secrets in ignored private Lab storage and pass them only through stdin/private files.

The secondary source gets separate API, worker and broker registrations, each bound to its own mTLS leaf and signing key. API retains explicit event-read authority for immediate rule activation; worker operations cover events, current namespace/jobs and report/log evidence; broker gets namespace/log reads only. Namespace allowlists use the newly created actual IDs. No token, assertion or private Control database credential reaches a browser/iPhone. CA private material stays on the secondary source. Directory UID 21908 receives only its own LDAP server certificate/key, bind secret and state; it cannot read source DB/token/signing/CA-private material.

Reuse the existing Keycloak issuer, audience, client registrations, actual Alice/Bob subjects and immutable signed `directory_guid` values. Do not create duplicate accounts or alter the issuer. Map those identities independently to newly generated Control principals. Eight new direct groups (`73000000-…000001` through `…000008`) each map one-to-one to a namespace role, without nested memberships. The namespaces deliberately share the primary display names:

| Namespace | Secondary Alice | Secondary Bob |
| --- | --- | --- |
| `dashboard-research` | viewer | viewer + submitter |
| `dashboard-operations` | no grant | namespace administrator |

This yields Alice's two primary namespaces plus secondary research, and Bob's primary research plus both secondary namespaces. Same-named jobs/namespaces test display isolation; source-qualified ID substitution tests must still deny cross-source references. Generated IDs remain generated; do not alter existing IDs through SQL merely to force a collision. Identical opaque UUID collision scenarios remain covered by isolated unit/transport fixtures unless a normal admission/import API explicitly supports caller-chosen identities.

## Prepare a review artifact

After obtaining the exact approved source build directory, create a fresh private host parent and stage a public plan:

```sh
python3 scripts/prepare-dashboard-second-source.py \
  --control-build /absolute/path/to/approved-control-build \
  --output-directory /absolute/private-parent/secondary-plan
python3 scripts/test-dashboard-second-source.py
```

The planner verifies the exact Linux ARM64 binary hash, pinned Go 1.26.6 metadata and existing public identity mappings. It writes only a new mode 0700 directory containing mode 0600 `plan.json`, refuses pre-existing output, checks bounded regular inputs and duplicate JSON fields, and performs no SSH/database call. `applySupported:false` and explicit blockers prevent presenting staging as deployment. The plan contains no generated credentials, copied private files or runnable apply command.

## Required narrow upstream helper extension

The existing helper intentionally hard-codes the primary database, API/LDAP ports, directory source/base, group IDs, delegation audience and service IDs. Reusing it unchanged would fail its database safety check or collide with the first LDAP listener. Do not patch generated primary files or substitute the original database name to bypass that boundary.

Propose a fixture-only named profile `secondary-v1` selected explicitly by the prepare/directory/scenario entry points. Keep the existing default profile byte-compatible. The profile enumerates the fixed secondary values above; it is not arbitrary endpoint/database input. Before writes, require the secondary database, fresh isolated roots and exact migration set. Generate its trust/principals normally. Use explicit asymmetric memberships and separate directory-only material output. Preserve immutable preparation/recovery receipts and fail closed on a partial setup. Supplemental notification scenarios must accept only the chosen profile's database/namespace/deployment and retain their normal Submit/Cancel behavior. A helper from a newly reviewed commit may run against the unchanged approved source binary only after tests prove identical migration 21/runtime contracts; both independent hashes must be recorded.

Helper tests must prove refusal of the primary/original/Dashboard DBs under the secondary profile, unique trust and source instance, no listener collision, profile-bound receipt replay, exact direct-group grants, ordinary API/delegation authorization and separate directory filesystem ownership. Only after independent review and CI should a later Lab apply create its dedicated database/roles, private service files and new units.

## Later acceptance order

1. Capture original source/service/config identity and exact binary snapshots; verify second ports/UIDs unused and no pending recovery/upgrade receipts.
2. Provision only the new database/role/TLS HBA entries; migrate with the dedicated identity, seed normal source data, publish only new immutable objects as Alice under root-squashed NFS, then start only the two new units.
3. Verify source TLS/instance/schema, directory proof freshness, independent mTLS-bound delegation and broker UID 21901 read/hash versus Bob direct-NFS denial. Do not launch jobs while merely seeding observation fixtures.
4. Review additive source and exact target-generation mappings for the API/worker/broker; advance configuration revision and preserve every old source/credential/hold/ledger. No implicit downgrade or reset.
5. Run actual authenticated aggregate jobs/targets/workloads/counts/pagination and source-qualified deep links. Check asymmetric namespace grants, partial outage/subtotals, existing-token revocation scoped to the secondary source, and restored current proofs.
6. Activate source-qualified rules, create independent normal cancellation events on each source, verify account/event deduplication, matching-rule context, inbox/read state, replay and stop semantics. Durable feed IDs/cursors must never cross source boundaries.
7. Restore any temporary directory/outage state in guarded cleanup; leave normal synthetic jobs/events as evidence. Record exact revisions and all original services' unchanged identities.

Synthetic LDAP and Keycloak acceptance does not establish corporate AD FS compatibility. Cancellation events are not actual subprocess/Slurm completion. APNs credentials and managed-phone presentation remain separate acceptance requirements.


## Explicit phased source provisioning

`apply-dashboard-second-source.py` is separate from the public planner. The
planner's `applySupported:false` describes the planner itself; the phased driver
requires the exact saved plan digest, the approved primary runtime binary, and an
independently reviewed secondary-capable helper revision and digest. The current
reviewed helper is Control PR28, exact commit
`c0eb58ab58c0fff66e40361673656b708a9946d9`; all its GitHub CI gates passed. Its
migration set remains21 and the normal source executable remains exact `d332a2b`.
The helper includes no production source/schema change. The isolated secondary
source was applied and verified as recorded below; Dashboard aggregation remains
a separate registration and acceptance step.

Prepare a fresh private plan directory using the command above. Supply these
arguments to every driver invocation:

```sh
python3 scripts/apply-dashboard-second-source.py \
  --lab-root /absolute/path/to/jobman-lab \
  --staging /absolute/private-parent/secondary-plan \
  --expected-plan-sha256 <sha256-of-plan.json> \
  --control-build /absolute/path/to/approved-d332a2b-build \
  --helper-build /absolute/path/to/approved-c0eb58a-helper-build \
  --helper-revision c0eb58ab58c0fff66e40361673656b708a9946d9 \
  --phase preflight
```

The ordered phases are:

| Phase | Effect |
| --- | --- |
| `preflight` | Read only from pinned pg01/control01: exact primary binary/instance/schema, service start identities, private-file hashes, HBA hash, unused ports/UIDs/paths, and synchronized clocks. Saves a private host receipt. |
| `database --apply` | Creates only `jobman_dashboard_control_secondary` role/database, preserving a private HBA backup and prepending one exact TLS-only SCRAM/reject block. Reloads HBA without restarting PostgreSQL. Verifies TLS and denial for plaintext/other databases. |
| `prepare --apply` | Creates only users21907/21908, separate private roots, exact binary copies, material and new systemd unit files. Runs the immutable helper once against the new DB. Sends only twelve known synthetic log objects to an Alice process for exclusive creation under the new NFS subtree, then verifies designated broker read/hash and Bob denial. No service starts. |
| `start --apply` | Verifies prepared material, loads unit definitions and enables/starts only the two new secondary units. Checks actual executable/UID, source TLS/instance/epoch and unchanged original services. |
| `verify` | Reads completed receipts and rechecks material/log hashes, actual process identities, TLS instance/epoch, database-role isolation and both current namespace directory proofs. It cannot create a guest receipt, start a unit or repair a failed phase. |

`--phase preflight` is the default. Every mutation requires `--apply`. Complete
all mutation phases within one hour of the immutable preflight snapshot. The
host receipt directory and guest receipt roots are mode0700, records mode0600.
The execution identity binds the exact plan, helper build, both apply scripts, the pure planner, and the narrow continuation script,
so editing code or swapping a build cannot reuse an earlier approval receipt.
A nonblocking exclusive lock serializes every phase using the same staging directory. New private records are set to0600 through their open descriptor even under a restrictive umask. The secondary password is generated once into ignored private
`.lab/credentials/dashboard-secondary.env`; it is never printed. The source UID
gets the normal private environment containing only its own DB credential. The
independent LDAP UID cannot read that environment or any source signing/CA key;
the source UID cannot read the LDAP private tree. Both denials are checked.

An exclusive pending record is synced before any phase's database or guest
mutation. An incomplete phase refuses automatic replay. A completed phase checks
its exact installed material before returning its saved result. Do not delete a
pending record, drop/reset a database or replace an existing tree merely to make
a rerun succeed. Preserve receipts and inspect the bounded partial state. The
driver does not automatically restore HBA, roll back ownership, stop original
services, reset identity, resume notification delivery or modify existing source
grants. Read-only `verify` remains distinct from the mutating `start` path.

The host `prepare.json` receipt includes the new public fixture manifest and
immutable log metadata, plus private material hashes for reproducibility. It
contains no raw key, password or log bytes. The private material stays beneath
its respective guest owner until a separate reviewed API/worker/broker registry
extension copies only the required leaf and signing files. That extension must
start from the successfully verified split revision and retain every primary
source, executable, role, hold, cursor and configuration revision.

Offline tests (`test-dashboard-second-source.py` and
`test-dashboard-second-source-apply.py`) cover fixed identities, wrong profile/DB
refusal, exclusive staging, bounded inputs, additive HBA/SQL scope, separate unit
users, private pending/completion receipts, explicit mutation flags, invalid
binary rejection before writes, read-only verification and private fixture
identity checks. They do not load Lab credentials or call SSH/SQL. Guest provisioning used the reviewed exact archives and continuation recorded
below. Full delegated multi-source acceptance requires the separate reviewed
Dashboard/broker registration step.


For reproducible replay, archive all four implementation dependencies together:
`apply-dashboard-second-source.py`, `dashboard-second-source-guest.py`, and
`dashboard-second-source-plan.py`, and `continue-dashboard-second-source.py`. Run the archived driver with explicit
`--lab-root /absolute/path/to/jobman-lab` and the same staged-plan and build
arguments above. It reads private credentials/inventory only beneath that selected
Lab checkout; no operational helper is imported from the archive's parent. The
four exact hashes are part of the execution identity. The nine original apply
tests plus regressions for restrictive umask, competing locks, private SQL stdin
and archived replay remain offline.

## Recorded early-prepare failure and explicit continuation

The first reviewed apply completed only the secondary database phase. The first
`groupadd` then rejected the proposed33/36-character names under Linux's32-character
limit. Neither new identity, material root, NFS subtree, unit nor listener was
created. The original archive, plan, complete database/HBA receipts and pending
prepare receipt remain unchanged. Fixed identities are now
`jobman-dashboard-source2` and `jobman-dashboard-directory2`, with unchanged
UID/GID21907/21908. The guest validates their exact names and bounds before writes.

`continue-dashboard-second-source.py` is a deliberately narrow, separately reviewed
continuation for that exact failed execution, not a general retry or reset. Stage
a new plan and archive the four implementation dependencies listed above together. Use the normal exact build/plan
arguments with `--prior-staging` pointing to the original private plan directory:

```sh
python3 /private/reviewed/scripts/continue-dashboard-second-source.py \
  --lab-root /absolute/path/to/jobman-lab \
  --prior-staging /absolute/private-parent/original-plan \
  --staging /absolute/private-parent/corrected-plan \
  --expected-plan-sha256 <corrected-plan-sha256> \
  --control-build /absolute/path/to/approved-d332a2b-build \
  --helper-build /absolute/path/to/approved-c0eb58a-helper-build \
  --helper-revision c0eb58ab58c0fff66e40361673656b708a9946d9
```

This command performs only read-only guest checks. It requires the exact old
completed database and HBA, the same private credential with TLS/role isolation,
an empty secondary schema, unchanged primary source/process snapshots, the exact
old pending receipt, and zero identity/path/unit/port effects. It never clears a
pending record or recreates the database. New private host receipts carry the
verified database completion and bind all prior evidence into the new execution
identity. After independent review and an explicit apply authorization, continue
with `prepare --apply`, `start --apply`, then `verify`; the driver refuses a
`database` or fresh `preflight` phase for this continuation. Any failed check or
partially written continuation requires inspection and preserves all evidence.


## Applied source checkpoint — 2026-10-04

The corrected continuation and `prepare`, `start`, `verify` phases passed on the
existing pg01/control01 guests. No additional VM was started. Exact source build
`d332a2b569333ae8aed9c2fc9ebc648d8eb5ba4e` has SHA256
`38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e`;
helper `c0eb58ab58c0fff66e40361673656b708a9946d9` has SHA256
`5b6f50215097c727b511a721d9e5ae16af7a25390dc5bacf87d211c6c28252f7`.
Both are pinned Go1.26.6 Linux/arm64 builds; the helper's exact CI passed.

| Field | Verified value |
| --- | --- |
| Dashboard deployment ID | `72000000-0000-4000-8000-000000000002` |
| Control origin | `https://10.77.0.21:28443` |
| Fresh Control instance | `a4f0e2ab-7323-4c90-9510-1f073c660f06` |
| Recovery epoch / migration | `1` / `000021_monitoring_events.sql` |
| Research namespace | `455525f6-5d8a-4d4f-bea3-2d3f1ed4698f` |
| Operations namespace | `b7b972fb-0d69-4564-8dcc-cbc07b7b845e` |

Both namespace directory proofs were current within120seconds. The new database
role required verify-full TLS and could not connect to the original Control,
primary isolated Control, Dashboard state, or postgres databases; plaintext was
denied. All12 synthetic NFS objects matched exact length/hash under broker UID21901,
and Bob could not read them directly. Root-squash and unrelated storage were
unchanged. Source21907 and directory21908 cannot read each other's private roots
or the root-owned provisioning DSN.

Original Control, primary isolated Control, primary directory and Keycloak retained
the same PID, UID, executable and start timestamp across both the failed attempt
and successful continuation. Capacity and clock checks passed before/after. No
Dashboard/broker source list, primary service registration, hold or delivery state
was changed. The new source is not yet registered with the Dashboard.

Private reproducibility evidence is retained under
`/private/tmp/jobman-secondary-continued-6ztu9_dj`, with eight reviewed file hashes
in manifest `b76d9b2f9f933946020156547bcacf31e467cc2167f564903f0d5b2f35989614`.
Plan SHA256 is `162bfe2e44d5c09833c59600e7b7e910bc1aff5bfffcbb5457dc22a5b2b82d76`;
new execution `fa0375caa7f47e86b2dc00370f50a99f92f3e6b25dfb34d24317cc5f1e886bb9`
binds original execution `d87f4b43ba6cb4d503f09e3cf4738795f52550c04623bfeeb8c4bce2f5f93331`.
The original pending record and archive remain preserved. Evidence includes no raw
credential or log content. These checks establish synthetic provisioning only;
aggregate authorization, outages, notification routing and real device delivery
remain separate acceptance work.
