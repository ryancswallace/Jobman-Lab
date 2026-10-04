# Packaged startup refusal for an unknown or newer schema

This is an offline-prepared follow-on to the completed fresh-install and compatible
rollback exercise. It has not been run in the Lab. It tests the actual selected
candidate executable, with a separately named disposable PostgreSQL database and
roles. It does not alter the primary, restore, or fresh-install database.

The fixed database is `jobman_schema_probe_v1`; its four login roles are
`jobman_schema_probe_ddl`, `jobman_schema_probe_api`,
`jobman_schema_probe_worker`, and `jobman_schema_probe_operator`. The API and
worker reuse only the stopped accepted installation’s finite OS identities
(v1:21920/21921, or v2:21923/21924) and
read-only access to their existing private local TLS and signing material.
No new systemd unit or source registration is created. Probe configuration roots
are `/etc/jobman-dashboard-schema-probe-{api,worker,operator}-lab`, with separate
API/worker socket parents under `/run/jobman-dashboard-schema-probe-*-lab`.
The API binds only loopback127.0.0.1:48444 if it incorrectly gets that far.
Source origins remain unique: two sources use ports48445 and48446, preserving
their source-qualified IDs/scopes while disabling access to actual Controls.

## Evidence required before preparation

The operator selects one of the two reviewed candidate archives from a completed
fresh-install exercise. Both candidates must already meet that exercise's
output-bound-fix ancestry, package provenance and exact migration18 checks.
The fresh-install `complete.json`, immutable `plan.json`, stopped unit receipts,
retired test identity receipt, exact original implementation archive and the
selected candidate archive must be retained. This probe validates each original
implementation hash before importing it. Pass its frozen `scripts` directory,
not the potentially newer working checkout. The plan’s explicit finite scope
also selects its exact release root and reader GID (v1:21922, v2:21925).
No arbitrary resource or UID input is accepted. Failed-v1 abort evidence cannot
replace the required successful completion of v2.

A completion produced by an independently reviewed installation continuation
requires the additional `--expected-install-continuation-sha256` input on every
probe invocation. This is the SHA256 of the canonical encoded `continuation`
object in the retained completion receipt, including its newline. The probe
retains the complete receipt and this review digest in its plan. It requires
exact adapter, original-implementation, failure and diagnostic hashes, with
only the reviewed explicit false audience-mapper difference. The original
implementation digest must match the unchanged nine-file installation archive.
Extra or changed provenance fields, an omitted review digest, or a changed
operation fail closed. Ordinary completions keep the existing path with no
continuation option. This does not rerun identity adoption or retirement.

No source or broker request is needed. The worker configuration is retention-only,
with no source, broker, APNs or application-key credentials. The API configuration
retains its local file references, removes reports and remote logs, and points
its source endpoints to distinct loopback ports48445 onward and its OIDC
endpoint to loopback48445. The existing certificate
still identifies the unchanged `dashboard.lab.test` public hostname. Local
`check-config` must pass before the negative test. The product must reject the
schema before any listener or background work starts. The refusal parser accepts
the exact default Go logger frame emitted by `slog.Error` and the explicit
TextHandler frame, with the complete fixed schema-version error and no extra fields; an unrelated configuration,
permission, connection or identity error does not count as refusal evidence.

The operator must coordinate an otherwise quiet Lab window. Read-only snapshots
pin original runtime processes/configuration, source metadata, the retained
restore clone, and fresh-install artifacts/data. Normal primary feed position
and generation growth is allowed without changing authority. Minimum preflight
headroom is256MiB on storage01,1GiB on pg01 and20 PostgreSQL connection slots.
No server capacity change is made.

## Explicit phases

Use the new `scripts/probe-dashboard-schema.py`. All host evidence and generated
secrets go into a new, pre-created canonical owner0700 directory immediately under
`/private/tmp`, named `jobman-schema-probe-<unique>`. Every invocation requires:

```text
--lab-root /Users/rcw/home/code/jobman-lab
--install-driver /private/tmp/REVIEWED_INSTALL_ARCHIVE/scripts
--install-staging /private/tmp/REVIEWED_COMPLETED_INSTALL
--expected-install-plan-sha256 REVIEWED_INSTALL_PLAN_SHA256
--expected-install-complete-sha256 REVIEWED_INSTALL_COMPLETE_SHA256
--staging /private/tmp/jobman-schema-probe-REVIEWED_UNIQUE
```

1. `snapshot` is read-only on the guests and refuses existing probe DB, roles or
   private roots. It verifies that the fresh-install API/worker remain stopped.
2. `prepare --selected baseline|upgrade --candidate-archive PATH` is host-only.
   It validates the full archive, renders API/retention/operator grants with its
   own reviewed grant renderer, and generates four distinct private DB secrets.
   Independently review `plan.json`, `review.json` and implementation hashes.
3. `database --apply` creates only the four fixed roles and the probe DB from
   template0, with a private public schema owned by the probe DDL identity.
   An additive HBA prefix permits these roles only over verified TLS from
   storage01 and rejects their other host connections. Existing HBA bytes are
   retained and preserved beneath this prefix; PostgreSQL is reloaded, not
   restarted. Empty-schema checks reject relations, routines, types, extra user
   schemas and non-default extensions.
4. `material --apply` creates only the separate probe config/DSN and socket-parent
   directories. Existing install keys and files are read and hash-checked.
5. `migrate --apply` invokes the exact packaged migrator once, using only the probe
   DDL URL. This is permitted only on the verified empty probe database.
6. `grants --apply` verifies the complete exact18-entry ledger and applies the
   candidate's API, retention and read-only operator grants. It records hashes of
   every public table's rows and schema definitions; no row contents are emitted.
7. `positive --apply` runs packaged API and worker `check-config` under their
   actual OS identities, then packaged read-only `status --operator-config` under
   the operator DB role. It must succeed and leave the table and artifact hashes
   unchanged. The earlier completed install supplies actual healthy startup
   evidence for this same candidate; this phase separately validates the probe.
8. `future --apply` inserts exactly one synthetic ledger marker,
   `migrations/999999_lab_schema_probe.sql`, in the probe DB. It executes no
   migration body. The resulting19-entry ledger and table/schema digests are
   recorded. This one fixture represents an unknown, newer migration version.
9. `refuse --apply` starts the packaged API and worker once each under their
   separate UIDs. Each must exit1 within15seconds and emit exactly the standard
   single-line error value `Dashboard schema is incompatible with this binary:
   migration version`. No missing-secret, failed-connection, permission or generic
   startup error is accepted. The commands receive no DDL credential. Config,
   material and runtime-directory hashes must remain unchanged, with no socket
   and the loopback port still available. The worker has no external authority.
10. `verify` compares every retained DB/ledger/schema/table digest and artifact
    hash against the pre-start proofs and records `complete.json`. It also
    rechecks all preserved original resources. No automatic role/database deletion
    or schema downgrade follows; retain the probe and all evidence.

For phases after `prepare`, also pass the reviewed `--expected-plan-sha256` and
`--expected-implementation-sha256` from `review.json`. Host and guest pending
receipts are written before any mutation or process admission. Successful phases
write completion last. They are deliberately not automatically rerunnable.

## Interrupted or failed probes

Every product invocation has its own exclusive pending receipt and private bounded
log. Combined stdout/stderr is capped at64KiB. A timeout or overflow kills and
reaps only that invocation's newly created process group. Neither a primary nor
fresh-install service is signaled. The positive migrator has60seconds; each other
product invocation has15seconds, with a135-second SSH transport bound and a
120-second guest phase bound. No raw stderr, DSN, key or SQL error is printed.

After an uncertain reply, preserve everything. `observe --observed-phase PHASE`
reads a matching durable guest completion without invoking its product command
or mutation again. It cannot adopt a partial phase that lacks completion; that
requires separate inspection and review. A complete receipt with later drift
cannot pass final verification. Never clear a pending receipt, rerun migration,
remove the future ledger entry, restore a different database, or start any
retained service to make a failed probe pass.

Offline checks are in `scripts/test-dashboard-schema-probe.py`. They exercise
real bounded subprocess output and timeout handling plus fixed DB/HBA scopes,
exact refusal classification, existing-pending refusal, observe-only behavior,
empty-template drift, changed final proofs and actual bootstrap module isolation.
Passing those checks is not deployed schema-refusal acceptance.

The probe also accepts a completed finite v3 installation and derives only its
UIDs 21926/21927, reader GID 21928, and v3 release root. The guest bootstrap
retains both prior-scope modules so preservation still verifies failed v1 and
v2. An aborted v2 receipt is never accepted as the prerequisite completed
installation. The probe database, loopback endpoints, and refusal contract do
not change.
