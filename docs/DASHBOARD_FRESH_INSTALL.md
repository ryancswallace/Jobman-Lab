# Disposable Dashboard installation and compatible rollback acceptance

This is an opt-in Lab procedure. The scripts are prepared for independent review;
no fresh installation or rollback acceptance has been run. The operator chooses
**two separately reviewed candidate packages** after the output-bound repair
`2e8f1b15c58889c52023d49d396fd600b31eecd2`. Both commits must descend from that repair,
have distinct revisions, and contain the exact same 18 migration names/checksums
and identical role-grant generator inputs. No pre-fix candidate is recommended.
This exercises supported application rollback at an unchanged schema; it does not
claim that a migration can be reversed or that an incompatible old binary is safe.

## Scope and preservation

The fixed disposable scope is deliberately different from both the current Lab
Dashboard and the retained, stopped restore exercise:

| Resource | New fixed value |
| --- | --- |
| PostgreSQL database | `jobman_install_v1` |
| Roles | `jobman_install_ddl`, `jobman_install_api`, `jobman_install_worker`, `jobman_install_operator` |
| API user / UID | `jobman-dash-install-api` / `21920` |
| Worker user / UID | `jobman-dash-install-worker` / `21921` |
| Read-only report group / GID | `jobman-dash-install-readers` / `21922` |
| Config roots | `/etc/jobman-dashboard-install-{api,worker,operator}-lab` |
| Report root | `/var/lib/jobman-dashboard-install-reports-lab` |
| Candidate releases | `/opt/jobman-dashboard-install-lab/releases/<full-commit>` |
| Units | `jobman-dashboard-install-{api,worker}-lab` |
| Listener | `10.77.0.10:48443` |
| Origin | `https://dashboard.lab.test:48443` |
| Confidential OIDC client | `jobman-dashboard-install-web-v1` |

The existing Lab CA and server certificate cover the same hostname. Each new
role receives only copies of the existing corresponding role's Control/broker
mTLS and delegation material. Service ID, audience, instance, namespaces,
log mappings, and all upstream trust policy stay unchanged. These copies allow
concurrent reads by a separate Dashboard; they do not create source grants or
widen the source trust boundary. The plan inventories the files by owner, mode,
size and hash without returning their contents. Source and broker credentials
are never sent back to the host. An operator needing independently revocable
service identities must use a separate reviewed trust-enrollment exercise.

Auth, report-policy and cursor keys, all four database passwords, and the new
confidential client secret are generated afresh and persisted privately before
any remote action. The API has read-only report-directory access; only the worker
can write. The worker enables ingestion, evaluation and reports, with no APNs
provider credentials, device topics, delivery or retention component. There are
no synthetic source mutations in this scenario. Feeds begin at current heads;
there must be no historical event/inbox flood.

The scripts pin the existing API, worker, broker, both Controls, LDAP services,
original services, source/helper files, source instance/epoch/namespace and
schema facts, database role/hold state, and the stopped restore clone. Ordinary
Dashboard feed generation/position progress is accepted only monotonically.
Source job/run/event facts must remain unchanged. Coordinate a quiet window with
all other Lab tasks before snapshot and through closure. No shared PostgreSQL,
NFS, source, broker, or directory service is stopped. Only the new units are
started/stopped. Old clients, users, realm profile, database data, keys and all
prior evidence are retained and hashed before/after every phase.

Port isolation does **not** isolate browser cookies: cookies are scoped to a host,
not its port. The harness uses a new private in-memory cookie jar and never opens
a user's browser or imports existing cookies. Do not manually browse this origin
using an existing Dashboard browser session for this acceptance.

## Review and package inputs

Review the four new scripts and this runbook, plus the exact frozen dependencies
listed by `dashboard-install-plan.py:FILES`. The Go harness is
`internal/auth/lab_installation_test.go` in Dashboard. Root must separately approve
the concrete snapshot, package pair and resulting plan before any phase with
`--apply`. Existing user authorization covers this synthetic Lab work, but review
is an engineering gate and these scripts never infer approval from elapsed time.

Record the package pair in a new private file; values below are placeholders:

```json
{
  "baseline": {
    "revision": "<full-reviewed-post-fix-commit>",
    "archiveSHA256": "<sha256-of-linux-arm64-package>",
    "reviewEvidence": "<exact review receipt or URL>",
    "ciEvidence": "<exact-head passing workflow URL>"
  },
  "upgrade": {
    "revision": "<different-reviewed-post-fix-commit>",
    "archiveSHA256": "<sha256-of-linux-arm64-package>",
    "reviewEvidence": "<exact review receipt or URL>",
    "ciEvidence": "<exact-head passing workflow URL>"
  }
}
```

The existing archive checker verifies all files/checksums/metadata and paths. The
new planner also checks both revisions' ancestry, actual committed migration
ledger paths (including `migrations/`), identical grant generators, ELF candidate
metadata, total expanded size <=128 MiB per archive and <=1024 files. It derives
unit changes from each actual packaged template: all three release sites
(WorkingDirectory, ExecStartPre, ExecStart), both config sites, fixed fresh users,
report path and private-path hardening. Reusing or repairing existing new-scope
paths is forbidden. Select a pair whose wire/storage contract remains compatible
for the intended rollback; the 18-row schema check alone does not prove arbitrary
future application-level compatibility.

## Commands and ordered phases

Run from an immutable Lab archive containing the frozen driver/dependencies.
`IMPLEMENTATION` is the frozen archive root; `LAB` is the separate actual Lab
root holding its existing private SSH inventory and known-hosts file. `DASHBOARD`
is the source checkout used only to verify candidate ancestry/migrations. All
three must be real absolute paths. Use a new private staging
path under `/private/tmp`; do not reuse another exercise's directory. The snapshot
`--revision` is the **currently running primary Dashboard** commit, not either
new candidate. The snapshot reads guests and writes only a new host receipt.
There is no guest mutation before a reviewed `stage --apply`.

```sh
python3 "$IMPLEMENTATION/scripts/install-dashboard-fresh.py" snapshot \
  --lab-root "$LAB" --revision "$CURRENT_DASHBOARD_COMMIT" \
  --output "$SNAPSHOT"
python3 "$IMPLEMENTATION/scripts/install-dashboard-fresh.py" prepare \
  --lab-root "$LAB" --dashboard-root "$DASHBOARD" \
  --snapshot "$SNAPSHOT" --reviewed-pair "$PAIR_REVIEW" \
  --baseline-archive "$BASELINE_ARCHIVE" --upgrade-archive "$UPGRADE_ARCHIVE" \
  --staging "$STAGING"
```

Independently inspect `review.json` and `plan.json`; archive their exact hashes and
implementation hash set. Reconfirm at least 1536 MiB available memory on storage01,
2 GiB free on storage01/pg01, 36 free PostgreSQL connection slots, unused fixed
UIDs/roles/paths/port, and no concurrent source workload or service writer. The
new units are limited to 512 MiB (API) and 768 MiB (worker), GOMAXPROCS2. A plan
must be staged within one hour of its snapshot-derived preparation.

Invoke **each** phase separately with the same reviewed hashes; never use a loop
that continues past failure:

```sh
python3 "$IMPLEMENTATION/scripts/install-dashboard-fresh.py" stage \
  --lab-root "$LAB" --staging "$STAGING" \
  --expected-plan-sha256 "$PLAN_SHA256" \
  --expected-implementation-sha256 "$IMPLEMENTATION_SHA256" --apply
```

Replace only the phase name and continue in this exact order:

1. `stage`: install both full immutable candidate trees on storage01, no units.
2. `identity`: create only the new confidential Keycloak client with exact48443
   callback, S256 PKCE, API audience and immutable directory-GUID mapping.
3. `database`: create only the four fresh roles and new database, asserting zero user relations, no migration ledger and the new DDL
   schema owner; prepend one
   fixed TLS/SCRAM HBA rule for that database/roles from storage01 and reload
   PostgreSQL. Save original HBA privately; never overwrite unrelated lines.
4. `install`: create fresh OS users/group, role roots and exact units; copy pinned
   same-role source material; write fresh keys/DSNs. Probe that API cannot write
   the report root. No service starts.
5. `migrate`: run the baseline package's real migrator against the new empty
   database using only its separate DDL credential, after a second read-only
   empty-schema check immediately before admission. Verify the exact real ledger
   on pg01 before completing the host receipt.
6. `grants`: apply the actual packaged role-grant output to this database only;
   verify schema ledger and runtime role flags.
7. `baseline`: validate both configurations and the real schema using the actual
   packaged binary, then start only the new API and worker. Confirm exact
   executable/argv/UID/unit and positive TLS health within a bounded deadline.

The opt-in Go acceptance harness now owns the remaining explicit phases. Root
must review the test invocation against the exact staged operation before use.
It needs the existing authorized synthetic sign-in configuration and an accepted
**actual host-execution receipt** (not imported monitoring observations):

```sh
JOBMAN_DASHBOARD_LAB_RUNTIME=1 \
JOBMAN_DASHBOARD_LAB_INSTALLATION=1 \
JOBMAN_DASHBOARD_LAB_ROOT="$LAB" \
JOBMAN_DASHBOARD_LAB_INSTALL_IMPLEMENTATION_ROOT="$IMPLEMENTATION" \
JOBMAN_DASHBOARD_LAB_INSTALL_STAGING="$STAGING" \
JOBMAN_DASHBOARD_LAB_INSTALL_PLAN_SHA256="$PLAN_SHA256" \
JOBMAN_DASHBOARD_LAB_INSTALL_IMPLEMENTATION_SHA256="$IMPLEMENTATION_SHA256" \
JOBMAN_DASHBOARD_LAB_EXECUTION_RECEIPT="$ACTUAL_HOST_EXECUTION_RECEIPT" \
go test -tags integration ./internal/auth \
  -run '^TestLabFreshInstallationAndSupportedRollback$' -count=1 -timeout=17m
```

Use the repository's pinned Go toolchain/runtime configuration. Credentials are
read by existing private synthetic sign-in helpers and stay in memory; no bearer
or password is placed in argv, environment, receipts or diagnostic output.
The test has an11-minute main context, two bounded sign-ins, and a separate
3-minute cleanup budget; the17-minute outer timeout leaves teardown margin.

The harness proves a new empty application database and independent account
records, real native PKCE and new confidential BFF/CSRF behavior, source-qualified
job/log access and Bob's denied namespace, exact accepted execution bytes and
cursor continuation, fresh deterministic metadata and redacted-log reports with
sealed citations, preferences, and one **disabled** personal rule. It then:

- records baseline HTTP and database preservation receipts;
- explicitly upgrades only the two new units and API webRoot to the second
  package, with no schema migration or configuration-revision change;
- rechecks the same browser session, account, keys, preferences, disabled rule,
  original log bytes and exact reports/citations, plus retained database facts;
- explicitly rolls the new units/webRoot back to the baseline package and
  repeats those assertions;
- logs out the new private BFF session, stops/disables only the new units and
  disables only the new confidential client, preserving the database, objects,
  roles, keys, HBA rule, packages and all receipts for inspection;
- closes the operation only after all three verification receipts and fresh
  read-only stopped/client-disabled observations are confirmed.

This is Lab HTTP/API acceptance, not a claim of browser visual, production AD FS,
physical iPhone, or APNs delivery acceptance.

## Failure, lost replies, and recovery

Every mutation is preceded by an exclusive private host intent and guest intent.
Guest phases use a root-owned lock; the host also holds a per-Lab lock. The
initial snapshot pre-creates that private single-linked host lock before the
long Go acceptance invocation. Every phase rechecks its strict owner/mode/link
identity; a transient extra link fails closed instead of weakening validation.
The harness hashes and executes all nine implementation siblings from the frozen
archive and passes the separate actual Lab root solely for SSH inventory. It
does not require credentials to be copied into the source archive. A failed
phase leaves all pending/completed receipts intact and must stop the sequence.
There is no automatic rollback, destructive cleanup, secret replacement,
repeated migration, or repeated uncertain restart.

If a **guest completed receipt exists** but its response/host receipt was lost,
use only the read-only observation path after independently reviewing the exact
pending operation:

```sh
python3 "$IMPLEMENTATION/scripts/install-dashboard-fresh.py" observe \
  --observed-phase "$EXACT_UNCERTAIN_PHASE" --lab-root "$LAB" --staging "$STAGING" \
  --expected-plan-sha256 "$PLAN_SHA256" \
  --expected-implementation-sha256 "$IMPLEMENTATION_SHA256"
```

Observation validates current state and adopts only that exact durable completed
receipt. It never executes the phase. If a receipt is missing, effects are partial,
files differ, or a unit start response was lost before completion, retain the
failure and use a separately reviewed **forward recovery** packet. That packet
must inspect exact own-unit PIDs, hashes, current schema/roles, HBA bytes and client
identity before proposing any action. Do not delete intents, repair existing
paths, rotate keys, rerun the test with a new operation ID, or reset the database
to turn a failure into a pass.

After an uncertain transition, planned `stop --apply` remains available only for
the two new units with exact reviewed unit bytes and UID ownership. This is a
safe close of the disposable service, not an application rollback. It uses the
ordinary90s stop policy, never forced cgroup termination. If stop is itself
uncertain, observe its completed receipt or inspect explicitly; do not retry it.
`retire-identity --apply` requires the confirmed stop receipt and exact new-client
ID/secret/policy. Incomplete acceptance has no successful `complete.json` claim.
Partial provisioning before units/client exist needs a separately reviewed close;
this tool does not guess what it owns from a matching name alone.

Keep original primary and restore services untouched during recovery. Before any
later exercise, reverify their exact original config/key/binary/source/hold/data
pins, including monotonic primary feed progress. Retained HBA entries and roles
apply only to the fixed disposable database; removing them is a separate approved
cleanup, outside this acceptance's scope.

## Offline validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 "$LAB/scripts/test-dashboard-install.py"
go test -race -tags integration ./internal/auth \
  -run '^TestLab(Installation|FreshInstallation)' -count=1
```

With live opt-ins absent, the full scenario skips and the Go guard tests run. The Python tests exercise package/schema identity, fresh role/secret
separation, actual packaged unit transformations, no cross-role source keys,
new-client callback policy, private filesystem bounds, primary/restore identity
preservation, pending-before-effect/no retry, read-only receipt adoption, exact
operator/DDL DSN pins, and retained-data mismatch rejection. Actual package pair,
source SQL/schema proof, concrete plan review and live phases remain separate
gates; passing offline tests never authorizes a guest mutation.

## A separate attempt after a preserved failure

The first `v1` acceptance stopped at its preference request before reports, rules,
upgrade or rollback. Its exact operation remains failed; the confirmed stop and
client retirement do not imply successful acceptance. Keep its original archive,
plan, private run log, pending and completed phase receipts, database, releases,
keys and empty report root. Do not restart it or create `complete.json` for it.

The driver now accepts only two finite resource profiles. The default `v1`
retains its original plan format and resources. Explicit `--scope v2` uses
`jobman_install_v2`, four `jobman_install_v2_*` roles, API/worker UIDs21923/21924,
reader GID21925, port49443 and client `jobman-dashboard-install-web-v2`.
Its config, units, releases, reports and operation roots use the fixed
`jobman-dashboard-install-v2` stem. The fresh preflight must still prove those
identities, paths, port and database unused. Arbitrary resource names are refused.

Before v2, independently review the separate exact-operation abort helper. It
hash-checks the failed v1 plan and implementation, run failure/log, acceptance
intent, confirmed stop and disabled-client receipts. It makes only read-only
observations of v1 own files/releases/units, disabled client and secret digest,
ledger, rows and roles, twice. It writes an exclusive host receipt with
`aborted:true, accepted:false`; it never invokes an old phase or writes a guest
marker. An incomplete observation retains its pending evidence without an abort
receipt. No original receipt is rewritten. This helper's exact manifest and
script hash are separate review inputs, not an installer bypass.

Every v2 command, including snapshot and prepare, additionally requires:

```sh
--scope v2 --previous-attempt "$REVIEWED_ABORT_RECEIPT" \
  --expected-previous-attempt-sha256 "$ABORT_RECEIPT_SHA256"
```

The three-host snapshot embeds that same reviewed envelope. Each later phase
rechecks v1's exact stopped/disabled state and retained own-state fingerprints.
Normal primary jobs are outside that prior-attempt fingerprint; the new v2
snapshot pins the then-current primary/source state independently. `prepare`
copies the envelope to private `previous-attempt.json` in its staging directory
for the acceptance harness. The Go harness derives its origin, OIDC client,
transport allowlist and phase arguments only from the validated finite scope;
it cannot use a v1 continuation for v2. New keys and secrets are generated for v2.
A v1 abort receipt cannot satisfy the schema probe's successful-completion gate.

## Separate schema-refusal acceptance

The [schema-refusal driver](DASHBOARD_SCHEMA_REFUSAL.md) is implemented and
independently reviewed offline. Its live invocation remains separate. It requires
a successfully completed, stopped installation and preserves that accepted
installation while testing a separately named probe database. A failed or merely
aborted installation cannot authorize this follow-on. No schema-refusal result is
claimed here.
