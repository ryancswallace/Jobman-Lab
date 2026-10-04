# Add the verified secondary source to the split Dashboard

Status: offline implementation, awaiting independent apply-driver review. The secondary source itself is provisioned as
recorded in [second-source evidence](DASHBOARD_SECOND_SOURCE.md). Primary Slurm mapping revision6 is runtime-verified. Its exact private
configuration snapshot has been captured read-only; live configuration/restart
work remains frozen while the separate original Slurm array is investigated. No Dashboard/broker configuration has been changed by this
planner. The intended change is additive revision6→7, preserving the resumed
notification hold (`held=false`, generation3).

## Review boundary and exact inputs

`dashboard-multisource-plan.py` accepts only the three revision6 split configs and
the separate minimal operator config, plus the verified secondary public fixture.
`stage-dashboard-multisource.py` reads a private local snapshot directory and writes
new private before/after files and hashes. It has no network, SSH, SQL, key
creation or service action. All inputs are bounded regular0600 files in a real
owned0700 directory; output is exclusive and survives restrictive umasks.

A separately reviewed read-only snapshot step must obtain actual API/worker
configs from storage01 and broker/operator configs from their installed hosts,
record ownership/mode/hash and process/package identity, and confirm that all
revision6 services are working. The offline command intentionally does not label
provided snapshots as live-verified:

```sh
python3 scripts/stage-dashboard-multisource.py \
  --snapshot-directory /absolute/private/runtime6-snapshot \
  --output-directory /absolute/private/multisource7-plan
```

The snapshot files are `api.json`, `worker.json`, `broker.json`, `operator.json`
and `secondary-fixture.json`. Do not put raw tokens, passwords or private-key
contents into configuration JSON. The staged private review includes full source
paths but no secret file contents. The captured revision6 configuration hashes match the verified Slurm mapping
receipt. Staging itself remains an offline operation.

## Additive configuration and material

Existing source entries, mappings, caller registrations, OIDC/session/report
settings, bindings, provider settings and hold flags remain semantically identical.
Only the following additions and monotonic revision advance are planned:

- API and worker append the secondary Control with its exact fresh instance,
  namespace allowlist and distinct pre-registered role signing/mTLS identity.
- Each appends one source-qualified remote broker entry and the two secondary
  target-generation `lab-nfs/v1` mappings. The existing broker HTTPS server trust
  remains unchanged.
- The broker appends the secondary Control using its dedicated source-side identity,
  two new API/worker caller registrations, and two roots pointing only to
  `/data/jobman/alice/dashboard-secondary`.
- The minimal read-only operator configuration adds the secondary display entry.

Copy only each intended process's source leaf certificate, leaf private key,
delegation signing key and public source CA. Never copy the secondary CA private
key, database URL, Control environment or LDAP material into API/worker/broker
secret directories. Keep role ownership21904/21905/21901 and private0600 modes.

API→broker and worker→broker each receive a fresh independent signing key and
clientAuth-only TLS leaf signed by the secondary fixture CA. Generate these only
in private, receipt-bound operator staging on control01; the CA key remains at
its existing source root. The broker receives only those leaf certificates and
signing public keys. Its new client trust bundle preserves the exact original
CA bytes and appends only the verified secondary public CA. Retain durable
original/new bundle hashes and compare the original live hash before the swap;
no existing trust file is overwritten or removed. A new trusted CA does not
replace the broker's exact key/certificate/service/audience/source bindings.

## Phased apply driver — no live apply yet

Before any secret/config write, independently recheck both sources' actual
TLS identities, recovery epoch1, allowed namespaces, current directory proofs,
service public-key fingerprints and operations; verify the source2 immutable
material against its completed preparation receipt. Snapshot both source units,
original Control/Keycloak/directory, current source registry/feeds and global hold.

The driver persists private exact backups/pending receipts and
installs only the intended new files with no overwrite, validates all staged configs
as the real service identities, then uses exact SHA comparisons and atomic swaps.
A coordinated restart restarts only broker, API, then worker, retaining both
Control sources and their directories. The old worker may briefly fail its
configuration-revision fence while API establishes the new registry revision;
it retries after the exact worker restart. The driver must
verify current readiness, source registry, original bindings/feeds and unchanged
hold generation3 before completion. Service configuration revisions must stay
aligned; no reset, implicit source retirement, hold release, or broad grant change.

Recovery commands need a separate private API-shaped configuration with the
current revision and the ingestion worker identities for both sources. Its
privileged database credential remains operator-only; do not expand the API or
read-only observer grants. Generate/review this exact operator configuration as
part of the apply plan, without exposing its private credential.

On interruption, preserve evidence. Continue only the exact reviewed remaining
work after proving its current state, or prepare an explicit forward revision8+
from live values. Never restore a revision6 file after revision7 is observed,
remove a registry ledger, rotate existing keys, or reset an event cursor to make
startup succeed.

## Driver invocation and interruption behavior

Archive the exact reviewed implementation before invoking it. Its executable
manifest covers `apply-dashboard-multisource.py`,
`dashboard-multisource-guest.py`, `dashboard-multisource-runtime.py` and
`dashboard-multisource-plan.py`. A canonical sorted/indented JSON map of these
filenames to SHA-256 digests (with one final newline) is itself hashed and passed
as `--expected-implementation-sha256`. The explicit `--lab-root` preserves the
pinned SSH inventory and host-key path when running from an immutable archive.

Every phase requires the same private staged review, exact secondary preparation
receipt, original secondary public fixture bytes and their reviewed digests:

```sh
python3 /absolute/private/reviewed/apply-dashboard-multisource.py \
  --lab-root /absolute/jobman-lab \
  --staging /absolute/private/multisource7-plan \
  --secondary-prepare-receipt /absolute/private/secondary/prepare.json \
  --secondary-fixture /absolute/private/runtime6-snapshot/secondary-fixture.json \
  --expected-prepare-sha256 REVIEWED_PREPARE_SHA256 \
  --expected-review-sha256 REVIEWED_PLAN_SHA256 \
  --expected-implementation-sha256 REVIEWED_IMPLEMENTATION_SHA256 \
  --phase preflight
```

After review and a coordinated window, invoke phases `materials`, `install`,
`apply`, `restart`, then `verify` sequentially with the same arguments. The first
four mutating phases additionally require `--apply`. Default `preflight` and final
`verify` perform no guest configuration or service writes. Host receipts use an
exclusive lock and owned0700 directory; guest receipts use root-owned0700 with
per-execution locks. Mutating preparation/application must occur within30minutes
of the preflight snapshot. An expired snapshot requires review of preserved state;
the driver does not silently renew it.

Preflight and final verification execute fixed read-only SQL inside the existing
pg01 container as the Lab operator. They check the dedicated Dashboard database,
current source instance/epoch/revision, no unfinished recovery or open gap,
primary namespace set/feed generation/monotonic position, current feed observation,
and held=false/generation3. A bounded server-side SHA-256 projection proves
unchanged device-binding rows; no account, token, cursor or binding row is exported.
The separate secondary Control database must retain migration21, its exact
instance/epoch and two fresh namespace directory proofs. These checks do not
add database privileges to either runtime process.

Material generation remains on control01. Only the destination role's allowlisted
material is sent to its install phase; no private material goes to pg01. The host
retains generated role material in a private receipt-bound file to recover a lost
response. No CA private key is exported. Installation also creates a new root-only
`/etc/jobman-dashboard-operator-lab/multisource-recovery.json` with the current
API-shaped configuration, ingestion worker Control identities and the existing
privileged legacy Lab DSN path. It is not mounted into runtime processes and does
not broaden their grants.

A completed material phase can return the same sealed material. An uncertain
partial generation or installation stops for inspection and is never overwritten.
A lost CAS response can finish only if exact new bytes, the pending receipt and
original private backup all match. A lost restart response can finish only after
a different process is proven healthy with the exact binary/unit, role and
configuration revision; it never issues a second uncertain restart. Startup polling
is bounded and includes process identity, `/livez`, `/readyz` and revision metrics.
Errors expose fixed phase/failure codes, never command output or credentials.

Offline regression commands (no Lab credentials, SSH or guest operations):

```sh
python3 scripts/test-dashboard-multisource.py
python3 scripts/test-dashboard-multisource-apply.py
```

## Actual acceptance after apply

A new opt-in bounded Dashboard harness will use real synthetic Alice/Bob PKCE and
verified TLS, and preserve private tokens in memory only. It will check:

1. Alice's primary research/operations plus secondary research, and Bob's primary
   research plus secondary research/operations. Equal namespace names remain
   source-qualified. Denied operations return generic authorization errors.
2. Explicit per-source and aggregate overview counts, stable paginated jobs,
   arrays/collections/graphs/targets, with source-qualified deduplication and exact
   totals. Wrong-source namespace/resource and cursor substitution are denied.
3. Cross-owner log access within granted namespaces, original synthetic byte and
   empty-stream states, and denial of cross-source job/run/cursor substitution.
4. A bounded outage of only the exact secondary Control unit, with pinned process
   identity before stopping and unconditional independent cleanup to start it.
   Primary results remain truthfully partial, missing sources do not become zeros,
   and full contributions return after current authorization recovers. Do not stop
   its LDAP service, the primary Control, Keycloak, API, worker or broker.
5. After functional acceptance, separately activate exact account-owned rules and
   use each profile's normal Submit/Cancel fixture operation to emit original
   terminal events in both sources. Verify one account/event inbox fact with all
   matching rules, source-qualified denials, replays and deep links. Delete/stop
   only harness-owned rules afterward. No fabricated terminal SQL or execution
   claim; APNs/device presentation remains a separate gate.

Every mutating harness phase requires a reviewed exact helper/config identity and
cleanup receipt before work. This plan is not yet evidence of multi-source reads,
notifications, actual secondary execution, corporate AD FS or device delivery.

## Receipt-bound inactive recovery-draft continuation

The first revision7 installation reached completed API/worker/broker material
and staged-configuration checks, then failed validation of the new root-only
recovery draft. Its legacy database-file path omitted `-app`:
`/etc/jobman-dashboard-lab/database-url` instead of the existing
`/etc/jobman-dashboard-app-lab/database-url`. No active configuration swap or
service restart had begun. The original archive, private material bytes and
all pending/completed receipts remain evidence.

`continue-dashboard-multisource.py` supports only this exact predecessor:
implementation `c993dcc1b92bf404def903f211862b406c41b3cdbbc4680ee2bcedea1fe82f35`
and execution `1bb641283d575e6df8003c6a5034e67254baae0957309def1d9393702140305b`.
Archive it alongside the four executable driver files; the current implementation
digest includes all five scripts. It cannot continue a different operation or
regenerate material.

Its default `inspect` phase is read-only on both guests. It requires the original
hash-pinned archive and invocation, completed role-install receipts, exact staged
configs and key/certificate hashes, active original config6 bytes/processes and
readiness, unchanged source identities/processes, unchanged hold/device bindings,
and a monotonically advancing primary feed. Any swap/restart receipt refuses
continuation. It records observed service start identities in a host-private
review plan and prints only that plan's digest.

```sh
python3 /absolute/reviewed/continue-dashboard-multisource.py \
  --lab-root /absolute/jobman-lab \
  --previous-invocation /absolute/original-private/invocation.json \
  --expected-implementation-sha256 <reviewed-five-file-digest>
```

After reviewing the resulting concrete continuation plan, repeat that command
with `--phase apply --apply --expected-continuation-sha256 <plan-digest>` within
15 minutes. It records an exclusive additive continuation receipt before writes,
requires the observed service starts to remain identical, and changes only the
inactive recovery draft's exact old bytes to its exact corrected bytes. The
original draft and original implementation binding are retained privately.
Local `check-config` must pass before completion. Both guest execution bindings
then name the reviewed revised driver, with old/new driver and recovery hashes
in the continuation receipts. Runtime configs, services, source state and keys
remain unchanged.

A failure after the draft CAS may resume only with matching pending evidence,
old backup and exact new bytes; it never resets or overwrites unrelated state.
A host response loss can verify completed guest receipts. No automatic rollback
is provided.

Once both guests and the host have completed receipts, resume the original
`apply-dashboard-multisource.py` invocation using the new archived implementation
and its digest, retaining the original staging/plan/prepare arguments and adding
`--continue-from-implementation c993dcc1b92bf404def903f211862b406c41b3cdbbc4680ee2bcedea1fe82f35`.
Run `install`, then `apply`, `restart`, and `verify` sequentially. The resume path
requires the completed continuation, cannot run `preflight` or `materials`, and
revalidates existing role-install receipts rather than generating new keys.
Its 30-minute phase freshness bound starts at the completed continuation's
fresh runtime/database checks; the original preflight is not rewritten.
