# Synthetic API authentication-master rotation

This is a one-time, explicit Lab acceptance operation. It rotates the browser
authentication master in the already split API process. It does not rotate
notification encryption, report policy, log cursor, delegation, TLS, database,
Keycloak, or Apple material. It does not apply a schema migration or alter a
source namespace, role, event hold, cursor, or feed binding.

Run it only after configuration 8 activation, its feed recovery/resume, and the
separate scale/mixed-load acceptance have finished. All three Dashboard processes
must run the same independently reviewed exact candidate revision. The snapshot
pins that revision explicitly; it does not assume RC2 remains current after
later reviewed fixes. Both source feeds must be active at revision 8/schema 18,
with the final 12/7 namespaces, no open gap/recovery and delivery hold false.
Ordinary ingestion may advance feed generation and position during the exercise;
source instance, epoch, namespaces, schema checksums, database identity, role
grants and the complete delivery-hold record may not change.

## Private material and exact changes

The new key is generated once on storage01 using 32 bytes from `os.urandom`.
It is never an argument, environment value, SSH output or host artifact.

| Material | Owner/mode | Purpose |
| --- | --- | --- |
| `/etc/jobman-dashboard-auth-rotation-lab/` | root, 0700 | Exclusive operation intent, key backup and phase receipts |
| `.../key` | root, 0600 | Exact new key bytes, retained for forward recovery |
| `.../recovery.json` | root, 0600 | New separate operational API-shaped configuration |
| `.../api-before.json` | root, 0600 | Original API configuration backup |
| `/etc/jobman-dashboard-api-lab/authentication-rotation-v1.key` | 21904:21904, 0600 | New API authentication key |
| `/etc/jobman-dashboard-api-lab/authentication-rotation-v1.json` | 21904:21904, 0600 | Validated draft retained after activation |

Only the active API `encryption` object changes, to key ID
`lab-auth-rotation-v1` and the new key path. Configuration revision 8 remains
unchanged because the source registry and all source authority are identical.
Every other API field and all worker/broker configuration and units are preserved.
The old master must be exactly 32 bytes and must not be reused by another
configured purpose. Explicit separate token, report-policy and log-cursor key
files are prerequisites.

The original `/etc/jobman-dashboard-operator-lab/scale-recovery.json` and every
scale activation receipt remain byte-identical. The new root-only recovery file
changes only its authentication `encryption` object. It keeps the original
privileged database reference, worker source credentials, and exact old static
root, if an earlier binary-only upgrade deliberately preserved that static root.
No existing recovery file is overwritten.

## Prepare and review

Archive these exact implementation files together, preserving the dependency:

```text
dashboard-auth-rotation-plan.py
dashboard-auth-rotation-guest.py
rotate-dashboard-auth.py
dashboard-multisource-runtime.py
```

The archive's directory, the private snapshot parent and host staging parent must
be real absolute paths. Host records are 0600, staging 0700. The implementation
hashes are part of the reviewed plan. The driver requires the established pinned
Lab SSH inventory/known-hosts; it neither modifies host DNS/CA trust nor suppresses
SSH/TLS verification. Remote source capability reads verify the configured CA.

Commands below contain only paths and public digests; use actual reviewed values:

```sh
python3 /absolute/archive/rotate-dashboard-auth.py snapshot \
  --lab-root /Users/rcw/home/code/jobman-lab \
  --snapshot /absolute/private/snapshot.json
python3 /absolute/archive/rotate-dashboard-auth.py prepare \
  --snapshot /absolute/private/snapshot.json \
  --staging /absolute/private/new-rotation \
  --revision EXACT_REVIEWED_DEPLOYED_COMMIT
```

`snapshot` performs bounded read-only guest inspection. `prepare` is entirely
offline and recomputes the exact API/recovery delta. Independently review the
resulting private `plan.json`, public-safe `review.json`, implementation hashes,
unchanged purpose-material hashes and source/database/hold pins before applying.
Never upload private snapshots or plans to GitHub or CI.

Each subsequent invocation includes the exact `--lab-root`, `--staging`,
`--expected-plan-sha256` and `--expected-implementation-sha256`. Run `preflight`
without `--apply`; then run `stage --apply` under the authorized Lab coordination.
All new effects must begin within one hour of the preflight. `stage` creates
private material and validates the draft with the existing exact binary as the
API user; it does not change active configuration or restart any process.

The Dashboard opt-in harness then creates in-memory old credentials and invokes
only `apply --apply`, `restart --apply` and `verify --apply` from that same archive.
See Dashboard `docs/LAB_AUTH_ROTATION.md` for its exact invocation and required
retained report evidence. Do not manually activate the key before the harness
captures old credentials, because that would discard the acceptance baseline.

## Failure and forward recovery

Every mutation has an exclusive host/guest intent before effects and a completion
receipt after verified effects. Competing plans cannot share the operation.
Host and guest locks prevent concurrent phase attempts. A lost reply stops normal
execution and preserves the pending receipt. `--observe-only` can prove an
already completed effect without repeating it; in particular a pending restart
can only observe a newer ready API process, never issue another restart.

A partial stage never generates replacement key bytes automatically. A partial
configuration write is accepted only when exact after-bytes and the retained
before-backup prove the original CAS completed. Unexpected bytes, process
generations or authority changes require a new narrowly reviewed continuation;
do not delete pending evidence or start a new rotation to hide a failed phase.

Once the API may have loaded the new key, **never restore the old authentication
master to make old credentials valid again**. Recover forward with the retained
new key/configuration and reviewed current binary. If a binary fallback is
needed, prepare a separate reviewed exact-binary change that retains the new
authentication key and unchanged purpose keys. No automatic rollback exists.
Existing old session rows are not deleted by this operation; normal expiry and
retention remove them. The retired key is preserved privately for evidence, not
configured for authentication reads.

The current authentication format has no readable per-record key-ID envelope.
Retired-key decryption/MAC failures and malformed current-key cryptographic data
are both invalid credentials (401). Actual dependency transport or store errors
are unavailable (503). The exercise does not claim to distinguish ciphertext
corruption from key retirement, transparent browser-session continuity, external
AD FS rotation, APNs signing rotation or production acceptance.

Offline tests:

```sh
python3 scripts/test-dashboard-auth-rotation.py
```

The suite uses synthetic local files and subprocess stand-ins only. It must never
load Lab credentials, invoke a guest or contact a provider in CI.
