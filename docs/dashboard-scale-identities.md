# Dashboard scale identities

This bounded Lab workflow creates exactly `dashboard-scale01` through
`dashboard-scale25` in the existing `jobman-lab` Keycloak realm. It prepares
identity inputs for the separately reviewed Control scale fixture. It does not
seed source jobs or namespaces, change directory state, configure Dashboard
sources, rebind feeds, restart services, or change the delivery hold.

The initial implementation is offline only. Live invocation requires the
coordinated Lab window after the existing Slurm acceptance work releases its
source/configuration freeze. Keycloak exercises synthetic OIDC mechanics;
these checks do not establish corporate AD FS compatibility or workload scale
acceptance.

## Fixed account and preservation contract

Each account has a permanent independently generated 64-character hexadecimal
password. The credential variable is
`JOBMAN_LAB_DASHBOARD_SCALE01_PASSWORD` through `...SCALE25_PASSWORD` in the
existing private `.lab/credentials/dashboard.env`. Existing bytes and values
are retained exactly, followed by the new lines. No password is printed.

The display names are exactly `Synthetic scale 01` through `Synthetic scale 25`.
The immutable `dashboard_directory_guid` user attribute contains
`74000000-0000-4000-8000-000000000001` through `...000025`. The existing signed
`directory_guid` token mapper, API audience and PKCE clients are verified and
preserved. The helper never writes a client, mapper, profile, realm, existing
user, group, or password-reset endpoint. It sends each new user's password in
that user's sole creation request.

A bounded inventory rejects conflicting usernames (including case variants),
GUIDs, and existing local password keys. Before and after creation it verifies
hashes of every preexisting user representation, all clients, the user profile,
and the realm. Any concurrent identity configuration drift stops the phase.
User sessions and password representations are not requested. Inventories are
bounded to 100 users and 64 clients; those are fixture limits, not product limits.

The actual Keycloak subject UUID returned by each successful creation is
verified through a subsequent GET and saved in a root-private per-account
receipt. No guessed subject or synthetic replacement is exported.

## Reviewed executable and storage boundaries

Archive these three scripts together before live use:

- `scripts/dashboard-scale-identities.py`
- `scripts/dashboard-scale-identities-common.py`
- `scripts/dashboard-scale-identities-guest.py`

`--lab-root` is explicit, so an archived implementation does not infer the Lab
root from its own location. Every phase verifies the caller's expected digest
of all three scripts. Preflight also pins the checked-in existing identity
helper to the installed guest helper's exact SHA-256. It reuses only that
helper's verified HTTPS administrative client and client-policy verification;
it does not invoke its reconciliation entry point.

Host staging, backups and locks use private 0700 directories and 0600 files,
with no-follow descriptor checks and bounded reads. The exact original and
revised credential bytes stay in that private staging directory. New writes
set their descriptor mode explicitly even under a restrictive umask.

The only guest is pinned `control01` through the existing private
`.lab/dashboard/ssh-connections.json` and strict Ed25519 `known_hosts` file.
The guest uses the existing explicit Lab CA for
`https://oidc.lab.test:8443`; it does not change host DNS, trust settings,
Keycloak configuration or service units. The existing Keycloak administrator
credential is read locally inside the guest and its access token remains in
memory. Only the 25 new passwords cross SSH stdin.

Guest receipts live beneath
`/var/lib/jobman-dashboard-scale-identities/<stage-sha256>` as root 0700/0600.
A global guest lock and host staging/credential-directory locks exclude
concurrent runs of this workflow. HTTP calls, response sizes, subprocess
output, and overall guest execution time are bounded. Failures print only
fixed sanitized codes, never remote error bodies or credentials.

## Phased invocation

Use an already reviewed archive and an absolute private staging directory.
The placeholders below are operator-supplied paths and independently reviewed
digests. Do not substitute any credential or access token on a command line.

```sh
python3 /absolute/reviewed/dashboard-scale-identities.py \
  --lab-root /absolute/jobman-lab --phase digest
```

`digest` is local and does not read credentials or contact a guest. Record its
`implementationSHA256`, then use that exact value for every remaining phase.
The default phase is read-only guest `preflight`; it writes host evidence only:

```sh
python3 /absolute/reviewed/dashboard-scale-identities.py \
  --lab-root /absolute/jobman-lab --staging /absolute/private/scale-identities \
  --implementation-sha256 <reviewed-implementation-sha256> --phase preflight

python3 /absolute/reviewed/dashboard-scale-identities.py \
  --lab-root /absolute/jobman-lab --staging /absolute/private/scale-identities \
  --implementation-sha256 <reviewed-implementation-sha256> --phase stage
```

`stage` is local only. It saves fresh passwords and the exact additive credential
transform, then prints a nonsecret `stageSHA256`. Independent review can inspect
the plan, field names, account identities and hashes without exposing passwords.
First application requires a preflight no more than 15 minutes old and guest
clock agreement within 30 seconds; use a fresh private staging directory if a
pre-application receipt expires. Retain the previous staging as evidence.

Explicit application first repeats the read-only identity preflight, then
appends the local credentials through a double-checked compare-and-swap with
an exact private backup. It records a pending receipt before replacing the
credential file, and only then may create accounts:

```sh
python3 /absolute/reviewed/dashboard-scale-identities.py \
  --lab-root /absolute/jobman-lab --staging /absolute/private/scale-identities \
  --implementation-sha256 <reviewed-implementation-sha256> \
  --stage-sha256 <reviewed-stage-sha256> --phase apply

python3 /absolute/reviewed/dashboard-scale-identities.py \
  --lab-root /absolute/jobman-lab --staging /absolute/private/scale-identities \
  --implementation-sha256 <reviewed-implementation-sha256> \
  --stage-sha256 <reviewed-stage-sha256> --phase verify
```

`verify` makes only guest GETs after obtaining its administrative token. It
checks all 25 receipt-bound subjects and unchanged preexisting policy, verifies
the local credential bytes and records local verification evidence. The
resulting `identities.json` contains public subject/GUID/name mappings and
preservation hashes, with no passwords or tokens; it remains mode0600.

## Retry and failure behavior

Keep the complete staging and guest receipts after every failure. Do not delete
pending receipts, rerun the old broad identity reconciler, or reset passwords.

A completed per-account receipt permits a retry to verify and skip that exact
subject. A lost host response after guest completion is recoverable by running
the same reviewed `apply` phase and stage digest; no account is recreated.
The same is true when earlier accounts completed and a later account has not
yet entered its pending creation step.

An individual creation with a pending receipt but no completed subject receipt
is deliberately uncertain. It stops even if a user with matching visible fields
exists, and even if the preceding network request appears to have failed before
creation. An operator must inspect the bounded evidence and review a separate
continuation; this tool has no automatic adoption, reset, or cleanup command.
If credentials already equal the revised bytes, exact matching pending and
backup evidence are required before continuing. Any unrelated credential or
identity-policy change fails closed. The tool never rolls credentials back
after account creation could have occurred.

## Fresh source handoff

Generate Control inputs only when source preparation is ready. Supply one
explicit canonical UTC timestamp older than one minute and no more than seven
days old, as required by the reviewed Control fixture. This separate local
phase avoids consuming that history window while account provisioning waits.

```sh
python3 /absolute/reviewed/dashboard-scale-identities.py \
  --lab-root /absolute/jobman-lab --staging /absolute/private/scale-identities \
  --implementation-sha256 <reviewed-implementation-sha256> \
  --stage-sha256 <reviewed-stage-sha256> --phase handoff \
  --history-at <YYYY-MM-DDTHH:MM:SSZ> \
  --output-directory /absolute/private/scale-source-inputs
```

The immutable output files are `primary-scale-input.json`,
`secondary-scale-input.json`, `identities.json`, and `handoff.json`. Each source
input has only `instanceId`, `issuer`, `historyAt` and the 25 ordered
`{directoryId,subject,name}` objects. The pinned instances are
`e633cf92-258d-48ff-965a-fda88d68ef3a` and
`a4f0e2ab-7323-4c90-9510-1f073c660f06`. Existing files must match exactly; use a
new output directory for a later history timestamp.

A subsequent reviewed workflow must seed sources, upgrade the synthetic LDAP
helper bounds before loading 25 extra identities, install direct viewer-group
state and alias mappings, extend service scopes, and explicitly rebind/replay
both notification feeds. None of those actions is performed here.

## Offline regression checks

```sh
python3 scripts/test-dashboard-scale-identities.py
python3 -m py_compile scripts/dashboard-scale-identities*.py
```

The tests use temporary private directories and an in-memory Keycloak model.
They never load `.lab` credentials, contact a guest or mutate an identity server.
They cover exact account/claim/name bounds, preservation, conflicting identities,
complete and uncertain creation retries, credential CAS/backup evidence,
restrictive umask and symlinks, locks, public source handoff, whole host phases,
transport loss, and subprocess time/output bounds. This is offline evidence;
actual sign-in and source authorization remain separate live acceptance gates.
