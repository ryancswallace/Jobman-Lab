# Synthetic source metadata for scale acceptance

This driver stages a reviewed helper and adds isolated monitoring data to the two
existing synthetic Control deployments. It does not execute workloads, install
configuration, restart services, change delegation scopes, reset event feeds, or
change Dashboard delivery holds. No live seeding result is claimed here.

The fixed helper is Control commit
`367006818e72315b01860f56f971004e17c24886`, executable SHA256
`6f511e91434dac2499d464f0b424607fe0b099b966148c992499e5371a333f65`.
Its separate path is
`/usr/local/libexec/jobman-dashboard-scale/367006818e72315b01860f56f971004e17c24886/jobman-control-lab-helper`.
The file and its new ancestors are root-owned0755; the old helpers remain.
This permits the existing unprivileged LDAP users to execute the same reviewed
binary during the separately reviewed [directory upgrade](DASHBOARD_SCALE_DIRECTORY.md).

The fixed primary deployment is `72000000-0000-4000-8000-000000000001`, instance
`e633cf92-258d-48ff-965a-fda88d68ef3a`, database `jobman_dashboard_control`.
The secondary is `72000000-0000-4000-8000-000000000002`, instance
`a4f0e2ab-7323-4c90-9510-1f073c660f06`, database
`jobman_dashboard_control_secondary`. Both must retain epoch1 and schema21.
The driver refuses the original `jobman_control` database as a target.

The primary receives10 namespaces and the secondary5, named
`dashboard-scale-01` onward. Each has50 jobs admitted through the normal Store
and10,000 explicitly imported successful history rows. These have no executor,
runs, agent observations or terminal-transition events. History is monitoring
metadata, not execution evidence; separate host/Slurm tests establish execution.
All25 users come from the completed synthetic identity provisioning handoff,
using its actual immutable OIDC subjects. The driver cannot mint subjects or
read account passwords. Input history time must be UTC seconds, between one
minute and seven days old.

## Reviewed phases

Archive these three implementation files and their printed digest together with
this runbook and `test-dashboard-scale-source.py`. Run from that immutable
archive, with `--lab-root /Users/rcw/home/code/jobman-lab`; SSH uses the existing
pinned inventory and host keys. `--phase digest` prints only code hashes.

Use a root-private0700 host parent and a fresh staging directory for each
profile. All non-digest phases require `--implementation-sha256` and `--staging`.
No phase automatically advances to another:

1. `--phase stage --apply --helper /absolute/path/to/exact/helper`: install only
   the exact executable at its fixed new path. The guest verifies existing
   executable ancestors, sets exact modes even under umask077, preserves all
   source/LDAP/Keycloak/broker process identities, and saves a private
   `binary-stage.json`. Repeating this phase accepts only identical bytes.
2. Complete the separate LDAP helper upgrade before capturing the source
   preflight. The seeder pins both LDAP processes and cannot reuse a preflight
   from before either process changed.
3. `--phase preflight --profile primary|secondary --identity-handoff /private/dir`:
   read-only source and PostgreSQL checks. Save and review `preflight.json` and
   its printed SHA256 before seeding. The handoff must include matching
   `identities.json`, `handoff.json` and both source input files. Source files,
   process IDs/start times/executable and unit hashes are pinned; SQL binds the
   exact database/instance/epoch/migration ledger and original namespaces/jobs.
   No scale namespaces or subjects may already exist. The preflight requires
   at least1GiB free on control01,2GiB on pg01, eight available PostgreSQL slots,
   and a database no larger than1GiB. It must be no older than15minutes at seed.
4. `--phase seed --apply --profile ... --identity-handoff ... --preflight-sha256 ...`:
   recheck the reviewed baseline, then run the fixed helper as root. Privilege is
   required to read the secondary directory user's private state; it does not
   copy LDAP, delegation or certificate keys. Only the exact source DSN is read
   from its pinned JSON-quoted environment and written to the private operation
   directory. It never appears in argv, host output or receipts. The helper has
   four database connections, an eight-minute context, GOMAXPROCS2 and a512MiB
   Go soft memory limit. The surrounding process has a490second deadline and
   bounded output streams. These are test-operation bounds, not production
   capacity guarantees.
5. `--phase verify --profile ... --identity-handoff ... --preflight-sha256 ...`:
   verify helper completion, unchanged source files/processes and original
   namespace/job metadata, then exact new namespace/job totals and absence of
   execution/terminal events. Download only `seed.json`, `directory.after.json`,
   `directory-state.after.json`, `receipt.json` and the driver receipt into the
   private `handoff` directory. Draft validation reconstructs the exact additive
   mapping, preserves every old identity/alias/membership and binds each new
   namespace to a direct viewer group containing all25 identities. Both source
   mapping and directory-state revisions advance once in the draft only.

The original metadata digest includes immutable job identity, ownership,
creation time, name, import flag and request/workload digests. It deliberately
excludes evolving job phase and lease fields, so ordinary existing agents can
continue. Namespace identities/names and total count must remain consistent;
unrelated concurrent admissions or administrative changes invalidate the
preflight or verification. PostgreSQL checks use bounded read-only transactions.
The private handoff is not a public release artifact and must not be uploaded.

## Uncertain completion and authority

Guest driver `pending.json` and helper `.scale-seed.pending.json` are durable
before mutation and are never deleted to obtain a pass. A helper completion
receipt is also retained. After an SSH timeout, invoke `verify`, not another
seed: verification can recover a completed helper response without invoking the
helper. It can write completion receipts and copy verified evidence, but it
cannot seed or repair database data. A pending operation without exact helper
completion requires inspection and a separately reviewed recovery; neither this
driver nor the helper retries partial namespace/history insertion. An existing
completed diagnostic receipt is allowed; the distinct diagnostic pending marker
or any directory acceptance marker blocks seeding.

Normal Store bootstrapping temporarily grants the new identities authority in
new namespaces. **Do not expose those namespaces through Dashboard or broaden
service namespace scopes until ordinary directory reconciliation has adopted
all new identities and proven viewer-only grants.** Installing the two additive
directory drafts, reconciling, extending service scopes, and auditing feed gaps
are separate reviewed phases. Keep the drafts' exact original hashes as CAS
inputs. The seeding driver performs none of those actions and makes no claim of
new user authorization or multi-user performance acceptance.

Run `python3 scripts/test-dashboard-scale-source.py` for offline validation of
profile/time/subject bounds, exact additive authority drafts, strict private
files, umask behavior, command deadlines, read-only SQL, collision/capacity and
no-execution checks, pending/lost-response behavior, and private output hashes.
Guest SQL/process checks and actual seeding still require an approved live plan.
