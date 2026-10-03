# Jobman local lab

This repository builds a synthetic, production-shaped Jobman test environment
on an Apple Silicon Mac with Parallels Desktop Pro. The lab is completely
defined by Vagrant, Packer, Ansible, checked-in topology data, and bounded
lifecycle scripts. Generated images, credentials, keys, caches, and VM state
live beneath `.lab/` or `.vagrant/` and are intentionally ignored.

The lab never bridges to the Mac's LAN. Every VM has one Parallels shared-NAT
adapter for outbound package and image downloads and one host-only adapter on
`10.77.0.0/24` for lab traffic. All names, identities, credentials, namespaces,
certificates, and workload data are synthetic.

## Topology

```text
Mac host
  |
  +-- Parallels shared NAT (egress only)
  |
  `-- 10.77.0.0/24 host-only network
       |-- storage01   .10  NFSv4 + SMB3, dedicated 100 GiB sparse disk
       |-- pg01        .20  PostgreSQL 17.6
       |-- control01   .21  Jobman Control + Keycloak test OIDC
       |-- slurmctl01  .30  slurmctld + slurmdbd + MariaDB
       |-- submit01    .31  Slurm client + Alice/Bob Jobman agents
       |-- compute01   .32  slurmd
       |-- compute02   .33  slurmd
       |-- linuxws01   .40  AlmaLinux workstation
       `-- winws01     .50  Windows 11 ARM64 workstation
```

All Parallels VM names start with `jobman-lab-`. Linux guests use the pinned
official `almalinux/9` ARM64 Parallels box. Packer creates one secret-free
Windows 11 ARM64 Vagrant base box from the locally supplied ISO. Ansible adds
all lab identities and credentials only after cloning the base images.

The two users are `alice` (namespace administrator) and `bob` (submitter), with
stable Linux UID/GID values. They have individual synthetic passwords and SSH
keys. The `research` namespace has three Control targets:

- `onprem-slurm`, backed by `submit01` and the two compute nodes;
- `linux-workstation`, backed by per-user agents on `linuxws01`; and
- `windows-workstation`, backed by per-user scheduled agents on `winws01`.

Slurm 25.05.8 is built once from its checksummed SchedMD source archive,
published to `/shared/apps/slurm`, and installed identically on every Linux
host. `slurmdbd` and MariaDB retain accounting data used by Jobman's `sacct`
reconciliation path.

## Storage contract

| Purpose | Storage path | Linux mapping | Windows mapping |
| --- | --- | --- | --- |
| data and artifacts | `/srv/lab/data` | `/data` | `X:` / `\\storage01\data` |
| shared applications | `/srv/lab/shared` | `/shared` | `T:` / `\\storage01\shared` |
| per-user homes | `/srv/lab/home/<user>` | `/home/<user>` | `S:` / `\\storage01\home\<user>` |

Linux mounts use NFSv4 with `root_squash`; each home is exported and mounted
individually so Vagrant's local account remains independent. Windows uses
SMB3 and maps drives at each user's interactive logon. Windows OpenSSH keys,
Jobman configuration, bearer tokens, and agent journals remain on local NTFS;
`S:` is user data, not a Windows service-profile substitute.

Jobman log and artifact bytes use the logical store `lab-nfs` version 1. Linux
maps it to `/data/jobman/<user>`, Windows clients map it to
`X:\jobman\<user>`, and the Windows agent uses the equivalent UNC path.
PostgreSQL stores only Control metadata and durable intent.

## One-time host preparation

1. Launch Parallels Desktop, sign in, and activate the Pro trial. Verify that
   `prlsrvctl info --license` reports an installed Pro or Business license.
   Merely installing the application does not activate the trial.
2. Install Vagrant in an interactive Terminal because its signed macOS package
   requires an administrator prompt:

   ```sh
   brew install --cask vagrant
   ```

3. Confirm that the Windows ISO remains at
   `/Users/rcw/Downloads/Win11_25H2_English_Arm64_v2.iso`.
4. From this repository, run:

   ```sh
   make bootstrap
   ```

`bootstrap` verifies the host and ISO, installs the pinned
`vagrant-parallels` plugin, installs the pinned Ansible collections and Packer
plugins into `.lab/`, downloads the pinned Slurm source, and creates private
synthetic keys and credentials. Packer 1.16.0 and Ansible 14.3.1 are already
installed by Homebrew on the current host; `make tools` checks the exact
versions rather than silently accepting drift.

No production credential or data is accepted by any workflow. The generated
development CA is trusted only in lab guests.

## Create and operate the lab

Build the base images and create the full topology:

```sh
make images
make up-full
make configure-control
make enroll
make test
```

`make up-full` is deliberately self-sufficient: it verifies/downloads images
and artifacts, cross-builds the current local Jobman and Control source trees,
creates the VMs, generates a strict host-key inventory, and converges all
roles. It reads the three product repositories but does not edit them.

For faster Linux-only work, use `make up-core`. It omits `linuxws01` and
`winws01` but retains storage, Control, PostgreSQL, Slurm, submit, and compute
coverage. Later, `make up-full` adds the workstation pair without rebuilding
the existing core.

Common operations are:

```sh
make status             # Vagrant and lab-prefixed Parallels status
make converge           # start/resume VMs, refresh inventory, and reapply configuration
make configure-control  # refresh OIDC tokens and replay Control bootstrap
make enroll             # enroll missing/expired agents and restart services
make test               # storage, all-pairs SSH, Slurm, Control, Jobman E2E
make halt               # graceful shutdown, state retained
make up-full             # start/reconcile again
make destroy            # confirmed removal of Vagrant-managed lab VMs
```

`make clean-generated` separately removes ignored caches, artifacts,
certificates, and synthetic credentials after an explicit typed confirmation.
It does not remove VMs. Run `make destroy` first if both VM and generated state
must be discarded.

`make converge` is safe after Parallels or macOS suspends the lab. Its inventory
dependency first starts or resumes the selected VMs and waits for their Vagrant
SSH or WinRM communicators before requesting connection configuration.

When `make enroll` detects an expired agent certificate or renewable session,
it stops that agent, renames its state directory with an
`.expired-<timestamp>` suffix, creates fresh state, and enrolls a replacement
identity. It never silently deletes old agent state, and it fails closed when
state is corrupt or unreadable.

## What validation covers

`make test` refreshes short-lived OIDC tokens, idempotently configures the
namespace and targets, enrolls missing Alice/Bob agents, then verifies:

- all Linux and Windows storage mappings;
- key-only SSH from each user across every ordered host pair;
- native Slurm submission from every Linux host and through Windows wrappers;
- healthy `slurmctld`, both `slurmd` nodes, and durable `sacct` records;
- Keycloak OIDC discovery, Control TLS/readiness, and namespace authorization;
- Jobman submission, wait, and verified logs on Slurm and both workstations.

The Windows wrappers (`sbatch.cmd`, `squeue.cmd`, `sacct.cmd`, `sinfo.cmd`, and
`scancel.cmd`) preserve the user-facing ability to reach Slurm from Windows by
SSHing to `submit01`. Jobman shared-mode submission uses Control and its mTLS
agents directly.

`storage01` synchronizes through the NAT adapter and serves time only to the
host-only lab network. Every AlmaLinux guest follows that internal Chrony peer,
and Windows uses it through W32Time. Synchronization permits clock steps after
host sleep so certificate validity and Slurm's Munge authentication recover
before provisioning, enrollment, or validation continues.

## Capacity and reproducibility notes

The full topology assigns about 29 GiB of guest RAM, leaving headroom on a
48 GiB Mac. The storage disk and guest system disks are sparse; reserve at
least 220 GiB of free host disk before the first build. Linked clones keep
repeat runs smaller, while Vagrant and the dedicated storage disk preserve
state across `halt`/`up`.

Exact tool, box, source, ISO, and container pins live in
`config/versions.yml`; VM sizing and addresses live in `config/topology.yml`.
Changing topology data followed by `make converge` handles configuration
changes. Base-image, disk, and immutable target-generation changes may require
a controlled `make destroy` and recreation.

## Security boundary

This is a local development lab, not a production deployment. It intentionally
uses a private development CA, synthetic long-lived user passwords, Keycloak's
development server, self-signed TLS for WinRM on the host-only network, and a
single PostgreSQL role without database TLS before the optional Dashboard setup below. It still preserves the product
boundaries under test: no database credentials reach clients or agents, agent
private keys are generated target-side, agent journals are host-local, Control
uses OIDC/TLS and agent mTLS, and bulk bytes remain in the shared artifact
store.


## Dashboard infrastructure

`make configure-dashboard-infra` extends an **already running** `pg01`,
`storage01`, and `control01`. It does not power on other VMs, run the full
converge, recreate containers, or reset any database. It generates new synthetic
Dashboard secrets and a PostgreSQL server certificate under ignored `.lab/`,
then applies `ansible/dashboard-infra.yml` through a dedicated inventory.

```sh
make configure-dashboard-infra
make check-dashboard-infra
```

The dedicated inventory obtains each VM's Ed25519 host public key through the
local Parallels guest channel, binds it to the Vagrant-managed VM UUID, and uses
strict SSH host verification. Subsequent unexpected VM or host-key changes fail
closed. Existing inventories and their host-key files are not overwritten. The
static CI check also preserves an existing host-key file.

PostgreSQL continues to use its existing persistent container volume. The
playbook enables TLS by reloading settings, preserving existing Control HBA
rules and connections. Its additive HBA block requires TLS and SCRAM for the
new roles, restricts each to its dedicated database and the isolated Lab
network/loopback, and denies access to other databases. This compatibility
choice leaves the original Control test role's plaintext connection working;
it is not a production PostgreSQL policy.

| Setting | Value |
| --- | --- |
| Database endpoint | `10.77.0.20:5432` (`pg01.lab.test`) |
| Dashboard database | `jobman_dashboard` |
| Migration identity | `jobman_dashboard_ddl` |
| Runtime identity | `jobman_dashboard` |
| TLS mode | `verify-full` |
| Trusted host CA | `.lab/certs/lab-ca.crt` (use its absolute path) |
| Private credential file | `.lab/credentials/dashboard.env` |
| Runtime password key | `JOBMAN_LAB_DASHBOARD_PASSWORD` |
| Migration password key | `JOBMAN_LAB_DASHBOARD_DDL_PASSWORD` |
| Synthetic Control fixture DB/owner | `jobman_dashboard_control` |
| Synthetic Control password key | `JOBMAN_LAB_DASHBOARD_CONTROL_PASSWORD` |

None of these identities is a superuser, database/role creator or replication role.
The fixture Control owner cannot connect to the original Control or Dashboard
database. Its private verify-full DSN is installed on `control01` at
`/etc/jobman-dashboard-lab/control-database-url` with mode `0600`.
Only the migration identity owns the database and public schema. Apply Dashboard
migrations as that identity, then rerun the PostgreSQL portion to grant runtime
DML on the current tables and sequence use:

```sh
./scripts/configure-dashboard-infra.sh --limit pg01
```

The runtime role has no schema CREATE or role-assumption privilege. It receives
only SELECT on the migration ledger. New tables get no automatic runtime grant:
rerun the grant step after every migration. Credentials are never printed; load
them through the ignored file, not command-line arguments or committed config.
The generated leaf certificate expires after one year; initialization refuses
an expired or incomplete pair rather than silently replacing trust or secrets.

The log-reader account `jobman-dashboard-log` uses UID/GID `21901` on storage
and Control. Named-user ACLs allow only traversal of `/srv/lab/data` and
`/srv/lab/data/jobman`, then read/traversal of canonical namespace/job/execution
prefixes within Alice's and Bob's stores. Read grants apply only to canonical
`logs/{stdout,stderr}/<sequence>.chunk` objects. Existing nonlog file grants to
this reader are removed; private directories retain a zero access mask.
Per-user directory defaults provide the exact named reader inheritance while
owning-group and other entries remain empty. Legacy paths with incompatible
preexisting ACLs are excluded, preserving their prior owner/group rights;
provisioning reports the exclusion count. Removing the reader preserves existing
ACL masks; adding outer traversal fails if it would activate a previously masked
execute grant for another identity. They require explicit operator
migration before the strict producer policy can use them. The reader receives
no write permission. The existing NFSv4.2 export retains `root_squash`. The remote reader
uses `/data/jobman/<user>`; a reader on storage uses `/srv/lab/data/jobman/<user>`.

**Producer integration is required for new private logs.** POSIX default ACLs
are masked when a producer creates files with mode `0600` or directories with
`0700`. The bounded check explicitly proves this denial. A store-specific,
validated reader-policy opt-in must create published log objects with the
appropriate ACL mask (`0640`/`0750`) while keeping owning-group/other access
empty. The infrastructure does not change global producer modes, run a
privileged ACL reconciler, or grant root/capability-based read bypasses. NFS
clients expose `system.nfs4_acl`; the probe saves its native ACL representation
for producer-policy validation.

`make check-dashboard-infra` verifies host certificate/SAN checking, TLS-only
role authentication, runtime DML without DDL, cross-database and role isolation,
existing Control connection compatibility, inherited reader access, denied
reader writes, denied Bob access to Alice's probe, and root-squash behavior.
It creates unpredictable temporary table/directory names and removes only
those probes, then saves non-secret ACL metadata in
`.lab/dashboard/acl-probe.json`. It never prints log bytes or passwords.
The check uses the existing PostgreSQL container's client for authenticated
role checks and OpenSSL from the Mac for certificate/hostname checks; Dashboard
integration tests separately establish the actual host pgx connection.

The scoped Keycloak helper adds only `jobman-dashboard-api`,
`jobman-dashboard-web` and `jobman-dashboard-native`, plus `dashboard-alice` and
`dashboard-bob` in the existing `jobman-lab` realm. It refuses to adopt
conflicting unmarked clients/users, and preserves the existing clients/users.
The web client is confidential; native is public. Both require authorization
code plus S256 PKCE and disable direct password, implicit and service-account
flows. Exact redirects are `https://dashboard.lab.test:8443/auth/callback` and
`jobman-dashboard-auth://callback`. Only access tokens receive the `jobman-dashboard-api` resource audience; ID
tokens retain their client audience. `azp` identifies the client. Claim `directory_guid` is emitted from a single,
admin-editable-only `dashboard_directory_guid` attribute; users cannot change
that identity through self-service. The helper preserves the other realm user
profile fields. This signed-claim configuration still requires actual
application authorization-code/PKCE and directory integration acceptance.

Public issuer/client/subject/GUID mappings are saved in
`.lab/dashboard/oidc-public.json` and on Control at
`/etc/jobman-dashboard-lab/oidc-public.json`. Synthetic secrets are appended only
when missing to `.lab/credentials/dashboard.env` as
`JOBMAN_LAB_DASHBOARD_WEB_SECRET`, `JOBMAN_LAB_DASHBOARD_ALICE_PASSWORD`, and
`JOBMAN_LAB_DASHBOARD_BOB_PASSWORD`. Existing passwords are not rotated on rerun.
The guest helper input is root-only `/etc/jobman-dashboard-lab/identity-input.json`.
No host DNS edits are made. The operator/application fixture should arrange
`dashboard.lab.test` resolution explicitly; current command checks can use
`--resolve` without changing host networking. Control fixture ports `18443`
and synthetic LDAPS `18636` are separate from existing Control `8080` and
Keycloak `8443`. No long-lived fixture service is installed by this playbook.

Offline regression tests run with `python3 scripts/test-dashboard-provisioning.py`
and are included in `scripts/ci-check.sh`. They exercise canonical log scope,
sequence bounds, exact callbacks and rejection of authentication-policy drift.
A real Linux ARM64 producer test on Control's NFS mount additionally verified
that its opt-in policy publishes readable logs while artifacts remain private;
broker write, Bob read and root-squashed read were denied. That synthetic probe
was removed afterward; these results do not install/enable a production policy.

For rollback, first stop Dashboard processes and preserve its database backup.
The original HBA is retained inside PGDATA as `pg_hba.conf.pre-dashboard`.
An operator can restore that file and reload PostgreSQL, and return the three
TLS settings to their prior configuration. Keep the dedicated database and
roles for recovery rather than dropping data; revoke login while inactive.
Remove only the named-reader ACL entries if decommissioning the reader; do not
replace ownership, broadly chmod the data tree, or remove pre-existing data.
Ansible and check results are synthetic Lab evidence, not corporate AD FS,
production NFS, APNs, or managed-device acceptance.

To repeat the real producer check, build Jobman's artifact test binary for
Linux ARM64 with its `integration` build tag, then run:

```sh
PYTHONDONTWRITEBYTECODE=1 ./scripts/check-dashboard-producer.py /absolute/path/artifact.test
```

The test runs as Alice, creates a unique disposable NFS subtree, verifies actual
content reads without printing bytes, cleans only its own files, and records
the tested binary SHA-256 in `.lab/dashboard/producer-check.json`.

## Isolated Dashboard runtime fixture

The optional runtime uses only the three already-running infrastructure VMs.
Prepare it after `configure-dashboard-infra` using an explicitly supplied exact
Linux ARM64 Control fixture build, then an exact Dashboard/broker/web build:

```sh
./scripts/configure-dashboard-source.sh /absolute/path/to/control-fixture-build
./scripts/configure-dashboard-runtime.sh /absolute/path/to/dashboard-build
./scripts/check-dashboard-runtime.py
```

Each build directory has `build.json` with its full source revision, platform,
toolchain and SHA-256 hashes for its executables. The scripts verify those hashes
before upload. The Dashboard directory also contains the compiled `web.tar.gz` and its digest.
The wrapper verifies that digest and stages its exact `web/` tree, rejecting
path traversal, links, special files, duplicate paths and excessive sizes. An
existing staged tree must match the archive byte-for-byte; it is not overwritten.
Control's directory contains the ordinary `jobman-control` binary and the
nonrelease `jobman-control-lab-helper`; both must come from the same exact
revision. The normal Control API and real directory reconciliation workers run
unchanged against the isolated `jobman_dashboard_control` database. The helper
creates a synthetic LDAPS service and admits synthetic data through real Store
methods; it does not execute Slurm/host jobs or prove corporate AD behavior.

| Process | Guest / endpoint | User |
| --- | --- | --- |
| Dashboard HTTPS | storage01, `https://dashboard.lab.test:8443` | `jobman-dashboard-app`, UID21903 |
| Storage broker | control01, `https://10.77.0.21:19443` | `jobman-dashboard-log`, UID21901 |
| Synthetic Control | control01, `https://10.77.0.21:18443` | `jobman-dashboard-source`, UID21902 |
| Synthetic directory | control01, `ldaps://127.0.0.1:18636` | `jobman-dashboard-source`, UID21902 |

Original Control8080 and Keycloak8443 on control01 are preserved. Only the
Dashboard guest receives the scoped `/etc/hosts` entry for its own hostname;
the Mac's DNS and trust stores are unchanged. Host checks should use an explicit
CA and a hostname-preserving `--resolve dashboard.lab.test:8443:10.77.0.10`.
Existing Lab guest trust already covers the Lab CA. Generated application and
broker leaf certificates last seven days and are not silently renewed; inspect
and replace the explicit synthetic credentials before expiry.

The private Control fixture root is `/etc/jobman-dashboard-lab/control-fixture`,
owned by its service user with mode0700. Preparation is immutable once complete;
repeating identical inputs is a no-op. A partial preparation needs inspection,
not a database reset or deletion of credentials. Public actual source,
namespace, target-generation and job/group IDs are fetched to
`.lab/dashboard/fixture-info.json`. Only the Dashboard's required Control client
key/certificate/signing key and public fixture CA are copied into private host
staging. The Control fixture CA **private** key never leaves its fixture root.

Synthetic log bytes first go to `/var/lib/jobman-dashboard-lab/seed-logs` on
control01. Alice receives only read/traverse access to that spool; a scoped
copier exclusively creates its two synthetic namespace trees in
`/data/jobman/alice` with modes0750/0640. It never uses root to write the
root-squashed NFS mount, never preserves a local source ACL over the NFS default,
and rejects changes to existing immutable output. No existing workload target
or job is launched or modified.

Application material is private under `/etc/jobman-dashboard-app-lab` on
storage01. Broker material is independently private under
`/etc/jobman-dashboard-broker-lab` on control01. Dashboard-to-broker mTLS and
Ed25519 credentials are distinct from either process's Control credentials.
All TLS roots are explicit. The broker's rollback/identity ledger remains on
local disk at `/var/lib/jobman-dashboard-broker-lab` with mode0700; do not remove
it to bypass source restore or rollback checks. Its only log mapping pins the
fixture's actual target generations, `lab-nfs` version1, and Alice's NFS root.

The runtime playbook applies Dashboard migrations using a temporary root-only
DDL credential, grants runtime DML on current tables (migration ledger remains
read-only), and removes the guest DDL credential before starting the app.
Service users are non-login, have no privileges/capabilities, and use systemd
read-only system protection; only broker local state is writable. A runtime
reapply restarts only the corresponding isolated services when their material
or binary changes. It never changes the original services.

To stop this fixture, stop only `jobman-dashboard-lab-app` on storage01 and
`jobman-dashboard-lab-broker`, `jobman-dashboard-lab-control`, and
`jobman-dashboard-lab-directory` on control01. Preserve private material, broker
ledger and both dedicated databases for inspection/recovery. Starting the
fixture does not constitute production, APNs, AD FS or managed-iPhone acceptance.
