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
single PostgreSQL role without database TLS. It still preserves the product
boundaries under test: no database credentials reach clients or agents, agent
private keys are generated target-side, agent journals are host-local, Control
uses OIDC/TLS and agent mTLS, and bulk bytes remain in the shared artifact
store.
