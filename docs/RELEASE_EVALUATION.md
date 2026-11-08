# Reproducible release evaluation

The evaluation path consumes an explicitly reviewed JSON selection of published
Core/Agent, Control, Diagnose and Dashboard artifacts. It needs Python 3.11 or
later, the GitHub CLI, Docker and the exact Go toolchain in the selection. It
does not require Parallels, existing Lab guests, a private service or a provider.
The tooling and its documentation are covered by the repository [MIT license](../LICENSE).

## Fetch and verify

Use a clean checkout of the recorded Lab revision. Obtain the reviewed selection
through its owning configuration repository or release. The selection fixes
every repository, release commit, platform, archive, checksum manifest, SPDX
inventory and executable SHA-256; it also fixes the two official runtime images
by immutable digest. No `latest`, inferred platform or mutable sibling checkout
is accepted. Keep district configuration and approval records private.

```sh
make evaluation-test
python3 scripts/evaluation.py fetch --manifest /absolute/reviewed/selection.json \
  --output /absolute/new/verified-inputs
python3 scripts/evaluate-smoke.py --manifest /absolute/reviewed/selection.json \
  --inputs /absolute/new/verified-inputs --output /absolute/new/smoke-result.json
```

Fetching checks the immutable tag-to-commit relationship, selected release
channel, all pinned hashes and archive/SPDX checksum entries. GitHub attestations
must bind both the archive and SPDX inventory to the exact selected source and
release workflow on hosted runners. Extraction rejects traversal, duplicates,
links, special files and oversized inventories. Only the six named executable
roles can be selected. `verification.json` records the actual selection; a failed
or partial operation never produces a successful verification receipt. Outputs
must be new; inspection and a fresh operation replace destructive retries.

## Disposable smoke scope

The smoke command rechecks every executable digest and compiles the recorded
standard-library Go harness. It creates a uniquely named internal Docker network
and two disposable containers, exposes no host ports and mounts only public,
verified payloads read-only. Runtime processes are unprivileged with capabilities
dropped and private temporary state. Generated test credentials remain in tmpfs.
The command removes only its own containers/network on success or failure.

The real released Control, Agent and Core executables exercise synthetic TLS,
one-time enrollment, mTLS, a shared subprocess workload, agent restart while the
workload is running, preserved enrollment identity, immutable logs and a denied
namespace read. A failed standalone job exercises the released deterministic
Diagnose executable without a provider. Dashboard's explicit loopback fixture
mode exercises its monitoring API and denied scope. It is labeled fixture
evidence: it does not establish live Dashboard-to-Control, corporate identity,
physical iPhone/APNs, Slurm, cross-user NFS or expired-certificate acceptance.
The separate upstream PostgreSQL recovery suite and preserved real Lab evidence
retain their own source and scope.

The result binds the selection, Lab revision, harness source/build digests and
runtime images to each observed result. Failed results remain failed and are
retained for inspection; historical evidence is never rewritten or promoted.

## Source-build mode

Ordinary `make build-products` remains an explicitly mutable development build.
For a source evaluation, select clean checkouts at the two recorded commits and
use the separate mode:

```sh
JOBMAN_LAB_BUILD_MODE=evaluation \
JOBMAN_LAB_EVALUATION_MANIFEST=/absolute/reviewed/selection.json \
JOBMAN_LAB_EVALUATION_OUTPUT=/absolute/new/source-build \
make build-products
```

This rejects dirty or mismatched inputs, compiles isolated `git archive` snapshots
with pinned Go, disables workspaces and ambient Go configuration, and records
source and executable hashes. The original checkouts are rechecked afterward.
These are source evaluation builds; the fetch path establishes published-byte
identity. Source builds do not replace signed release artifacts.

## Security evidence and follow-up

Run Gitleaks v8.30.1 with full history, redaction and the repository's exact
reviewed fingerprint exceptions. Do not add path-wide or test-wide exclusions:

```sh
gitleaks git --redact=100 --log-opts=--all \
  --gitleaks-ignore-path .gitleaksignore .
```

The owning baseline retains scan scope, tool identity, reviewed false-positive
counts, vulnerability results and SPDX inventory identities. Scan output must
never publish matched credential values. Track remaining capabilities through
issues with an owner and observable acceptance criteria; deployment approval is
recorded separately. Sparse Slurm cancellation follow-up is tracked in
[issue 14](https://github.com/ryancswallace/Jobman-Lab/issues/14).
