# Isolated hard-NFS reader acceptance

This opt-in test is not yet live acceptance evidence. It exercises the production
`ProcessReader` and exact packaged `jobman-log-broker --isolated-chunk-read`
against the existing storage01 NFS export, as UID/GID 21901. It does not exercise
broker HTTP authorization or claim APNs/device acceptance.

The test creates one exclusive root under
`/var/lib/jobman-dashboard-nfs-stall/<operation UUID>` on control01 and one
unenabled `jobman-dashboard-nfs-<UUID>` keeper unit. It does not change existing
services, configurations, directory memberships, firewall rules, exports,
network bridges, sysctls, shared mounts, source data, or the stopped restore clone.
All original active process/configuration/source/schema/role/hold pins are
verified around the operation; ordinary feed positions/generations may advance.

## Evidence and implementation

Use a separately reviewed package containing the output-bound repair
`2e8f1b15c58889c52023d49d396fd600b31eecd2`. The candidate binary, release build
receipt, exact source revision, and new Go probe source are pinned independently.
The probe is built from that candidate's clean source plus the single reviewed
`internal/logs/lab_nfs_test.go` overlay. Preserve the archive, overlay checksum,
Go toolchain identity, compile command, and binary checksum. A later source tree
must not silently substitute a different production `ProcessReader`.

Two distinct, nonempty, immutable log chunks must come from already accepted
synthetic execution evidence. Inputs include each exact object key, byte length,
SHA-256 checksum, and accepted evidence receipt checksum. The first is the warm
baseline; the second is cold on the new `nosharecache` mount. Neither chunk is
created or modified. If a chunk no longer exists, stop and report that evidence
limitation; do not replace it silently.

The keeper opens one TCP connection to 10.77.0.10:2049 **before** creating its
private namespaces. It chooses the first available reserved source port in
900–915, without reuse flags, retaining the existing secure-port export policy.
It then unshares mount, network, and UTS namespaces, makes mount propagation
private, sets an operation-specific hostname, and enables only private loopback.
A bounded loopback relay forwards that preconnected socket. The private mount is
read-only, hard, NFSv4.1, `nconnect=1`, `nosharecache`, `actimeo=0`, with 256 KiB
read/write bounds and a 60s transport retry interval.

The relay recognizes a bounded RPC COMPOUND containing SEQUENCE, PUTFH, READ and
optional GETATTR, with AUTH_SYS UID/GID 21901 and offset zero. The structure follows
[RFC 5661 sections 18.22 and 18.46](https://www.rfc-editor.org/rfc/rfc5661.html).
It records only request identity/count and a filehandle hash, never log bytes.
Unknown compounds do not count as proof. Malformed framing releases all held
bytes and enters transparent forwarding with a failure status. A first real READ
for the second distinct file is held; client backpressure bounds retained bytes.
This proves a kernel NFS read reached the relay, rather than merely timing a sleep
or observing a cached page.

Before any hold, an independent systemd timer is armed for 40s, acknowledged within
10s, and its conservative before+45s deadline is checked by the keeper. The timer
survives SSH/probe exit and always requests forwarding recovery. The keeper also
honors the same deadline. Resume is irreversible, including a watchdog that wins
before the probe arms. The timer is never canceled by the harness.

The probe requires a live occupied slot to reject a second request, then the first
read to return `read_timeout` without bytes within 3.5s around its 2s deadline.
It explicitly resumes forwarding and requires actual reaping followed by exact
original checksums for both chunks. Linux may kill this NFS read promptly; the
receipt records whether a slot was still retained at the deadline. It does not
claim an unkillable kernel wait. The separate real `Cmd.Wait` inherited-pipe
regression proves that a pending wait retains capacity until completion.

## Offline preparation

Archive all five new implementation scripts plus their three fixed dependency
scripts together. The plan binds every hash; the driver always runs from this
frozen archive while `--lab-root` points to the actual canonical Lab checkout for
pinned SSH connection material. Credentials never enter argv, reports or output.
Run Python tests on the actual host Python 3.9 as well as the selected interpreter.

Build the Linux ARM64 probe from the reviewed clean candidate archive with:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -tags=integration -c -trimpath -buildvcs=false -o /private/tmp/nfs-probe ./internal/logs
```

Create a private input JSON with exactly `candidate`, `probe`, and `chunks`:

```json
{
  "candidate": {
    "revision": "<40 hexadecimal characters>",
    "binary": {"sha256": "<64 hexadecimal characters>", "bytes": 1},
    "buildReceiptSHA256": "<64 hexadecimal characters>",
    "outputFixAncestor": "2e8f1b15c58889c52023d49d396fd600b31eecd2"
  },
  "probe": {
    "revision": "<same candidate revision>",
    "binary": {"sha256": "<64 hexadecimal characters>", "bytes": 1},
    "sourceSHA256": "<reviewed lab_nfs_test.go checksum>"
  },
  "chunks": [
    {"objectKey":"jobman/<accepted first chunk>","byteLength":1,"checksum":"sha256:<digest>","acceptedEvidenceSHA256":"<receipt digest>"},
    {"objectKey":"jobman/<accepted second chunk>","byteLength":1,"checksum":"sha256:<digest>","acceptedEvidenceSHA256":"<receipt digest>"}
  ]
}
```

Replace illustrative sizes with actual sizes. Snapshot and prepare are separately
reviewed; snapshot performs bounded reads only:

```sh
python3 /private/tmp/frozen-driver/dashboard-nfs-stall.py snapshot --lab-root /Users/rcw/home/code/jobman-lab --runtime-revision <currently deployed Dashboard SHA> --output /private/tmp/private-operation/snapshot.json
python3 /private/tmp/frozen-driver/dashboard-nfs-stall.py prepare --lab-root /Users/rcw/home/code/jobman-lab --dashboard-root /Users/rcw/home/code/jobman-dashboard --snapshot /private/tmp/private-operation/snapshot.json --inputs /private/tmp/private-operation/inputs.json --broker /private/tmp/inspected/jobman-log-broker --probe /private/tmp/nfs-probe --probe-source /private/tmp/reviewed/lab_nfs_test.go --build-receipt /private/tmp/private-operation/build-receipt.json --staging /private/tmp/private-operation/prepared
```

Review concrete inputs/plan/checksums before any mutation. Existing runtime and
source identities must stay fixed for the bounded acceptance window. No automatic
fault-suite, notification, or candidate upgrade runs concurrently.

## Explicit phases and recovery

Each later invocation specifies the same `--lab-root`, `--staging`,
`--expected-plan-sha256`, and `--expected-implementation-sha256`. Mutation commands
also require `--apply`. `stage` additionally requires exact `--broker` and `--probe`
paths. Execute phases individually: `stage`, `start`, `arm`, `probe`. After `arm`,
start `probe` promptly; it requires at least 20 seconds of watchdog budget. Root
runs only one invocation at a time. `state` polls bounded status; it never starts
a new probe. `preserved` rechecks all original runtimes and database authority.

All start/arm/probe intents are durable before effects. A lost reply stops the
sequence. `observe` reports or adopts only proven completed state; it never
restarts a keeper, creates another timer, or launches another probe. Never rerun
an uncertain phase or issue fresh operation IDs to hide a failed attempt.

On any failure, `resume --apply` requests immediate irreversible forwarding;
the already armed timer remains in place. Once the timer's durable recovery proof
exists and all direct/adopted descendants have been reaped, `close --apply` uses
an ordinary unmount inside the private namespace and records a truthful passed
or failed outcome. The keeper is a subreaper and remains alive when an orphaned
helper has not exited. No forced/lazy unmount, cgroup kill, export change, or
shared-service restart is an allowed shortcut. A pending unmount may only be
observed later; the driver does not issue it again. If the keeper itself fails or
an NFS transport cannot recover, retain the exact unit/namespace/process evidence
for an independently reviewed recovery instead of claiming bounded cleanup.

No namespace is eligible for another operation until its `closed.json` exists.
Artifacts, failed outputs, timer/unit receipts, originals, and exact checksum
proofs remain in place. Closing does not delete evidence or modify the original
chunks.
