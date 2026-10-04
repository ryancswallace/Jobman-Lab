# Private host receipts for dependency faults

The dependency-fault driver keeps its strict owner, mode, canonical-path and
single-link checks. New operation receipts can be explicitly bound to a private
host directory outside the Lab checkout. This avoids placing frequently written
intent/completion files where filesystem tools may temporarily hard-link them.
The third database attempt reported `host_file` before DROP admission; its exact
historical file/link state was not captured. This change does not assert that an
unobserved filesystem actor caused that attempt's failure.

Before preparing new faults, finish or explicitly retire every previous operation
and retain its original evidence. Create a new empty owner-only directory with
`mktemp -d /private/tmp/jobman-dashboard-fault-records-XXXXXXXX` on macOS (use the
canonical `/tmp` parent on Linux). Review the current driver, then invoke once:

```sh
python3 /ABSOLUTE/REVIEWED/scripts/dashboard-dependency-faults.py prepare-records \
  --lab-root /Users/rcw/home/code/jobman-lab \
  --records-root /private/tmp/jobman-dashboard-fault-records-REPLACE --apply
```

This is a host-only operation. It uses the existing exclusive Lab fault lock;
no guest, firewall, process, source, database or service configuration is changed.
It validates the original completed/aborted history, binds its hashes plus the
new directory's device/inode identity, and leaves that history untouched. A
persistent owner-only binding under `.lab/dashboard` selects the new registry.
Future invocations cannot choose a different per-operation registry.

An intentionally unfinished `records-relocated` directory fences the old registry
before the new binding is published. Frozen older drivers therefore refuse a new
fault instead of bypassing the shared history. Updated watchdog preflight reads
the bound registry too. An interrupted setup, altered binding, replaced or
missing directory, changed original evidence, symlink, hard link, or unexpected
permissions fails closed. There is no automatic retry, relocation or cleanup.
Never create a completion marker for the relocation guard or remove it to make
an older driver pass. Preserve this private directory across restarts; temporary
storage removal requires a separately reviewed recovery, not a fresh empty bind.

The bound registry only changes the location of new host operation receipts.
Fault staging still needs a fresh reviewed plan, and all original guest locks,
fixed targets, deadlines, watchdogs, no-replay rules and recovery proofs remain.
The original database attempts and frozen implementation archives remain failed
or aborted evidence. A future complete REJECT/DROP test must pass on its own.

Offline checks execute real filesystem operations for legacy compatibility,
interrupted setup, original-history preservation, old/new admission fencing,
replacement/symlink/hard-link refusal, strict binding types and watchdog use:

```sh
python3 scripts/test-dashboard-dependency-faults.py
python3 scripts/test-dashboard-watchdog.py
```
