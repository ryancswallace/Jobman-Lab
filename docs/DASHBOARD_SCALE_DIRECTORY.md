# Synthetic LDAP helper upgrade for scale acceptance

The existing isolated directory helpers accept only the original small fixture.
The reviewed Control helper `367006818e72315b01860f56f971004e17c24886` supports
32 users, groups and direct members, sufficient for the original two users plus
25 scale users and the additional namespace viewer groups. This driver changes
only each fixed LDAP unit's executable path and restarts that LDAP service once.
It does not install directory drafts, restart Control, change Dashboard scopes,
alter database rows, or change delivery holds. No live result is claimed here.

First stage the byte-verified helper through the separate scale-source driver:
`/usr/local/libexec/jobman-dashboard-scale/367006818e72315b01860f56f971004e17c24886/jobman-control-lab-helper`,
SHA256 `6f511e91434dac2499d464f0b424607fe0b099b966148c992499e5371a333f65`.
All executable ancestors are root-owned and traversable by the existing LDAP
service users. The old helpers and all original configuration files remain.

Archive the four implementation files reported by `--phase digest`, plus the
test and this runbook, before live work. For each profile, `primary` and
`secondary`, use a fresh private0700 staging directory and invoke the following
phases through that archive:

1. `--phase snapshot`: read-only capture of the exact old unit/process, verified
   LDAP TLS listener, both source configurations and unaffected Control services.
   Review the printed snapshot digest and the private snapshot before mutation.
2. `--phase stage --apply`: requires that exact snapshot digest, no older than
   15minutes, and the installed exact helper; retain old/new unit bytes.
3. `--phase swap --apply`: compare-and-swap only the known `ExecStart` executable,
   preserving service users, arguments, ports and all other unit bytes. Save an
   exclusive pending receipt and original unit before the atomic replacement.
4. `--phase restart --apply`: reload units, retain the restart intent, queue one
   restart of the selected fixed LDAP unit, and verify the new executable/UID/
   arguments/start identity plus verified loopback TLS within40seconds.
5. `--phase verify`: read-only recheck of the exact completed process and unchanged
   source/configuration hashes. A later unrelated restart is reported as drift.

All non-digest phases require `--implementation-sha256`, `--profile`, `--staging`
and `--lab-root`. All phases after snapshot also require `--snapshot-sha256`.
Only the three explicit mutating phases accept `--apply`; nothing auto-advances.

A pending restart is never queued again: a retry can only verify that the new
process became ready and then complete the receipt. An uncertain or failed
restart with the old process still present requires inspection. The driver does
not roll back the binary, reset a cursor, or erase receipts to obtain a pass.
Primary and secondary snapshots are separate; complete one service before
capturing the next. Do not overlap this work with restore, wiring, directory
revocation or other configuration acceptance freezes.

Run `python3 scripts/test-dashboard-scale-directory.py` for offline guards.
These tests and the TLS/process check do not establish expanded membership or
performance acceptance. After both upgrades, the separately reviewed source
seeding/configuration phases must install additive directory drafts through
normal Control reconciliation and prove viewer-only permissions before exposing
the new Dashboard scopes. Never reuse a source-seeding preflight that predates
either LDAP process change.
