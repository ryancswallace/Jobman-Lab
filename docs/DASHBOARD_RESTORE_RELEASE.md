# Isolated clone release and retirement

This supplemental helper changes only the three restored clone startup-hold flags.
It does not run event recovery, modify a persisted hold, reset a cursor, replace a
source registration, change an original service, or delete restored data. Use the
same immutable restore-driver files that created the operation; the original intent
still pins that implementation. A later corrected driver cannot silently adopt an
older operation.

Run `dashboard-restore-release.py digest` first. Keep the returned complete file
manifest, then use its `implementationSHA256` for every action. Common arguments
are the original invocation packet's `--lab-root`, candidate/path/hash, prepared and
operation directories, plan hash, guest hash and object-helper hash. Add a new
private `--release-directory` beneath an owner-only directory. Keep all these files
private; configuration contents and source cursors are not console output.

1. After both reviewed source recoveries have applied and the replayed harness
   passes, run `prepare` with `--scenario-directory` and the implementation hash.
   This performs bounded read-only PostgreSQL proof queries and clone/primary
   process/config checks. It writes only local private staged files. Review the
   returned release plan hash, unchanged two-source identities/scopes, active feeds,
   no unresolved gaps, persisted hold generation and original external cutoff.
2. Run `configure --release-sha256 ... --apply` only after exact-plan review. All
   original configuration bytes, ownership/modes, clone unit bytes/effective stop
   policies and current PID/UID/executable identities are pinned. Staged configs
   validate before stop. Only clone API/worker stop; exact CAS changes API
   `events.deliveryHold`, worker `deliveryHold` and recovery `events.deliveryHold`
   from true to false, preserving configuration revision and every other value.
   Original bytes remain in immutable root-only backups. Persisted hold stays held.
3. A durable start-intent precedes one clone start. If its reply is lost, retries
   only observe the exact resulting process and readiness; they never requeue start.
   Review bounded `/readyz` and `/metrics` evidence for both clone processes and the
   before/after source/database/primary preservation proof. Readiness retries only
   a starting process/socket or unavailable local dependency for at most25 seconds;
   identity, configuration and response-shape drift fail immediately.
4. Root separately invokes the product CLI `events resume` with the reviewed
   current generation and acknowledgment. The helper never invokes resume. Run
   `observe --hold-state released` and the resumed E3 harness. The generation must
   advance exactly once, while the original uncertainty cutoff remains the same
   instant; explicit timezone offsets are accepted and normalized for comparison.
5. Stop only the test-owned rules, then root separately establishes an ordinary
   clone hold with no new restore cutoff. Run `retire --apply` after review. It
   requires another exact generation advance, unchanged cutoff, disabled clone
   units, exact identities/configs, and preserved primary. It stops just the two
   clone units, verifies inactivity and closed38443 listener, and retains database,
   roles, objects, credentials and receipts for inspection. It never removes data.

Running source positions may advance; instance, epoch, configured scope and revision
must remain exact and positions must not regress. Only private cursor/checkpoint
hashes leave PostgreSQL. Failed/pending phases retain evidence; never delete intent
or guard files to retry. Configuration can resume through a verified partial CAS,
but an uncertain start only permits observation. Clone operations have a145-second
guest deadline,165-second transport ceiling,70-second stop and bounded command
outputs. There is no primary stop or restore command in this helper. Physical APNs
delivery and real corporate AD FS remain outside this synthetic restore exercise.
