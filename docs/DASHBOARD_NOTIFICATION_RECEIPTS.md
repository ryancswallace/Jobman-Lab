# Private host receipts for fresh notification acceptance

The two-source scenario wrapper accepts `--host-receipt-root` for a newly reviewed
host receipt store. Only public synthetic fixture/event receipts move; the Lab
SSH inventory, host keys, credential paths, guest roots, source identities and
normal SubmitJob/CancelJob behavior are unchanged.

The operator pre-creates an empty owner0700 canonical directory immediately under
`/private/tmp`, named `jobman-dashboard-notification-receipts-<unique>`. The
Dashboard harness reads `JOBMAN_DASHBOARD_LAB_NOTIFICATION_RECEIPTS`, validates
empty private state before sign-in, and passes the exact path to each wrapper
call. The wrapper checks current ownership and canonical0700 directory identity,
creates only its primary/secondary children, and retains0600 bounded receipts.
It still rejects symlinks, multiple hard links, wrong owners/modes, changing files
and conflicting immutable bytes. It never chmods or adopts an existing root.

This is a new-run path only. Explicit-root prepare refuses an existing receipt;
all six retained v1/v2/v3 receipt IDs are excluded for every action. No prior
receipt is copied from `.lab/dashboard/multisource-notifications`, no prior
scenario is reopened, and no uncertain cancellation is retried. Preserve the
original paths and all failed-attempt evidence. The legacy wrapper default remains
unchanged for compatibility; new Dashboard acceptance requires the explicit root.

A separate synthetic local probe reproduced the identified host boundary: a new
19-byte file in the Lab tree acquired a transient second hard link with unchanged
bytes/mtime/owner/mode and then failed the strict identity check. The parallel
`/private/tmp` file stayed single-linked. The actor creating the extra link is
unknown. Choosing a separately reviewed receipt directory keeps the single-link
safety check intact; it is not authorization to relax that check or repeat a
failed scenario.

The exact deployed test, mutation bounds, one-shot intent and six excluded IDs
are recorded in Dashboard's `docs/LAB_MULTISOURCE_NOTIFICATIONS.md` and each frozen
invocation manifest. No live invocation is performed by these offline tests:

```sh
python3 scripts/test-dashboard-multisource-notification-scenario.py
```

The tests cover real local receipt creation/repeat checks, strict hard-link and
metadata rejection, unavailable/aliased/incorrect roots, retained-ID exclusion,
and a synthetic host flow proving that the host-only path never enters guest
payloads or changes the fixed SSH inventory paths.
