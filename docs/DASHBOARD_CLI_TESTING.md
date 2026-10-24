# Submit CLI jobs and watch them in Dashboard

The Dashboard Lab monitors its dedicated Control deployments. Ordinary
`jobman run` creates a standalone job in local SQLite; the original Lab
`research` profile also points to a different Control deployment. For this
walkthrough, use **shared mode**, the primary Dashboard deployment, and the
`dashboard-operations` namespace.

## Start the Lab and select the test identity

From the Mac:

```sh
cd /Users/rcw/home/code/jobman-lab
make LAB_GROUP=full ensure-running
make iphone-check
```

The configured iPhone gateway may prompt for your Mac administrator password.
For web testing, open <https://dashboard.lab.test:8443>. The iPhone app uses the
same server address and its existing Wi-Fi DNS and certificate-trust settings.
Sign in as the synthetic **dashboard-alice** account, then select **Synthetic Dashboard Lab** and **dashboard-operations**. The organization-wide view also
includes these jobs. There is no need to change accounts on your Mac.

Define this convenience function in Terminal:

```sh
jobman_lab() {
  python3 /Users/rcw/home/code/jobman-lab/scripts/dashboard-cli.py \
    --lab-root /Users/rcw/home/code/jobman-lab "$@"
}

jobman_lab target list
```

The helper runs the installed `jobman shared` CLI. It signs in using the Lab's
existing synthetic Alice credentials and the same authorization-code/PKCE
flow as the native app. It obtains a fresh access token on each invocation;
no password grant, refresh-token storage, or authentication-policy change is
needed. It writes a private profile, token, and operation journal only under
`.lab/dashboard/cli/`, and disables extensions and project configuration.
Jobman's ordinary system/user configuration is still read and validated; it
is not modified. The Mac must already have the Jobman CLI installed.

Use `dashboard-execution-host` for Linux subprocess jobs and
`dashboard-execution-slurm` for actual Slurm jobs. Other target names are
retained fixtures and may have no real executor.

## Watch a job run and produce logs

Open the Dashboard **Jobs** page, then submit a job with enough running time to
observe it:

```sh
jobman_lab run --name demo-progress \
  --target dashboard-execution-host --timeout 30s \
  -- /bin/sh -c 'i=1; while [ "$i" -le 10 ]; do printf "Step %s of 10\n" "$i"; sleep 2; i=$((i+1)); done'
```

Submission returns a shared job ID. The work runs as Alice on the Lab's
`control01` guest; paths and commands are interpreted there, not on the Mac.
Jobman normally executes an argument vector directly. These examples request
`/bin/sh` explicitly to demonstrate shell loops and redirection.

Refresh the Jobs list if needed, open **demo-progress**, and inspect its
command, execution details, status, and logs. It should progress from accepted
through running to success. Fast jobs can finish before a refresh observes
their running state.

Copy the returned ID into the following commands:

```sh
jobman_lab list
jobman_lab status JOB_ID
jobman_lab show JOB_ID
jobman_lab wait --timeout 90s JOB_ID
jobman_lab logs --json JOB_ID
```

The Mac does not mount the Lab's NFS stores. `logs --json` displays the authorized
log manifest; read actual stdout/stderr in the Dashboard app, whose broker can
access the files. The helper rejects CLI byte-log commands without a local
store mapping. Nothing needs to be mounted on the iPhone.

## Compare success and failure

```sh
jobman_lab run --name demo-success \
  --target dashboard-execution-host --timeout 30s \
  -- /bin/sh -c 'printf "Started\n"; sleep 3; printf "Finished successfully\n"'

jobman_lab run --name demo-failure \
  --target dashboard-execution-host --timeout 30s \
  -- /bin/sh -c 'printf "Demonstration failure\n" >&2; exit 7'
```

The second job intentionally fails. Check its exit code and stderr in the job
details. `jobman_lab wait JOB_ID` returns a nonzero exit status for this job;
that is the expected result. You can also request a diagnosis from the
Dashboard job page.

## Submit to the real Slurm cluster

```sh
jobman_lab run --name demo-slurm \
  --target dashboard-execution-slurm --partition cpu \
  --cpu 1 --memory 128MiB --nodes 1 --tasks 1 \
  --wall-time 1m --timeout 30s \
  -- /bin/sh -c 'hostname; printf "Running on Slurm\n"; sleep 3'
```

Inspect the scheduler job ID, partition, state, execution host, and logs in the
Dashboard. Use the bounded resource settings above for this small Lab.
Native arrays use `jobman_lab collection submit FILE`; multiple independent
`run` calls create separate jobs, not an array. Dependency graphs use
`jobman_lab graph submit FILE`. Both commands accept Jobman's documented
versioned JSON request formats.

## Troubleshooting and data reset

- An empty list usually means the wrong deployment/namespace or an active
  filter. Use `Synthetic Dashboard Lab` / `dashboard-operations`, or the aggregate view.
- A job remaining accepted needs a healthy execution agent. On `control01`,
  the host service is `jobman-dashboard-execution-host`; on `submit01`, the
  Slurm service is `jobman-dashboard-execution-slurm`. Both are enabled for
  startup. Agent credentials are short-lived; a long shutdown can require
  fresh enrollment through Control. Do not extend certificate validity or
  delete an enrollment directory to hide an expiry failure.
- The helper refreshes the token for each command. For an unusually long
  `wait`, run `jobman_lab login` in another Terminal to refresh the shared
  token, or run a new status/wait command. Jobman rereads that file per request.
- Restart the full Lab with `make LAB_GROUP=full restart`. Existing iPhone DNS
  and CA trust remain as described in [iPhone testing](IPHONE_TESTING.md).

The initial manual-testing reset cleared jobs, executions, collections, arrays,
graphs, report records, and notification inbox history from the two monitored
synthetic Control databases and Dashboard. It preserved accounts, namespaces,
permissions, targets, configuration, alert rules, source identities, event
cursors, and audit/deduplication records. Existing log/report objects and prior
acceptance receipts were retained as evidence, outside the active job lists.
The original Lab Control database and the Mac's standalone Jobman database
were not reset.

Full pre-reset custom-format PostgreSQL backups were verified on `pg01` under
`/var/backups/jobman-dashboard/manual-testing-20261024/`, with private files and
before/after count receipts. Restore is an explicit operator operation across
the corresponding services and databases; do not import a backup into a
running source or reset event cursors independently. The CLI helper never
deletes jobs or performs a database reset.

Validation on 2026-10-24 used the installed Jobman 1.9.0 CLI: a successful
host job, a deliberate exit-7 failure, and a real Slurm job all appeared in
Dashboard with complete source coverage and verified stdout/stderr bytes.
The verification jobs were removed afterward, leaving the active job lists
empty for manual testing. Both real execution agents were re-enrolled through
Control with unchanged target generations and enabled for startup; their old
state directories remain archived beside the current directories.
