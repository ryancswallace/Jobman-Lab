# Exact static assets in the isolated runtime role

`dashboard_app` installs the hash-verified `web.tar.gz`, rather than merging the
controller's expanded `web/` directory into an existing served tree. A removed
asset therefore disappears from `/usr/local/share/jobman-dashboard-lab/web`
when the build changes. The configured `webRoot`, binary paths and separate
candidate release directories remain unchanged.

The root-only installer checks the uploaded archive against `build.json`,
rejects traversal, links, special entries and conflicting paths, and bounds the
archive to 72 MiB, extracted files to 64 MiB total/8 MiB each, and entries to
4,096. It prepares a new sibling tree with root-owned 0755 directories and 0644
files, verifies the exact inventory, and syncs it before publication. An exact
existing tree is an unchanged operation. Existing aliases, unexpected ownership
or permissions fail closed; the installer does not repair them implicitly.

An empty first-install web root is populated before `check-config`, which
requires `index.html`; this bootstrap requires the fixed service to be inactive
or absent and never starts an uninitialized application. It refuses to replace
a nonempty tree. First installation renames the prepared tree into place if no
root exists, or exchanges the initially empty root. Replacement uses
Linux `renameat2(RENAME_EXCHANGE)` to exchange the two complete directories in
one syscall, without an interval with a missing or partially copied web root.
There is no non-atomic fallback when that capability is unavailable. Before replacement, the role finishes configuration validation, forward
migrations and unit installation, validates the archive without changing the
served tree, then stops only the isolated application. The installer independently
requires the fixed service to be inactive with MainPID zero before publication.
This closes Dashboard’s retained `os.OpenRoot` descriptor before any old files
are deleted. An `always` block starts the application again even if installation
fails, so it reopens either the complete old tree or the complete new one. The
displaced tree is removed with descriptor-based, symlink-resistant cleanup;
failed validation or exchange preserves the existing tree. A process crash
after exchange can leave an unserved `.web-staging-*` sibling; rerunning verifies
the current tree and does not infer ownership of or delete an earlier staging
directory. An unconditional final service-start task also covers a retry after
an interrupted cutover whose tree is already exact. An identical live deployment
does not enter the stop/install/start block. Existing binary/configuration
notifications retain their normal deferred restart behavior. The role removes
only its own private upload. This does not make the role's
separate binary/configuration/migration tasks one transaction.

`python3 scripts/test-dashboard-web-assets.py` exercises obsolete-file removal,
exact replay, failure preservation, archive bounds and path guards. On Linux it
uses the real rename-exchange syscall in disposable local directories, with no
service or guest calls. macOS uses its analogous directory-swap syscall for
filesystem coverage and separately verifies that the production Linux-only
entry point refuses unsupported platforms; this is not Linux execution
evidence. The ordinary Linux static CI job runs the Linux path.
