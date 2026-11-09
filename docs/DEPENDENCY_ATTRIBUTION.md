# Dependency attribution evidence

The [release evaluation](RELEASE_EVALUATION.md#dependency-and-notice-attribution)
collects source and notice evidence for a fixed release selection. The appendix
preserves the original authenticated SPDX documents and each dependency's own
terms. Institutional distribution approval is a separate decision.

## Reviewed historical selection

The November 2026 review uses Linux ARM64 Core 1.10.1 (Core and Agent), Control
0.3.1, Diagnose 0.7.0-rc.3 and Dashboard 0.1.0 (Dashboard and log broker). The
[public evidence selection](evidence/attribution-linux-arm64-selection.json)
records their source commits, executable hashes and original release asset
hashes. Pass it to `scripts/evaluation.py fetch` to reproduce the inputs.
The [audit summary](evidence/attribution-linux-arm64-summary.json) records the
contributing web packages, wheel identities and SHA-256 of each report file.

The inventory records the six executable hashes, embedded Go module identities,
source notice hashes, Dashboard's complete npm lock inventory and the seven
composer Python pins. The run found 30 Go module versions and 153 npm lock
entries plus the root. It matched both rebuilt JavaScript files to the
historical archive and identified React, React DOM, React Router, Scheduler,
and injected Vite and Rolldown code. The wheel selection used CPython 3.11 on
macOS ARM64 for the platform wheels. A source file selected by the compiler
is distinct from an entire module, a test corpus, artwork and a separately
distributed notice.
Likewise, an npm package installed for a build is not necessarily included in a
browser asset. Source maps must reproduce the published JavaScript before they
can establish that relationship.

The historical Dashboard build predates the rendered graph observer. To
repeat that part of the audit, export `web/third-party.mjs` from Dashboard
commit `d4126f1b9ab49b1e468775859ffaac00d8fff66f` into the disposable web
directory. Copy the historical `vite.config.ts` to
`vite.attribution.config.ts`, import `thirdPartyInventory` from
`./third-party.mjs` and add `thirdPartyInventory()` to the plugin list. Run
`npm run build -- --sourcemap hidden --config vite.attribution.config.ts`.
The audit accepts the rebuilt assets only when their JavaScript bytes match
the authenticated archive. The observer's output describes the rebuild and
the appendix preserves the original archive separately.

## SPDX ambiguities

The following file digests equal the suffixes of the original `LicenseRef`
identifiers. The machine-readable inventory retains their exact identities and
records whether the files were selected as build inputs or shipped as notices.
The observations below describe the source of each existing expression.

| Module and file | Observation |
| --- | --- |
| `modernc.org/libc@v1.79.0/LICENSE-3RD-PARTY.md` | Composite notices distinguish the generated library and other source/test components. Retain the complete text. |
| `modernc.org/memory@v1.12.1/LICENSE-LOGO` | Refers to repository artwork. Check the selected build inputs and payload separately from the module license. |
| `modernc.org/sqlite@v1.61.0/LICENSE-3RD-PARTY.md` | Describes runtime, test, module-graph and source/artwork components separately. |
| `modernc.org/sqlite@v1.61.0/LICENSE-SQLITE` | Contains SQLite's public-domain dedication; preserve that upstream text. |
| `github.com/coreos/go-oidc/v3@v3.21.0/NOTICE` | Upstream attribution notice, retained alongside its license. |
| `github.com/jackc/pgx/v5@v5.12.0/pgproto3/notice_response.go` | Ordinary PostgreSQL protocol implementation whose filename matches a scanner notice heuristic. Its source identity is evidence, but its contents are not a license notice. |

The original libc SPDX expression includes `GPL-2.0-only`. The source tree has
a GPL test-corpus `COPYING` file and generated source comments that require
separate treatment. In the reviewed libc source, 275 Linux SPDX markers across
41 Go files retain `GPL-2.0 WITH Linux-syscall-note`. Generated stdio comments
also preserve GCC Runtime Library Exception text. The inventory records exact
source hashes and selected-file status rather than attributing the whole
detection to a test corpus or dropping exceptions. The [Linux licensing rules](https://www.kernel.org/doc/html/latest/process/license-rules.html)
and [SPDX exception text](https://spdx.org/licenses/Linux-syscall-note.html)
describe that exception. [SQLite's copyright statement](https://www.sqlite.org/copyright.html)
describes its upstream dedication.

`NOASSERTION` remains a scanner observation. Linked modules are mapped to exact
upstream notice files. Standard-library entries map to the selected Go
toolchain's notices. Main-project and aggregate-archive entries map to the
authenticated archive and project notice files. Aggregate entries describe
the archive as a whole.

## Distribution and remaining decisions

The historical Dashboard archive predates the browser dependency appendix.
The Control archive predates the nested `go-jose/json` notice. The current
Dashboard and Control packaging changes carry selected notices into their
archives, packages and containers. Dashboard also ships an inventory that
binds both Go services and the rendered browser graph to source and lock hashes.
Current Core and Diagnose already carry the root notices selected for their
executables. The report retains the observations for the exact historical
artifacts in the selection.

The repository maintainer, `@ryancswallace`, owns technical attribution,
generator maintenance and remediation of missing package notices. An adopting
organization must assign its own accountable reviewer for distribution policy
and interpretation of source-specific terms. Those institutional decisions are
unresolved until recorded by that organization. Python wheel evidence covers
the explicitly downloaded platform distributions. Another platform requires
a new wheel selection and report.
