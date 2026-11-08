# External deployment configuration

The standalone `scripts/jobman-config.py` tool composes organization-owned
configuration without starting Vagrant, contacting services, resolving secrets,
or applying changes. It is independent of the synthetic Lab lifecycle. Product
schemas, validators, safe defaults, reusable templates, and synthetic examples
remain public. Organization values, branding, notices, documentation, service
integrations, and release selections belong in a separate private root.

Secret values remain in a secret or certificate service; profiles use native
credential-file references. Sessions, enrollment state, jobs, user preferences,
recovery state, and reports are not Git configuration. Repository subdirectories
do not provide read isolation: use separate repositories when districts do not
share a confidentiality boundary.

## Installation and structural validation

Use Python 3.11 or later and the pinned dependencies:

```sh
python3 -m venv /absolute/path/config-tools
/absolute/path/config-tools/bin/python -m pip install -r config/requirements.txt
/absolute/path/config-tools/bin/python scripts/jobman-config.py schema
/absolute/path/config-tools/bin/python scripts/jobman-config.py validate \
  --root /private/config --profile north/environments/test.yaml
```

Without native validators, `validate` checks composition and bundle policy only.
Its JSON result explicitly reports `nativeValidated: false`. It does not prove
the application can start or certify an external service integration.

## Profiles and composition

[`deployment.schema.json`](../config/deployment.schema.json) is the structural
contract. `apiVersion` is `jobman.config/v1alpha1`. `kind: Deployment` requires
explicit organization, environment, deployment, components, and version pins.
`kind: Preset` supplies reusable defaults and cannot carry deployment metadata,
bindings, assets, or protected identity/trust fields.

```yaml
apiVersion: jobman.config/v1alpha1
kind: Deployment
metadata:
  organization: north
  environment: test
  deployment: north-test
bindings:
  organization-name: North Example Organization
components:
  client:
    kind: jobman
    config:
      schema_version: 1
      presentation:
        organization: {$binding: organization-name}
        display_name: North Jobman
versions:
  jobman:
    version: replace-with-tested-release
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
```

The example digest deliberately cannot validate a real executable. Replace it
with the exact reviewed validator/deployment binary's SHA-256 digest. Release
strings record intent; executable bytes are checked. The resolver does not fetch
or install binaries. Environments are lab, dev, test, stage, or prod.

`imports` is an ordered list of `{path, sha256}` references to local presets.
Paths resolve against their declaring document and stay inside the selected root.
Imports apply in order, then the current document. Maps merge; arrays/scalars
replace. Empty collections clear a branch; omission preserves it. There is no
automatic authorization-scope union, remote import, or environment override.
Component kinds cannot change across layers. Trust, deployment identity, and
native callback registrations must be explicitly selected by the entry profile;
they cannot be inherited from a district's reusable preset.

An exact `{$binding: name}` object selects one entry-document value for reuse in
native configuration. No interpolation, code evaluation, or secret resolution is
performed. Missing/cyclic bindings fail. Bindings cannot arrive from an imported
preset. Expansion has depth, node-count, and byte limits. Native validators
check resolved types and cross-field semantics.

Duplicate keys, aliases, anchors, explicit YAML tags, multiple documents, nulls,
nonfinite numbers, symlink references, and excessive size/depth are rejected.
Only JSON-style boolean/number scalars are implicit; quote strings such as `null`.
Known inline credential fields, private-key material, and credential-bearing URLs
are rejected. This is defense in depth, not a general secret-detection guarantee;
configuration authors must keep secret values out of all documents and assets.

`explain --root ROOT --profile FILE` shows leaf origins and binding references
without values. `diff --root ROOT --profile FILE --against OTHER` shows changed
JSON-pointer paths without values. Paths and resource labels may themselves be
private. These outputs are intended for private operator review.

## Native validators and rendered bundles

Each component is `{kind, config}`; `config` is its existing native document.
Native validators remain authoritative. Every executable is explicitly supplied
by absolute path and checked against its version pin. Use reviewed, immutable
executables in directories writable only by the release administrator: the tool
checks executable bytes but does not sandbox validators or lock their paths
against concurrent replacement.

| Kind | Output | Offline validator |
| --- | --- | --- |
| `jobman` | YAML | `jobman config validate --isolated FILE` |
| `jobman-agent` | YAML | `jobman-agent config validate FILE` |
| `jobman-diagnose` | YAML | `jobman-diagnose config validate FILE` |
| `jobman-control` | JSON | `jobman-control --config FILE --check-config` |
| `control-directory` | JSON | `jobman-control config validate --kind directory FILE` |
| `control-delegation` | JSON | Same with `--kind delegation` |
| `control-resources` | JSON | Same with `--kind resources` |
| `dashboard-api` | JSON | `jobman-dashboard --mode validate-config --check-mode api --config FILE` |
| `dashboard-worker` | JSON | Same with `--check-mode worker` |
| `dashboard-operator` | JSON | Same with `--check-mode operator` |
| `dashboard-broker` | JSON | `jobman-log-broker --mode validate-config --config FILE` |

```sh
python scripts/jobman-config.py render --root /private/config --profile north/test.yaml \
  --validator jobman=/opt/reviewed/bin/jobman --output /private/releases/north-test-001
```

Rendering requires native validation for every component. `validate` accepts the
same validator arguments for a check without publication. Validators receive a
clean environment without inherited credentials or user configuration. Their
output is suppressed to avoid accidental disclosure; timeouts/nonzero exits fail.
Run the component validator privately for detailed repair information.

Output must be a new directory outside configuration roots and Git worktrees.
Files use mode 0600, directories 0700. After private staging/validation, the tool
exclusively claims the destination and publishes `manifest.json` last as the
completion marker. An incomplete directory must not be installed. The manifest
records source, output, schema, renderer, and runtime-library digests/versions.
`origins.json` records leaf provenance and binding references and is included in
the manifest's file hashes. An organization's release pipeline must
authenticate the reviewed manifest; the tool does not automatically sign it.

## Assets and third-party configuration

`files` entries select `{source, destination, sha256, visibility}`. Sources must
be bounded regular files inside the root. Destinations are confined to `assets/`,
`docs/`, `notices/`, or `integrations/`. Duplicate paths, traversal, and symlinks
fail. Visibility is a publication classification, not a publication action; all
rendered files start private.

Use these entries for approved logos, login notices/MOTD, private documentation,
native build profiles, systemd drop-ins, PostgreSQL/IdP/Slurm/NFS/SMB configuration,
and other consumer-native inputs. Exact reviewed bytes are copied; executable
templates are not evaluated. Third-party files require their own syntax and
integration checks before installation. Bundle structural validation does not
validate arbitrary third-party file content. Existing service units and roles
are reference adapters, not a universal production installer.

Native app identifiers/icons, callback schemes, APNs environments/topics, and
signing inputs are build-time configuration. Use Dashboard's native profile
staging tool and coordinate server and IdP registrations; runtime presentation
does not replace a signed native rebuild.

## Synthetic Lab adapter

`scripts/lab-config.py` is the common loader for Vagrant, inventory generation,
build/artifact scripts, and generated Ansible variables. It defaults to `config/`.
Set `JOBMAN_LAB_CONFIG_ROOT` to an external directory containing `topology.yml`
and `versions.yml`; optionally set `JOBMAN_CONFIG_PYTHON` to the interpreter with
the pinned dependencies. Relative product/ISO paths resolve against that root.

The Windows ISO path has no personal default. Default product paths select
sibling checkouts. VM resources, supported software pins, source paths, time
source, Slurm time limit, and MOTD can be selected externally. The managed
`/etc/motd` is cleared when the configured message is empty. Version pins are
read from one source rather than repeated in shell scripts and Ansible variables.
This adapter fixes Parallels/ARM64, AlmaLinux 9, distribution MariaDB, and the
Packer/plugin versions required by its HCL. Changing those requires a reviewed
platform adapter update; conflicting overrides fail. Other version selections
require bounded numeric release pins, images/archives require SHA-256, and
source downloads require credential-free HTTPS with HTTPS-only redirects.
Lab values containing Jinja delimiters are rejected before inventory generation,
so external paths and notices cannot invoke Ansible's template or lookup engine.

Recorded synthetic DNS/network, users, storage, service identities, and host roles
remain pinned to the reference fixture. External configuration cannot repurpose
destructive Lab operations against other environments. Those identities are
acceptance safeguards, not organization defaults. Production uses native bundles
and an approved platform adapter, never synthetic `converge`/`destroy` workflows.
Historical acceptance records and their identity assertions are preserved.

## Migration, policy, and rollback

1. Inventory effective configuration privately. Separate desired policy from
   secrets and runtime records; retain a reviewed rollback artifact.
2. Pin binaries and renderer, then compose the existing effective values. Test
   two independent synthetic organizations before adding organization values.
3. Review diffs; install secret references separately with role-specific access.
   Follow each consumer's path contract: Agent, Diagnose transport, and Dashboard
   file references require absolute paths; Control resolves its relative file
   references against its configuration file. The composer does not rewrite
   references to copied assets or installation destinations.
4. Install separate API/worker/broker/operator files and restart affected services.
   Keep source IDs, target generations, and configuration revisions stable unless
   their native identity/recovery protocol requires a reviewed transition.
5. Apply database migrations separately. Production Control must explicitly set
   `migrateOnStart: false`; production development-authentication profiles fail.
6. Use Control resource plan/apply for supported administrative API resources.
   Do not bypass the API to create namespaces or reset emergency revocation,
   recovery holds, checkpoints, or user preferences.
7. Change operational settings in a separate release. Native bounds preserve
   replay retention, certificate/freshness constraints, and authorization floors.

Schema version, bundle release/digest, and component identity/configuration
revision are separate. A cosmetic change does not trigger source recovery.
Reverting configuration is not a database rollback; follow component restore
runbooks. Core user defaults remain overridable and cannot enforce organization
security policy. Optional AI and notification integrations remain opt-in.

## Checks

`make config-test CONFIG_PYTHON=/path/to/python` tests composition, bindings,
provenance, invalid YAML, pinning, path/symlink guards, district separation, secret
canaries, native validator execution, private publication, and synthetic external
version/resource selection. CI includes these offline checks. Public examples
use unrelated synthetic organizations and require no private repository.

For a cross-repository check after building the reviewed binaries, run
`python scripts/test-config-integration.py --bin-dir /absolute/build/bin`. It
renders all application and administrative configuration kinds using native
offline validators. It reads only checked-in synthetic examples, never a running
deployment or credential store. `--source-root` selects the directory containing
the sibling product checkouts when they are not adjacent to this repository.
