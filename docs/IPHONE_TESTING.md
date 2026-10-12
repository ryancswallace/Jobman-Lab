# Test Dashboard on a personal iPhone

The optional iPhone gateway makes the existing Dashboard and test sign-in service
available on the Mac's Wi-Fi address. VMs retain their host-only network; there
is no LAN bridge, internet port forwarding, or change to the OIDC issuer.
Only the configured phone IPv4 address and loopback checks are allowed.
The feature is disabled until this Mac has `.lab/iphone-gateway.json`.

## One-time Mac setup

Install the gateway tools (tested with dnsmasq 2.93, dnsdist 2.1.2 and HAProxy
3.4.6); this does not start Homebrew services:

```sh
brew install dnsmasq dnsdist haproxy
```

First provision the Dashboard using the existing runtime runbooks. Its native
OAuth client must be configured and both HTTPS endpoints must be healthy.
Run `make bootstrap` for a fresh Lab. Existing Labs can run
`python3 scripts/ensure-oidc-tls.py` followed by `make converge` to migrate a
legacy OIDC certificate lacking explicit server authentication usage.

Find the Mac's current Wi-Fi address with `ipconfig getifaddr en0` and the
phone's address under Settings → Wi-Fi → ⓘ → IPv4 Address. Find the existing
IPv4 DNS servers with `scutil --dns`. Configure using your actual values:

```sh
python3 scripts/iphone-gateway.py configure \
  --interface en0 \
  --mac-address 192.168.20.2 \
  --phone-address 192.168.20.3 \
  --upstream-dns 192.168.20.1
make iphone-start
```

The addresses above are examples. Configuration is ignored by Git; no personal
addresses, credentials, certificates, or signing identities are committed.
The command exports the **public** CA to `.lab/iphone/Jobman-Lab-CA.crt`.
It does not copy or export a CA/private signing key.

If replacing the earlier manual gateway, stop its Terminal command with Ctrl-C
first. The integrated gateway refuses to take ports from unrelated processes.
Allow incoming connections for dnsdist and HAProxy if macOS asks.

## Automatic lifecycle

After configuration:

- `make up`, `make up-full`, `make up-core`, and `make converge` configure the
  guests first, then start/check the gateway. A failed gateway check does not
  prevent guest convergence from repairing services or certificates.
- `make ensure-running` starts/resumes the existing VMs, then starts/checks the
  gateway. It does not provision a new Dashboard installation.
- `make halt` / `make down` stop the gateway before halting VMs.
- `make restart` runs shutdown followed by startup sequentially, including the
  configured gateway. Use `make LAB_GROUP=full restart` for every Lab VM.
- Confirmed `make destroy` and `make clean-generated` stop the gateway before
  removing their corresponding state. Canceling confirmation leaves it running.
- `make iphone-start`, `make iphone-stop`, `make iphone-status`, and
  `make iphone-check` operate just this feature. `make status` also reports it.

Start/stop may prompt for your Mac administrator password: DNS port 53 and
system launchd job management require it. No password is saved and no sudoers
exception is installed. Services run in the background; no Terminal window must
stay open. All request-serving processes run as your ordinary macOS account;
dnsdist binds port 53 first and then drops privileges.

Jobs are bootstrapped into launchd for the current Mac boot, with root-owned
runtime configuration under `/var/run/org.jobman.lab.iphone.<repository-id>`.
There is no permanent login/boot service. After reboot, start the Lab normally.
Use the same repository checkout for startup and shutdown, since job labels are
scoped to its absolute path. Raw `vagrant up` bypasses Make's gateway integration.

Keep the Mac awake and on that Wi-Fi while testing. DHCP reservations for the
Mac and phone are recommended. If either address changes, rerun `configure`
and `make iphone-start`, and update the phone's DNS if needed. A changed Mac
address or off-subnet phone makes startup fail closed. No subnet-wide fallback
is enabled. Wi-Fi guest/client isolation must permit phone-to-Mac connections.

## One-time iPhone setup

1. Install a development-signed Dashboard build from Xcode. A free Personal Team
   requires a Debug build without the Push Notifications entitlement. Its
   provisioning expires after seven days, requiring a rebuild/reinstall.
   See the Dashboard repository's `ios/README.md` for native build instructions.
2. On this Wi-Fi network, set Configure DNS → Manual to **only the configured
   Mac IPv4 address**. Record the previous setting for restoration. Additional
   resolvers can produce inconsistent answers for the private Lab names.
3. AirDrop `.lab/iphone/Jobman-Lab-CA.crt` to the phone and install its downloaded
   profile under Settings → General → VPN & Device Management.
4. **Also enable full trust** for Jobman Lab Development CA under
   Settings → General → About → Certificate Trust Settings. Installing the
   profile alone does not enable TLS trust. This is separate from trusting your
   developer-app signing identity. See [Apple's certificate instructions](https://support.apple.com/en-us/102390).
5. Open `https://dashboard.lab.test:8443` in Safari and verify that sign-in at
   `https://oidc.lab.test:8443` also works without certificate warnings.
6. Enter `https://dashboard.lab.test:8443` in the native app and sign in with
   `dashboard-alice` or `dashboard-bob`. Their synthetic passwords remain in
   `.lab/credentials/dashboard.env`. Allow Local Network access if prompted.

The browser and native client preserve the existing hostnames, port, TLS chain,
native client ID, issuer, and PKCE callback. No app-side certificate exception
is used. Monitoring, logs, and reports use the live synthetic Lab. A free
Personal Team build cannot test remote APNs notifications.

**When the gateway is stopped or the Mac is asleep/offline, restore Configure
DNS to Automatic (or the previous configuration).** Otherwise this Wi-Fi
connection cannot resolve ordinary internet names either.

## Diagnostics and boundaries

`make iphone-check` tests local DNS over UDP/TCP, verified TLS to both services,
service readiness, and rejection of DNS from the Mac's non-allowlisted Wi-Fi
address. These host checks do not prove physical-device access or CA trust;
complete the Safari and native sign-in checks on the phone.

If the phone cannot resolve names, check its current IPv4 address, saved DNS,
Mac firewall approvals, and router client isolation. Private Relay/custom DNS
profiles can change resolver selection; temporarily disabling Limit IP Address
Tracking for this Wi-Fi network is a diagnostic option, not a required global
privacy change. If DNS responses reach the phone and HTTPS starts but fails,
check the **full-trust switch** before changing certificates or network settings.

Gateway logs contain service operational messages, not DNS query logging or
HTTP contents. TLS passes unchanged through HAProxy. There is no general TCP
proxy, management console listener, or access to the remaining Lab services.
Root-owned runtime configuration files are regenerated from validated configuration
at start. Private operational logs belong to the service account so launchd can
open them after applying its user identity.
The launcher cleans up jobs on startup failure and serializes management actions;
launchd restarts a gateway process if it exits unexpectedly. Shutdown waits for
the recorded gateway processes to exit before returning, so an immediate restart
cannot race their port release. A 15-second timeout reports a failure rather than
claiming shutdown completed; only launchd manages termination of its own jobs.
The startup port check permits normal closed TCP connections in TIME_WAIT while
continuing to reject active TCP listeners and occupied UDP sockets.

OIDC certificate creation/renewal uses the existing key and CA, explicit
serverAuth/key usage/SANs, and a 365-day lifetime. Replaced public leaves are
backed up. A missing private key or expiring CA fails rather than replacing
identity or trust. Ansible already restarts Keycloak when its certificate changes.
New Dashboard runtime leaves also use 365 days. Existing valid leaves and CAs
are not rotated by gateway startup.

The host health check supports older Lab CAs that lack a key-usage extension.
For these roots only, it disables Python 3.13's additional `VERIFY_X509_STRICT`
checks; CA trust, signatures, hostname matching, and certificate expiry are still
verified. This is limited to the host probe and does not change app TLS policy,
server certificates, or the CA trusted by the phone. New Lab CAs include key
usage and retain Python's default strict validation.
