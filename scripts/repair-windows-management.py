#!/usr/bin/env python3
"""Inspect or repair password expiry for this checkout's Windows Lab account."""
import argparse
import base64
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent


def windows_vm(root, listing):
    identity = str(uuid.UUID((root / '.vagrant/machines/winws01/parallels/id').read_text().strip()))
    matches = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            candidate = str(uuid.UUID(fields[0].strip('{}')))
        except ValueError:
            continue
        if candidate == identity:
            matches.append(fields[1:])
    if matches != [['jobman-lab-winws01', 'running']]:
        raise RuntimeError('Expected the Vagrant-owned jobman-lab-winws01 VM to be running; refusing repair')
    return identity


def powershell(apply):
    return '''$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$before = Get-LocalUser -Name "vagrant"
if (-not $before.Enabled) { throw "Vagrant account is disabled; refusing unrelated repair" }
''' + ('Set-LocalUser -Name "vagrant" -PasswordNeverExpires $true\n' if apply else '') + '''$after = Get-LocalUser -Name "vagrant"
if ($before.PasswordLastSet -ne $after.PasswordLastSet) { throw "Password unexpectedly changed" }
[pscustomobject]@{
    Account = $after.Name
    Enabled = $after.Enabled
    PasswordNeverExpires = ($null -eq $after.PasswordExpires)
    PasswordUnchanged = ($before.PasswordLastSet -eq $after.PasswordLastSet)
} | ConvertTo-Json -Compress
''' + ('if ($null -ne $after.PasswordExpires) { throw "Vagrant password still expires" }\n' if apply else '')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Make only the synthetic vagrant account password non-expiring')
    args = parser.parse_args()
    listing = subprocess.run(['prlctl', 'list', '--all', '--output', 'uuid,name,status'],
                             capture_output=True, text=True, timeout=30, check=True)
    vm = windows_vm(ROOT, listing.stdout)
    encoded = base64.b64encode(powershell(args.apply).encode('utf-16-le')).decode()
    result = subprocess.run(['prlctl', 'exec', vm, 'powershell.exe', '-NoLogo', '-NoProfile',
                             '-NonInteractive', '-EncodedCommand', encoded],
                            capture_output=True, text=True, timeout=60, check=True)
    print(result.stdout.strip())


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('Windows Lab management: ' + str(exc), file=sys.stderr)
        sys.exit(1)
