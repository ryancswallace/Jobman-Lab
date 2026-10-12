#!/usr/bin/env python3
"""Create/renew the Lab OIDC leaf for Apple TLS clients, preserving its key and CA."""
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def run(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Certificate operation failed: ' + str(args[1]))
    return result.stdout


def ensure(directory):
    ca, cakey = directory / 'lab-ca.crt', directory / 'lab-ca.key'
    key, cert = directory / 'control01.lab.test.key', directory / 'control01.lab.test.crt'
    if not ca.is_file() or not cakey.is_file():
        raise RuntimeError('Initialize the Lab CA first')
    if cert.exists() and not key.exists():
        raise RuntimeError('OIDC private key missing; refusing to replace the existing identity')
    if key.exists() and cert.exists():
        if run(['openssl', 'pkey', '-in', key, '-pubout']) != run(['openssl', 'x509', '-in', cert, '-pubkey', '-noout']):
            raise RuntimeError('OIDC certificate/key mismatch')
        try:
            run(['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', 'oidc.lab.test', '-CAfile', ca, cert])
            run(['openssl', 'x509', '-in', cert, '-checkend', '86400', '-noout'])
            if b'TLS Web Server Authentication' in run(['openssl', 'x509', '-in', cert, '-noout', '-ext', 'extendedKeyUsage']):
                return False
        except RuntimeError:
            pass
    # Never silently rotate a root to satisfy renewal.
    run(['openssl', 'x509', '-in', ca, '-checkend', str(366 * 86400), '-noout'])
    with tempfile.TemporaryDirectory(prefix='oidc-tls-', dir=directory) as temporary:
        staging = Path(temporary)
        if not key.exists():
            run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', staging / 'server.key'])
            os.chmod(staging / 'server.key', 0o600)
            (staging / 'server.key').replace(key)
        csr, new, ext = staging / 'server.csr', staging / 'server.crt', staging / 'extensions.cnf'
        ext.write_text('subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:control01.lab.test,DNS:oidc.lab.test,IP:10.77.0.21\n')
        if cert.exists():
            run(['openssl', 'x509', '-x509toreq', '-in', cert, '-signkey', key, '-out', csr])
        else:
            run(['openssl', 'req', '-new', '-key', key, '-subj', '/CN=control01.lab.test', '-out', csr])
        run(['openssl', 'x509', '-req', '-sha256', '-days', '365', '-in', csr, '-CA', ca,
             '-CAkey', cakey, '-set_serial', '0x' + secrets.token_hex(16), '-extfile', ext, '-out', new])
        run(['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', 'oidc.lab.test', '-CAfile', ca, new])
        if run(['openssl', 'pkey', '-in', key, '-pubout']) != run(['openssl', 'x509', '-in', new, '-pubkey', '-noout']):
            raise RuntimeError('New OIDC certificate public key mismatch')
        if cert.exists():
            backup = directory / ('control01.lab.test.crt.before-' + str(time.time_ns()))
            with backup.open('xb') as output:
                output.write(cert.read_bytes())
        new.chmod(0o644)
        new.replace(cert)
    return True


if __name__ == '__main__':
    os.umask(0o077)
    try:
        changed = ensure(ROOT / '.lab/certs')
        print('OIDC TLS certificate ' + ('renewed (365 days, serverAuth).' if changed else 'already valid for Apple clients.'))
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
