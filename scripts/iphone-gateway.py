#!/usr/bin/env python3
"""Opt-in, phone-only macOS DNS/TLS gateway; launchd owns process lifetimes."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / '.lab/iphone-gateway.json'
LABEL = 'org.jobman.lab.iphone.' + hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
RUNTIME = Path('/var/run') / LABEL
SERVICES = ('dnsmasq', 'dnsdist', 'haproxy')
BINARIES = {'dnsmasq': 'sbin/dnsmasq', 'dnsdist': 'bin/dnsdist', 'haproxy': 'bin/haproxy'}


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], capture_output=True, text=True,
                          timeout=kwargs.pop('timeout', 30), **kwargs)


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def validate(config):
    require(set(config) == {'interface', 'mac_address', 'phone_address', 'upstream_dns'},
            'Invalid gateway configuration fields')
    require(isinstance(config['interface'], str) and re.fullmatch(r'en[0-9]+', config['interface']),
            'Expected a macOS enN network interface')
    for key in ('mac_address', 'phone_address'):
        addr = ipaddress.IPv4Address(config[key])
        require(any(addr in ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')),
                key + ' must be a private LAN IPv4 address')
        require(addr not in ipaddress.ip_network('10.77.0.0/24'), key + ' must not be a Lab VM address')
    require(config['mac_address'] != config['phone_address'], 'Phone and Mac addresses must differ')
    require(isinstance(config['upstream_dns'], list) and 1 <= len(config['upstream_dns']) <= 3,
            'Specify one to three existing upstream IPv4 DNS servers')
    for value in config['upstream_dns']:
        addr = ipaddress.IPv4Address(value)
        require(not (addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved),
                'Invalid upstream DNS address')
        require(value not in (config['mac_address'], config['phone_address']), 'DNS forwarding loop')
    return config


def configurations(c, runtime, user):
    """All substitutions are validated IPv4 addresses, enN, safe user, or fixed paths."""
    validate(c)
    require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', user), 'Unsupported macOS account name')
    mac, phone = c['mac_address'], c['phone_address']
    dns = '\n'.join([
        'port=1054', 'listen-address=127.0.0.1', 'bind-interfaces', 'no-hosts', 'no-resolv',
        *['server=' + ip for ip in c['upstream_dns']],
        'host-record=dashboard.lab.test,' + mac, 'host-record=oidc.lab.test,' + mac,
        'local=/lab.test/', 'cache-size=150', 'local-ttl=30', 'dns-forward-max=100',
        'edns-packet-max=1232', 'log-facility=-', 'pid-file=', ''])
    dnsdist = f"""setLocal('{mac}:53')
addLocal('127.0.0.1:1053')
setACL({{'{phone}/32', '127.0.0.1/32'}})
newServer({{address='127.0.0.1:1054', name='lab-dns', checkName='dashboard.lab.test.'}})
setMaxTCPClientThreads(2)
setMaxTCPQueuedConnections(32)
"""
    proxy = f"""global
    maxconn 128

defaults
    mode tcp
    timeout connect 5s
    timeout client 5m
    timeout server 5m

frontend iphone_lab_https
    bind {mac}:8443
    bind 127.0.0.1:18443
    acl phone src {phone}/32 127.0.0.1/32
    tcp-request connection reject unless phone
    tcp-request inspect-delay 5s
    acl tls_hello req.ssl_hello_type 1
    acl dashboard req.ssl_sni -i dashboard.lab.test
    acl identity req.ssl_sni -i oidc.lab.test
    tcp-request content reject if tls_hello !dashboard !identity
    tcp-request content accept if tls_hello
    use_backend dashboard_api if dashboard
    use_backend lab_identity if identity

backend dashboard_api
    server dashboard 10.77.0.10:8443

backend lab_identity
    server identity 10.77.0.21:8443
"""
    return {'dnsmasq.conf': dns, 'dnsdist.conf': dnsdist, 'haproxy.cfg': proxy}


def tools():
    paths = {}
    for service in SERVICES:
        candidates = [Path(prefix) / 'opt' / service / BINARIES[service]
                      for prefix in ('/opt/homebrew', '/usr/local')]
        path = next((p for p in candidates if p.is_file()), None)
        require(path is not None, 'Install gateway tools first: brew install dnsmasq dnsdist haproxy')
        paths[service] = str(path.resolve())
    return paths


def write(path, content, mode=0o600):
    require(not path.is_symlink(), 'Refusing symlink: ' + str(path))
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        temporary = Path(f.name)
        f.write(content if isinstance(content, bytes) else content.encode())
        f.flush()
        os.fsync(f.fileno())
    temporary.chmod(mode)
    temporary.replace(path)


def preflight(c):
    require(sys.platform == 'darwin', 'The iPhone gateway requires macOS')
    require(run(['/usr/sbin/ipconfig', 'getifaddr', c['interface']]).stdout.strip() == c['mac_address'],
            'Mac Wi-Fi address changed or interface is offline; reconfigure the gateway and iPhone DNS')
    mask = run(['/usr/sbin/ipconfig', 'getoption', c['interface'], 'subnet_mask']).stdout.strip()
    require(mask and ipaddress.IPv4Address(c['phone_address']) in
            ipaddress.ip_network(c['mac_address'] + '/' + mask, strict=False),
            'Phone must be on the Mac network; check its current Wi-Fi IPv4 address')
    require((ROOT / '.lab/certs/lab-ca.crt').is_file(), 'Initialize Lab certificates first')


def plists(paths, runtime, user):
    args = {
        'dnsmasq': [paths['dnsmasq'], '--keep-in-foreground', '--conf-file=' + str(runtime / 'dnsmasq.conf')],
        'dnsdist': [paths['dnsdist'], '--supervised', '--disable-syslog', '--uid', user,
                    '--gid', str(pwd.getpwnam(user).pw_gid), '-C', str(runtime / 'dnsdist.conf')],
        'haproxy': [paths['haproxy'], '-db', '-f', str(runtime / 'haproxy.cfg')],
    }
    result = {}
    for name in SERVICES:
        value = {'Label': LABEL + '.' + name, 'ProgramArguments': args[name], 'RunAtLoad': True,
                 'KeepAlive': True, 'ThrottleInterval': 5, 'ExitTimeOut': 10,
                 'StandardOutPath': str(runtime / (name + '.log')),
                 'StandardErrorPath': str(runtime / (name + '.log'))}
        if name != 'dnsdist':
            value['UserName'] = user
        result[name] = value
    return result


def loaded(name):
    return run(['/bin/launchctl', 'print', 'system/' + LABEL + '.' + name]).returncode == 0


def stop():
    failures = []
    for name in reversed(SERVICES):
        if loaded(name):
            r = run(['/bin/launchctl', 'bootout', 'system/' + LABEL + '.' + name])
            if r.returncode:
                failures.append(name)
    require(not failures, 'Could not stop gateway services: ' + ', '.join(failures))


def verify(c):
    for name in ('dashboard.lab.test', 'oidc.lab.test'):
        for transport in ([], ['+tcp']):
            r = run(['/usr/bin/dig', '@127.0.0.1', '-p', '1053', name, 'A', '+short',
                     '+time=2', '+tries=1', *transport])
            require(r.returncode == 0 and r.stdout.strip() == c['mac_address'], 'Gateway DNS failed: ' + name)
    ctx = ssl.create_default_context(cafile=str(ROOT / '.lab/certs/lab-ca.crt'))
    for name, path in [('dashboard.lab.test', '/auth/native/config'),
                       ('oidc.lab.test', '/realms/jobman-lab/.well-known/openid-configuration')]:
        with socket.create_connection(('127.0.0.1', 18443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=name) as tls:
                tls.sendall(f'GET {path} HTTP/1.1\r\nHost: {name}:8443\r\nConnection: close\r\n\r\n'.encode())
                response = tls.recv(4096)
                require(response.startswith(b'HTTP/1.1 200'), 'Lab service not ready: ' + name)
    # The Mac LAN address is deliberately not allowed; this catches broad/default ACLs.
    r = run(['/usr/bin/dig', '@' + c['mac_address'], 'dashboard.lab.test', '+short', '+time=1', '+tries=1'])
    require(r.returncode != 0, 'DNS allowlist unexpectedly permits another LAN address')
    print('Gateway DNS and verified HTTPS pass; phone-only DNS access enforced.')


def manage_start(c, user):
    require(os.geteuid() == 0, 'Internal start requires sudo')
    preflight(c)
    require(not RUNTIME.is_symlink(), 'Invalid runtime directory')
    RUNTIME.mkdir(mode=0o755, exist_ok=True)
    require(RUNTIME.stat().st_uid == 0, 'Runtime directory must be root-owned')
    RUNTIME.chmod(0o755)
    paths = tools()
    desired = json.dumps({'config': c, 'tools': paths, 'user': user,
                          'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, sort_keys=True)
    receipt = RUNTIME / 'configuration.json'
    if all(loaded(n) for n in SERVICES) and receipt.exists() and receipt.read_text() == desired:
        verify(c)
        print('iPhone gateway already running.')
        return
    stop()
    # Refuse to steal listeners belonging to the previous manual gateway or another service.
    for address, port, kind in [(c['mac_address'], 53, socket.SOCK_DGRAM),
                                (c['mac_address'], 53, socket.SOCK_STREAM),
                                (c['mac_address'], 8443, socket.SOCK_STREAM),
                                ('127.0.0.1', 1053, socket.SOCK_DGRAM),
                                ('127.0.0.1', 1053, socket.SOCK_STREAM),
                                ('127.0.0.1', 1054, socket.SOCK_DGRAM),
                                ('127.0.0.1', 1054, socket.SOCK_STREAM),
                                ('127.0.0.1', 18443, socket.SOCK_STREAM)]:
        with socket.socket(socket.AF_INET, kind) as listener:
            try:
                listener.bind((address, port))
            except OSError as e:
                raise RuntimeError(f'Port {address}:{port} is occupied; stop the previous gateway first') from e
    for name, text in configurations(c, RUNTIME, user).items():
        write(RUNTIME / name, text, 0o644)
    for args in ([paths['dnsmasq'], '--test', '--conf-file=' + str(RUNTIME / 'dnsmasq.conf')],
                 [paths['dnsdist'], '--check-config', '-C', RUNTIME / 'dnsdist.conf'],
                 [paths['haproxy'], '-c', '-f', RUNTIME / 'haproxy.cfg']):
        r = run(args)
        require(r.returncode == 0, 'Gateway configuration validation failed: ' + r.stderr[:500])
    try:
        for name, value in plists(paths, RUNTIME, user).items():
            path = RUNTIME / (name + '.plist')
            write(path, plistlib.dumps(value), 0o644)
            # A fresh start bounds retained operational logs; queries are never logged.
            write(RUNTIME / (name + '.log'), b'')
            r = run(['/bin/launchctl', 'bootstrap', 'system', path])
            require(r.returncode == 0, 'launchd startup failed: ' + name + ': ' + r.stderr[:300])
        for attempt in range(20):
            try:
                verify(c)
                break
            except (OSError, RuntimeError):
                if attempt == 19:
                    raise
                time.sleep(1)
        write(receipt, desired, 0o644)
    except BaseException:
        stop()
        raise
    print('iPhone gateway started in the background. Stop with make iphone-stop or make halt.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['configure', 'start', 'stop', 'status', 'check', '_start', '_stop'])
    parser.add_argument('--if-configured', action='store_true')
    parser.add_argument('--interface', default='en0')
    parser.add_argument('--mac-address')
    parser.add_argument('--phone-address')
    parser.add_argument('--upstream-dns', action='append')
    args = parser.parse_args()
    if args.command.startswith('_'):
        require(os.geteuid() == 0 and os.environ.get('SUDO_UID'), 'Internal operation requires sudo from a normal user')
        require(not RUNTIME.is_symlink(), 'Invalid runtime directory')
        RUNTIME.mkdir(mode=0o755, exist_ok=True)
        require(RUNTIME.stat().st_uid == 0, 'Runtime directory must be root-owned')
        RUNTIME.chmod(0o755)
        lock = RUNTIME / 'operation.lock'
        require(not lock.is_symlink(), 'Invalid operation lock')
        with lock.open('a') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError('Another gateway operation is in progress') from exc
            if args.command == '_stop':
                stop()
            else:
                c = validate(json.load(sys.stdin))
                user = pwd.getpwuid(int(os.environ['SUDO_UID'])).pw_name
                manage_start(c, user)
        return
    if args.command == 'configure':
        c = validate({'interface': args.interface, 'mac_address': args.mac_address,
                      'phone_address': args.phone_address, 'upstream_dns': args.upstream_dns})
        preflight(c)
        tools()
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        write(CONFIG, json.dumps(c, indent=2) + '\n')
        export = ROOT / '.lab/iphone'
        export.mkdir(mode=0o700, exist_ok=True)
        write(export / 'Jobman-Lab-CA.crt', (ROOT / '.lab/certs/lab-ca.crt').read_bytes(), 0o644)
        print('Configured phone-only access. Public CA: ' + str(export / 'Jobman-Lab-CA.crt'))
        return
    if args.command == 'stop':
        if not RUNTIME.exists():
            print('iPhone gateway is stopped.')
            return
        if not any(loaded(n) for n in SERVICES):
            print('iPhone gateway is stopped.')
            return
        operation = '_stop'
        payload = None
    else:
        if not CONFIG.exists() and args.if_configured:
            print('iPhone gateway is not configured; skipping.')
            return
        require(CONFIG.exists(), 'Configure iPhone access first; see docs/IPHONE_TESTING.md')
        c = validate(json.loads(CONFIG.read_text()))
        if args.command == 'status':
            print(json.dumps({'configured': True, 'mac_address': c['mac_address'],
                              'phone_address': c['phone_address'],
                              'services': {n: loaded(n) for n in SERVICES}}, indent=2))
            return
        preflight(c)
        if args.command == 'check':
            verify(c)
            return
        operation, payload = '_start', json.dumps(c)
    # Authenticate on the caller's terminal. Never capture or store an administrator password.
    require(sys.platform == 'darwin', 'The iPhone gateway requires macOS')
    auth = subprocess.run(['/usr/bin/sudo', '-v'], check=False)
    require(auth.returncode == 0, 'Administrator authorization required to manage DNS port 53')
    result = subprocess.run(['/usr/bin/sudo', '-n', sys.executable, str(Path(__file__).resolve()), operation],
                            input=payload, text=True, check=False)
    require(result.returncode == 0, 'Gateway operation failed; Lab VMs/state were not removed')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print('iPhone gateway: ' + str(exc), file=sys.stderr)
        sys.exit(1)
