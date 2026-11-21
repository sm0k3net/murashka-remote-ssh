"""Provision or manage only the project's dedicated loopback VNC service."""
import fcntl
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ACCOUNT = 'murashka-desktop-ssh'
HOME = '/var/lib/' + ACCOUNT
BASE = Path('/etc') / ACCOUNT
UNIT = Path('/etc/systemd/system') / (ACCOUNT + '.service')
PORT = 5901
PACKAGES = {
    'openbox': ['openbox', 'pcmanfm', 'tint2'],
    'xfce': ['xfce4', 'xfce4-terminal'],
}


def command(args, timeout=30, **kwargs):
    return subprocess.run(args, timeout=timeout, check=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kwargs)


def systemctl(*args):
    command(['systemctl', *args])


def active():
    return subprocess.run(['systemctl', 'is-active', '--quiet', ACCOUNT],
                          timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def managed():
    return (
        BASE.is_dir() and not BASE.is_symlink() and BASE.stat().st_uid == 0
        and BASE.stat().st_mode & 0o022 == 0 and (BASE / 'manifest.json').is_file()
        and UNIT.is_file() and not UNIT.is_symlink() and UNIT.stat().st_uid == 0
        and UNIT.read_text().startswith('# Managed by Murashka Remote SSH\n')
    )


def reserve_port():
    with socket.socket() as listener:
        try:
            listener.bind(('127.0.0.1', PORT))
        except OSError:
            raise ValueError('Port 5901 is already in use. The existing service was left alone.') from None


def wait_ready():
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', PORT), timeout=1) as connection:
                if connection.recv(12).startswith(b'RFB ') and active():
                    return
        except OSError:
            pass
        time.sleep(1)
    raise ValueError('VNC did not become ready. Check the systemd service logs on the host.')


def initialize_account():
    marker = Path('/etc') / (ACCOUNT + '.uid')
    try:
        user = pwd.getpwnam(ACCOUNT)
    except KeyError:
        if marker.exists() or Path(HOME).exists():
            raise ValueError('The desktop account or its home needs manual review.') from None
        command(['useradd', '--system', '--create-home', '--home-dir', HOME, '--shell', '/bin/bash', ACCOUNT])
        user = pwd.getpwnam(ACCOUNT)
        with marker.open('x') as output:
            output.write(str(user.pw_uid))
        marker.chmod(0o600)
    if (user.pw_uid == 0 or user.pw_dir != HOME or not marker.is_file() or marker.is_symlink()
            or marker.stat().st_uid != 0 or marker.read_text() != str(user.pw_uid)):
        raise ValueError('The existing desktop account is not managed by this installer.')
    return user


def write_new(path, value, mode):
    with path.open('xb') as output:
        output.write(value)
    path.chmod(mode)


def install(variant, password):
    if variant not in PACKAGES or not re.fullmatch(r'[A-Za-z0-9]{8}', password):
        raise ValueError('Invalid desktop profile.')
    if UNIT.exists() or UNIT.is_symlink() or BASE.exists() or BASE.is_symlink():
        raise ValueError('Desktop service or configuration already exists. Remove the managed desktop before reinstalling.')
    reserve_port()
    ram = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        field, _, value = line.partition(':')
        ram[field] = int(value.split()[0]) * 1024
    minimum = (768, 384, 1024) if variant == 'openbox' else (2048, 1024, 3072)
    available = (ram.get('MemTotal', 0), ram.get('MemAvailable', 0), shutil.disk_usage('/').free)
    if any(value < limit * 1024**2 for value, limit in zip(available, minimum)):
        raise ValueError('Insufficient host RAM or disk for the selected desktop profile.')
    packages = ['tigervnc-standalone-server', 'tigervnc-tools', 'dbus-x11', 'xauth', 'x11-xserver-utils',
                'xterm', 'xfonts-base', 'fonts-dejavu-core'] + PACKAGES[variant]
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    command(['apt-get', '-o', 'DPkg::Lock::Timeout=30', 'update'], timeout=120, env=env)
    command(['apt-get', '-o', 'DPkg::Lock::Timeout=30', '-o', 'Dpkg::Options::=--force-confold',
             '-y', '--no-install-recommends', 'install', *packages], timeout=720, env=env)
    initialize_account()
    reserve_port()
    server = shutil.which('tigervncserver')
    passwd = shutil.which('tigervncpasswd') or shutil.which('vncpasswd')
    if not server or not passwd:
        raise ValueError('TigerVNC packages did not provide the expected commands.')
    secret = subprocess.check_output([passwd, '-f'], input=(password + '\n').encode(), timeout=10)
    session = (
        "exec dbus-run-session -- sh -c 'pcmanfm --desktop & tint2 & xterm -geometry 100x28+30+30 & exec openbox-session'\n"
        if variant == 'openbox' else 'exec dbus-run-session -- startxfce4\n'
    )
    limits = ('384M', '512M') if variant == 'openbox' else ('768M', '1024M')
    unit = f"""# Managed by Murashka Remote SSH
[Unit]
Description=Murashka Remote SSH {variant} desktop
After=network.target
[Service]
Type=simple
User={ACCOUNT}
WorkingDirectory={HOME}
Environment=HOME={HOME}
Environment=SHELL=/bin/bash
LoadCredential=vnc-password:{BASE}/vnc-password
ExecStart={server} :1 -fg -localhost yes -geometry 1280x800 -depth 24 -SecurityTypes VncAuth -rfbauth %d/vnc-password -xstartup {BASE}/session
Restart=on-failure
RestartSec=5
KillMode=control-group
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
CPUQuota=100%
MemoryHigh={limits[0]}
MemoryMax={limits[1]}
[Install]
WantedBy=multi-user.target
"""
    BASE.mkdir(mode=0o755)
    try:
        write_new(BASE / 'vnc-password', secret, 0o600)
        write_new(BASE / 'session', ('#!/bin/sh\nunset SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS\n' + session).encode(), 0o755)
        write_new(BASE / 'manifest.json', json.dumps({'variant': variant}).encode(), 0o600)
        write_new(UNIT, unit.encode(), 0o644)
        systemctl('daemon-reload')
        systemctl('enable', '--now', ACCOUNT)
        wait_ready()
    except Exception:
        if managed():
            try:
                systemctl('disable', '--now', ACCOUNT)
            except subprocess.SubprocessError:
                # Leave the managed files in place if systemd could not stop it.
                raise ValueError('Desktop setup failed and the service could not be stopped. Review it on the host.') from None
            UNIT.unlink()
        for filename in ('vnc-password', 'session', 'manifest.json'):
            (BASE / filename).unlink(missing_ok=True)
        BASE.rmdir()
        systemctl('daemon-reload')
        raise
    return {'installed': True, 'active': True, 'variant': variant, 'port': PORT}


def main(body):
    action = body['action']
    if not Path('/run/systemd/system').is_dir() or not shutil.which('apt-get'):
        raise ValueError('Automatic desktop setup requires Debian or Ubuntu with systemd and APT.')
    if os.geteuid() != 0:
        raise ValueError('Desktop changes require root or passwordless sudo.')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') not in {'ubuntu', 'debian'}:
        raise ValueError('Desktop setup supports Debian and Ubuntu.')
    os.umask(0o022)
    lock = os.open('/run/lock/murashka-desktop-ssh.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, 'w') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'install':
            return install(body['variant'], body['password'])
        if not managed():
            raise ValueError('No managed Murashka Remote SSH desktop was found.')
        if action == 'restart':
            systemctl('restart', ACCOUNT)
            wait_ready()
            return {'installed': True, 'active': True}
        if action == 'remove':
            systemctl('disable', '--now', ACCOUNT)
            UNIT.unlink()
            systemctl('daemon-reload')
            for filename in ('vnc-password', 'session', 'manifest.json'):
                (BASE / filename).unlink()
            BASE.rmdir()
            return {'installed': False, 'active': False}
        raise ValueError('Unknown desktop operation.')


if __name__ == '__main__':
    try:
        print(json.dumps(main(json.load(sys.stdin))))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, ValueError) else 'Desktop operation failed. Check sudo access, package availability and systemd logs on the host.'
        print(json.dumps({'error': message}))
        sys.exit(1)
