"""Local administration and gateway service."""
import argparse
import json
import os
import ssl
import subprocess
import time

import telegram_bot
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import web
from cryptography.fernet import Fernet

from app import Gateway
from db import Store, TTL


def origin_value(value):
    url = urlsplit(value)
    if (
        url.scheme != 'https' or not url.hostname or url.username or url.password
        or url.path not in ('', '/') or url.query or url.fragment
        or (url.port is not None and not 1 <= url.port <= 65535)
    ):
        raise ValueError('Provide one HTTPS origin, for example https://remote.example.org.')
    host = url.hostname
    if ':' in host:
        host = f'[{host}]'
    return 'https://' + host + (f':{url.port}' if url.port not in (None, 443) else '')


def init(state, args):
    origin = origin_value(args.origin)
    if not 1 <= args.port <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    if args.local_tls and (urlsplit(origin).hostname != 'localhost' or (urlsplit(origin).port or 443) != args.port):
        raise ValueError('Local TLS requires https://localhost at the configured port.')
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.stat().st_mode & 0o077:
        raise ValueError('State directory must be private (chmod 700).')
    if (state / 'config.json').exists():
        raise ValueError('Already initialized. Edit config.json to change settings.')
    key = state / 'fernet-key'
    if not key.exists():
        with key.open('xb') as file:
            file.write(Fernet.generate_key())
    if args.local_tls:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-days', '365', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
            '-keyout', str(state / 'localhost.key'), '-out', str(state / 'localhost.crt'),
        ], check=True, stdout=subprocess.DEVNULL)
    config = dict(origin=origin, port=args.port, local_tls=args.local_tls, allow_reverse=False)
    with (state / 'config.json').open('x') as file:
        json.dump(config, file, indent=2)
        file.write('\n')
    print(f'Initialized {state}\nBrowser URL: {origin}\nStart with: ./murashka serve')


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--state', type=Path, default=Path(os.getenv('MURASHKA_STATE', '~/.local/state/murashka-remote-ssh')))
    commands = cli.add_subparsers(dest='command', required=True)
    configure = commands.add_parser('init', help='Generate local secrets and deployment settings')
    configure.add_argument('--origin', default='https://localhost:8765')
    configure.add_argument('--port', type=int, default=8765)
    configure.add_argument('--local-tls', action='store_true', help='Generate a certificate for localhost evaluation')
    commands.add_parser('serve', help='Run the browser gateway on IPv4 loopback')
    commands.add_parser('telegram-setup', help='Configure a dedicated Telegram bot and private operator')
    commands.add_parser('telegram', help='Start the optional Telegram long-polling process')
    commands.add_parser('hosts', help='List registered SSH hosts')
    commands.add_parser('grants', help='List current workspace IDs (no credentials)')
    grant = commands.add_parser('grant', help='Create a time-limited browser link and password')
    grant.add_argument('--minutes', type=int, choices=[n // 60 for n in TTL], default=30)
    grant.add_argument('--guest-host', type=int, help='Limit the workspace to one saved host')
    revoke = commands.add_parser('revoke', help='Revoke a workspace by ID')
    revoke.add_argument('id')
    return cli


def main():
    os.umask(0o077)
    cli = parser()
    args = cli.parse_args()
    state = args.state.expanduser().resolve()
    try:
        if args.command == 'init':
            return init(state, args)
        if state.stat().st_mode & 0o077:
            raise ValueError('State directory must be private (chmod 700).')
        config = json.loads((state / 'config.json').read_text())
        origin = origin_value(config['origin'])
        if args.command == 'telegram-setup':
            return telegram_bot.setup(state)
        if args.command == 'telegram':
            try:
                return telegram_bot.run(state, origin)
            except KeyboardInterrupt:
                return
        if args.command == 'serve':
            context = None
            if config['local_tls']:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(state / 'localhost.crt', state / 'localhost.key')
            app = Gateway(state, origin, config.get('allow_reverse') is True).application()
            return web.run_app(app, host='127.0.0.1', port=int(config['port']), ssl_context=context, access_log=None)
        store = Store(state / 'gateway.sqlite', (state / 'fernet-key').read_bytes().strip())
        try:
            if args.command == 'grant':
                host = args.guest_host
                grant = store.grant(host if host is not None else 0, 'guest' if host is not None else 'owner', args.minutes * 60)
                print(f"URL: {origin}/#g={grant['id']}.{grant['token']}\nPassword: {grant['password']}\nGrant ID: {grant['id']}")
            elif args.command == 'revoke':
                store.revoke(args.id)
                print('Workspace revoked.')
            elif args.command == 'hosts':
                print(json.dumps([{k: host[k] for k in ('id', 'name', 'host', 'port', 'username')} for host in store.targets()], indent=2))
            elif args.command == 'grants':
                rows = store.db.execute(
                    'SELECT id,role,target,expires FROM grants WHERE revoked=0 AND expires>?', (time.time(),)
                )
                print(json.dumps([dict(row) for row in rows], indent=2))
        finally:
            store.db.close()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        cli.error(str(exc))


if __name__ == '__main__':
    main()
