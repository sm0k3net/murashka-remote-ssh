"""Local, scoped workspace broker for Murashka Helper Tool."""
import asyncio
import hmac
import json
import os
import re
import secrets
import socket
import stat
import time

from db import Store

LIMIT = 8192


class Broker:
    def __init__(self, store, origin, token, allowed):
        self.store = store
        self.origin = origin
        self.token = token
        self.allowed = frozenset(allowed)
        self.store.db.execute(
            'CREATE TABLE IF NOT EXISTS helper_grants (id TEXT PRIMARY KEY, host INTEGER, expires REAL)'
        )

    def dispatch(self, body):
        token = body.get('token')
        if not isinstance(token, str) or not hmac.compare_digest(self.token, token):
            raise ValueError('Invalid broker credentials.')
        operation = body.get('op')
        if operation == 'hosts':
            return [{'id': host['id'], 'name': host['name']}
                    for host in self.store.targets() if host['id'] in self.allowed]
        if operation == 'revoke':
            ident = body.get('id')
            if not isinstance(ident, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16}', ident):
                raise ValueError('Invalid workspace ID.')
            row = self.store.db.execute('SELECT host FROM helper_grants WHERE id=?', (ident,)).fetchone()
            if not row or row['host'] not in self.allowed:
                raise ValueError('Unknown broker-issued workspace.')
            self.store.revoke(ident)
            return {'revoked': True}
        host = body.get('host')
        if type(host) is not int or host not in self.allowed:
            raise ValueError('Host is outside this broker’s allowlist.')
        target = self.store.target(host)
        if operation == 'status':
            row = self.store.db.execute('SELECT value,checked FROM metrics WHERE target=?', (host,)).fetchone()
            metrics = json.loads(row['value']) if row else {}
            percentages = {key: metrics[key] for key in ('cpu', 'ram', 'disk')
                           if type(metrics.get(key)) in (int, float) and 0 <= metrics[key] <= 100}
            return {'id': host, 'name': target['name'], 'metrics': percentages, 'checked': row['checked'] if row else None}
        if operation == 'grant':
            with self.store.db:
                self.store.db.execute('DELETE FROM helper_grants WHERE expires<=?', (time.time(),))
            active = self.store.db.execute(
                'SELECT COUNT(*) FROM helper_grants h JOIN grants g ON g.id=h.id WHERE g.revoked=0'
            ).fetchone()[0]
            if active >= 10:
                raise ValueError('Ten broker-issued workspaces are active. Revoke one or wait for expiry.')
            grant = self.store.grant(host, 'guest', 1800)
            with self.store.db:
                self.store.db.execute('INSERT INTO helper_grants VALUES (?,?,?)', (grant['id'], host, grant['expires']))
            return {'url': self.origin + '/#g=' + grant['id'] + '.' + grant['token'],
                    'password': grant['password'], 'id': grant['id'], 'expires': grant['expires']}
        raise ValueError('Unknown broker operation.')

    async def connection(self, reader, writer):
        try:
            try:
                async with asyncio.timeout(4):
                    raw = await reader.readline()
                    if not raw or len(raw) > LIMIT:
                        return
                    result = {'ok': True, 'result': self.dispatch(json.loads(raw))}
            except ValueError as error:
                result = {'ok': False, 'error': str(error)[:200]}
            except (TimeoutError, OSError):
                return
            except Exception:
                result = {'ok': False, 'error': 'Broker operation failed.'}
            writer.write((json.dumps(result) + '\n').encode())
            await asyncio.wait_for(writer.drain(), 4)
        except (TimeoutError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


def initialize(state):
    path = state / 'helper-token'
    if path.is_symlink() or path.exists():
        raise ValueError('A helper token already exists. Keep it private.')
    with path.open('x') as secret:
        secret.write(secrets.token_urlsafe(48) + '\n')
    print('Helper token written to ' + str(path) + '. Copy it only to the private Helper state if using another account.')


async def serve(state, origin, path, allowed):
    if not allowed or any(host <= 0 for host in allowed):
        raise ValueError('Explicitly allow at least one positive host ID.')
    secret = state / 'helper-token'
    if not secret.is_file() or secret.is_symlink() or secret.stat().st_mode & 0o077:
        raise ValueError('Run helper-init first; its token file must remain private.')
    token = secret.read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{60,90}', token):
        raise ValueError('Invalid broker token file.')
    if path.is_symlink():
        raise ValueError('Refusing a symbolic-link socket.')
    if path.exists():
        if not stat.S_ISSOCK(path.stat().st_mode) or path.stat().st_uid != os.getuid():
            raise ValueError('Socket path is occupied by another file.')
        # Do not unlink an active listener.
        with socket.socket(socket.AF_UNIX) as probe:
            probe.settimeout(1)
            try:
                probe.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            else:
                raise ValueError('A broker is already listening on this socket.')
    store = Store(state / 'gateway.sqlite', (state / 'fernet-key').read_bytes().strip())
    try:
        for host in allowed:
            store.target(host)
        broker = Broker(store, origin, token, allowed)
        server = await asyncio.start_unix_server(broker.connection, path=path, limit=LIMIT)
        identity = path.stat().st_ino
        path.chmod(0o660)
        try:
            async with server:
                print('Helper broker ready at ' + str(path), flush=True)
                await server.serve_forever()
        finally:
            if path.exists() and not path.is_symlink() and path.stat().st_ino == identity:
                path.unlink()
    finally:
        store.db.close()
