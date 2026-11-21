"""Single-operator browser SSH gateway."""
import asyncio
import collections
import contextlib
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import shlex
import time
from pathlib import Path

import aiohttp
import asyncssh
from aiohttp import web

from copies import FileJobs
from db import Store, digest, password_hash
from files import Workspace
from forwards import Forwards

COOKIE = '__Host-murashka-remote'
ROOT = Path(__file__).resolve().parent
LOG = logging.getLogger(__name__)

class Gateway(Workspace, FileJobs, Forwards):

    def csrf(self, token):
        return hmac.new(self.key, token.encode(), hashlib.sha256).hexdigest()

    def auth(self, request, owner=False, post=False):
        token = request.cookies.get(COOKIE, '')
        grant = self.store.session(token)
        if not grant:
            raise web.HTTPUnauthorized(text='Session expired. Create a new workspace link with the local CLI.')
        if owner and grant['role'] != 'owner':
            raise web.HTTPForbidden(text='Owner workspace required')
        if post and (not self.origin_ok(request) or not hmac.compare_digest(request.headers.get('X-CSRF', ''), self.csrf(token))):
            raise web.HTTPForbidden(text='Request verification failed')
        return grant

    def scoped_target(self, grant, ident):
        if grant['role'] != 'owner' and int(ident) != grant['target']:
            raise web.HTTPForbidden()
        if grant['role'] == 'monitor':
            raise web.HTTPForbidden(text='Dashboard access has no shell/file permissions')
        return self.store.target(ident, True)

    async def json(self, request):
        try:
            return await request.json()
        except Exception:
            raise web.HTTPBadRequest(text='Invalid JSON') from None

    async def index(self, request):
        return web.FileResponse(ROOT / 'static/index.html')

    async def login(self, request):
        if not self.origin_ok(request):
            raise web.HTTPForbidden()
        body = await self.json(request)
        ident = str(body.get('id', ''))[:100]
        token = str(body.get('token', ''))[:100]
        password = str(body.get('password', ''))[:200]
        client = request.remote or '?'
        now = time.monotonic()
        for k, limit in [(client, 6), ('*', 30)]:
            items = self.failures[k]
            items[:] = [t for t in items if now - t < 60]
            if len(items) >= limit:
                raise web.HTTPTooManyRequests(text='Wait one minute before trying again.')
            items.append(now)
        grant = self.store.valid_grant(ident)
        valid = False
        if grant and hmac.compare_digest(grant['token'], digest(token)):
            async with self.hash_slots:
                valid = hmac.compare_digest(grant['password'], await asyncio.to_thread(password_hash, password, grant['salt']))
        if not valid:
            raise web.HTTPUnauthorized(text='Invalid credentials or expired link.')
        for ws, meta in list(self.websockets.items()):
            if meta['grant'] == ident:
                await ws.close(code=4001, message=b'Another login replaced this session')
        session = self.store.login(grant)
        response = web.json_response({'ok': True})
        response.set_cookie(COOKIE, session, max_age=max(1, int(grant['expires'] - time.time())), httponly=True, secure=True, samesite='Strict', path='/')
        return response

    async def socket(self, request):
        grant = self.auth(request)
        if not self.origin_ok(request):
            raise web.HTTPForbidden()
        ident = int(request.match_info['id'])
        target = self.scoped_target(grant, ident)
        ws = web.WebSocketResponse(heartbeat=20, timeout=2, max_msg_size=65536, compress=False)
        await ws.prepare(request)
        if sum((m['session'] == digest(request.cookies[COOKIE]) for m in self.websockets.values())) >= 8 or len(self.websockets) >= 24:
            await ws.send_json({'type': 'error', 'message': 'Terminal limit reached (8 per workspace). Close a terminal first.'})
            await ws.close()
            return ws
        meta = {'grant': grant['id'], 'session': digest(request.cookies[COOKIE]), 'process': None, 'target': ident}
        self.websockets[ws] = meta
        try:
            conn = await self.connection(ident)
            process = await conn.create_process(term_type='xterm-256color', term_size=(100, 28), encoding='utf-8', errors='replace')
            meta['process'] = process
            await ws.send_json({'type': 'ready', 'target': target['name']})

            async def output():
                while not ws.closed:
                    text = await process.stdout.read(16384)
                    if not text:
                        break
                    await ws.send_json({'type': 'output', 'data': text})
                await ws.close(code=1000, message=b'SSH session ended')
            output_task = asyncio.create_task(output())
            try:
                async for msg in ws:
                    if not self.store.session(request.cookies.get(COOKIE, '')):
                        process.close()
                        await ws.close(code=4003, message=b'Access expired or revoked')
                        break
                    if msg.type != aiohttp.WSMsgType.TEXT:
                        continue
                    try:
                        data = json.loads(msg.data)
                    except ValueError:
                        continue
                    if data.get('type') == 'input' and isinstance(data.get('data'), str) and (len(data['data']) <= 8192):
                        process.stdin.write(data['data'])
                        await process.stdin.drain()
                    elif data.get('type') == 'resize':
                        cols = max(20, min(400, int(data.get('cols', 100))))
                        rows = max(5, min(200, int(data.get('rows', 28))))
                        process.change_terminal_size(cols, rows)
            finally:
                output_task.cancel()
                await asyncio.gather(output_task, return_exceptions=True)
        except Exception as ex:
            LOG.warning('terminal_failed target=%s type=%s', ident, type(ex).__name__)
            if not ws.closed:
                await ws.send_json({'type': 'error', 'message': 'SSH connection failed. Verify credentials and the pinned host key in server settings.'})
        finally:
            if meta['process']:
                with contextlib.suppress(Exception):
                    meta['process'].close()
                    await asyncio.wait_for(meta['process'].wait_closed(), 3)
            self.websockets.pop(ws, None)
            await ws.close()
        return ws

    async def probe(self, request):
        self.auth(request, True, True)
        body = await self.json(request)
        host, port, user = self.validate_host(body)
        try:
            key = await asyncio.wait_for(asyncssh.get_server_host_key(host, port, config=None), 8)
        except Exception:
            raise web.HTTPBadRequest(text='Cannot reach this SSH endpoint') from None
        return web.json_response({'hostkey': key.export_public_key().decode().strip(), 'fingerprint': key.get_fingerprint()})

    def validate_host(self, body):
        host = str(body.get('host', '')).strip()
        user = str(body.get('username', '')).strip()
        port = int(body.get('port', 22))
        if not re.fullmatch('[A-Za-z0-9_.:-]{1,253}', host) or not re.fullmatch('[A-Za-z0-9_.@\\\\-]{1,128}', user) or user.startswith('-') or (not 1 <= port <= 65535):
            raise web.HTTPBadRequest(text='Invalid SSH endpoint')
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                raise web.HTTPBadRequest(text='Invalid SSH address')
        except ValueError:
            pass
        return (host, port, user)

    async def add_target(self, request):
        self.auth(request, True, True)
        body = await self.json(request)
        host, port, user = self.validate_host(body)
        name = str(body.get('name', '')).strip()[:60]
        auth = body.get('auth', {})
        key = str(body.get('hostkey', ''))
        if not name or not isinstance(auth, dict) or (not (auth.get('private_key') or auth.get('password'))):
            raise web.HTTPBadRequest(text='Name and SSH credentials are required')
        private_key = auth.get('private_key') or ''
        passphrase = auth.get('passphrase') or ''
        password = auth.get('password') or ''
        if not all(isinstance(value, str) for value in (private_key, passphrase, password)):
            raise web.HTTPBadRequest(text='Invalid SSH credentials.')
        if len(private_key) > 32768 or len(passphrase) > 1024 or len(password) > 1024:
            raise web.HTTPBadRequest(text='SSH credential exceeds its size limit.')
        if private_key:
            try:
                asyncssh.import_private_key(private_key, passphrase or None)
            except (ValueError, asyncssh.KeyImportError):
                raise web.HTTPBadRequest(text='Cannot read this private key with the supplied passphrase.') from None
        auth = dict(private_key=private_key, passphrase=passphrase, password=password)
        try:
            asyncssh.import_public_key(key)
        except Exception:
            raise web.HTTPBadRequest(text='Probe and verify the host key before saving') from None
        ident = self.store.add_target({'name': name, 'host': host, 'port': port, 'username': user, 'hostkey': key, 'auth': auth})
        return web.json_response({'id': ident})

    def __init__(self, data, origin, allow_reverse=False):
        self.key = (data / 'fernet-key').read_bytes().strip()
        self.store = Store(data / 'gateway.sqlite', self.key)
        self.origin = origin
        self.allow_reverse = allow_reverse
        self.file_locks = {}
        self.connections = {}
        self.connection_locks = collections.defaultdict(asyncio.Lock)
        self.websockets = {}
        self.failures = collections.defaultdict(list)
        self.hash_slots = asyncio.Semaphore(2)
        self.metrics_slots = asyncio.Semaphore(2)
        self.metrics_locks = collections.defaultdict(asyncio.Lock)
        self.copy_init()
        self.forwards_init()

    def base(self):
        return self.origin

    def origin_ok(self, request):
        return request.headers.get('Origin') == self.origin

    async def forward_connection(self, ident):
        target = self.store.target(ident, True)
        auth = target['auth']
        host_key = asyncssh.import_public_key(target['hostkey'])
        keys = []
        if auth.get('private_key'):
            keys.append(asyncssh.import_private_key(auth['private_key'], auth.get('passphrase') or None))
        return await asyncssh.connect(
            target['host'], port=target['port'], username=target['username'], known_hosts=([host_key], [], []),
            client_keys=keys or None, password=auth.get('password'), agent_path=None, config=None,
            connect_timeout=6, login_timeout=8, keepalive_interval=20, keepalive_count_max=2,
        )

    async def connection(self, ident):
        async with self.connection_locks[ident]:
            conn = self.connections.get(ident)
            if conn is None or conn.is_closed():
                conn = await self.forward_connection(ident)
                self.connections[ident] = conn
            return conn

    async def session(self, request):
        grant = self.auth(request)
        hosts = self.store.targets()
        if grant['role'] != 'owner':
            hosts = [host for host in hosts if host['id'] == grant['target']]
        for host in hosts:
            host['fingerprint'] = asyncssh.import_public_key(host.pop('hostkey')).get_fingerprint()
        return web.json_response({
            'role': grant['role'], 'expires': grant['expires'], 'target': grant['target'],
            'targets': hosts, 'csrf': self.csrf(request.cookies[COOKIE]), 'reverse': self.allow_reverse,
        })

    async def logout(self, request):
        self.auth(request, post=True)
        token = request.cookies[COOKIE]
        with self.store.db:
            self.store.db.execute('DELETE FROM sessions WHERE token=?', (digest(token),))
        response = web.json_response({'ok': True})
        response.set_cookie(COOKIE, '', max_age=0, secure=True, httponly=True, samesite='Strict', path='/')
        return response

    async def remove(self, request):
        self.auth(request, True, True)
        host = int(request.match_info['id'])
        self.store.target(host)
        async with self.forward_lock:
            profiles = self.forward_profiles()
            for ident in [i for i, p in profiles.items() if p['host'] == host]:
                await self.forward_stop(ident)
                profiles.pop(ident)
            self.forward_save(profiles)
        async with self.connection_locks[host]:
            with self.store.db:
                self.store.db.execute('DELETE FROM targets WHERE id=?', (host,))
                self.store.db.execute("UPDATE grants SET revoked=1 WHERE role='guest' AND target=?", (host,))
                self.store.db.execute('DELETE FROM metrics WHERE target=?', (host,))
            conn = self.connections.pop(host, None)
            if conn:
                conn.close()
        return web.json_response({'ok': True})

    async def metrics(self, request):
        grant = self.auth(request)
        host = int(request.match_info['id'])
        self.scoped_target(grant, host)
        async with self.metrics_locks[host]:
            row = self.store.db.execute('SELECT value,checked FROM metrics WHERE target=?', (host,)).fetchone()
            if row and time.time() - row['checked'] < 25:
                return web.json_response({'sample': json.loads(row['value']), 'checked': row['checked']})
            try:
                async with self.metrics_slots, asyncio.timeout(12):
                    connection = await self.connection(host)
                    script = (ROOT / 'collector.py').read_text()
                    async with connection.create_process('python3 -c ' + shlex.quote(script)) as process:
                        raw = await process.stdout.read(65537)
                        if len(raw) > 65536:
                            raise ValueError('Sample too large')
                        sample = json.loads(raw)
                        if not isinstance(sample, dict):
                            raise ValueError('Invalid sample')
                now = time.time()
                with self.store.db:
                    self.store.db.execute('INSERT OR REPLACE INTO metrics VALUES (?,?,?)', (host, json.dumps(sample), now))
                return web.json_response({'sample': sample, 'checked': now})
            except (OSError, ValueError, asyncssh.Error, TimeoutError):
                raise web.HTTPBadGateway(text='Resource sampling requires Python 3 and /proc on the selected Linux host.') from None

    async def sweep(self):
        while True:
            for ws, meta in list(self.websockets.items()):
                session = self.store.db.execute(
                    'SELECT 1 FROM sessions WHERE token=? AND expires>?', (meta['session'], time.time())
                ).fetchone()
                if not session or not self.store.valid_grant(meta['grant']):
                    await ws.close(code=4003, message=b'Access expired or revoked')
            for peer, attempts in list(self.failures.items()):
                if not attempts or attempts[-1] < time.monotonic() - 60:
                    self.failures.pop(peer, None)
            with self.store.db:
                self.store.db.execute('DELETE FROM sessions WHERE expires<=?', (time.time(),))
                self.store.db.execute('DELETE FROM grants WHERE expires<=?', (time.time(),))
            await asyncio.sleep(2)

    async def start(self, app):
        self.workers = [asyncio.create_task(self.forward_worker()), asyncio.create_task(self.sweep())]

    async def stop(self, app):
        tasks = [*self.workers, *self.transfer_tasks.values()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for ident in list(self.forward_live):
            await self.forward_stop(ident)
        for conn in self.connections.values():
            conn.close()
        self.store.db.close()

    def application(self):
        @web.middleware
        async def headers(request, handler):
            try:
                response = await handler(request)
            except web.HTTPException as exc:
                response = web.Response(status=exc.status, body=exc.body, headers=exc.headers)
            except (TypeError, KeyError, ValueError):
                response = web.Response(status=400, text='Invalid request.')
            except (OSError, asyncssh.Error, TimeoutError):
                response = web.Response(status=502, text='The SSH endpoint could not be reached or refused the operation.')
            except Exception as exc:
                LOG.error('Request failed (%s)', type(exc).__name__)
                response = web.Response(status=500, text='Request failed.')
            if not response.prepared:
                response.headers.update({
                    'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
                    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                })
            return response

        app = web.Application(client_max_size=11 * 1024**2, middlewares=[headers])
        app.router.add_get('/', self.index)
        app.router.add_get('/healthz', health)
        app.router.add_static('/static', ROOT / 'static', show_index=False, follow_symlinks=False)
        app.router.add_post('/api/login', self.login)
        app.router.add_get('/api/session', self.session)
        app.router.add_post('/api/logout', self.logout)
        app.router.add_get('/ws/{id}', self.socket)
        app.router.add_post('/api/probe', self.probe)
        app.router.add_post('/api/targets', self.add_target)
        app.router.add_delete('/api/targets/{id}', self.remove)
        app.router.add_get('/api/metrics/{id}', self.metrics)
        app.router.add_get('/api/files/{id}/{action:list|read|download}', self.files)
        app.router.add_post('/api/files/{id}/{action:save|upload}', self.file_write)
        app.router.add_get('/api/copies', self.copies)
        app.router.add_post('/api/copies', self.copies)
        self.forward_routes(app)
        app.on_startup.append(self.start)
        app.on_cleanup.append(self.stop)
        return app


async def health(request):
    return web.json_response({'ok': True})
