"""Saved loopback SSH forwarding and optional authenticated computer bridges."""
import asyncio, contextlib, hmac, io, json, secrets, time, zipfile
from pathlib import Path
import aiohttp, asyncssh
from aiohttp import web
from db import digest

class Forwards:

    def forwards_init(self):
        self.forward_live = {}
        self.forward_links = {}
        self.forward_pending = {}
        self.forward_lock = asyncio.Lock()

    def forward_profiles(self):
        raw = self.store.setting('forward_profiles')
        return self.store.unseal(raw) if raw else {}

    def forward_save(self, p):
        self.store.set('forward_profiles', self.store.seal(p))

    def forward_spec(self, b):
        host = b.get('host')
        self.store.target(host)
        if type(host) != int or b.get('kind') not in ('local', 'remote', 'socks'):
            raise ValueError('Choose a host and tunnel purpose')
        if b['kind'] == 'remote' and not self.allow_reverse:
            raise ValueError('Reverse forwarding must be enabled in local gateway configuration.')
        port = b.get('port', 0)
        dest_port = b.get('destination_port', 0)
        dest = str(b.get('destination_host', '127.0.0.1')).strip()
        if type(port) != int or not (port == 0 or 1024 <= port <= 65535):
            raise ValueError('Listen port: 0 for automatic, or 1024–65535')
        if b['kind'] != 'socks' and (type(dest_port) != int or not 1 <= dest_port <= 65535):
            raise ValueError('Destination port: 1–65535')
        import re
        if not re.fullmatch('[A-Za-z0-9_.:-]{1,253}', dest):
            raise ValueError('Invalid destination hostname')
        endpoint = b.get('endpoint', 'gateway')
        if endpoint not in ('gateway', 'computer'):
            raise ValueError('Select the gateway or your computer')
        if b['kind'] == 'remote' and endpoint == 'computer' and (dest not in ('127.0.0.1', 'localhost', '::1')):
            raise ValueError('Computer service must listen on localhost')
        return {'id': secrets.token_hex(12), 'name': str(b.get('name', 'Tunnel'))[:80] or 'Tunnel', 'host': host, 'kind': b['kind'], 'endpoint': endpoint, 'port': port, 'destination_host': dest, 'destination_port': dest_port, 'autostart': b.get('autostart') is True}

    def forward_view(self, p):
        v = self.forward_live.get(p['id'], {})
        return {**p, 'state': v.get('state', 'stopped'), 'listen_port': v.get('port'), 'error': v.get('error'), 'connections': len(v.get('streams', [])), 'retry_at': v.get('retry_at'), 'location': 'Selected SSH host' if p['kind'] == 'remote' else 'Gateway loopback'}

    async def forward_stop(self, ident, reconnecting=False):
        v = self.forward_live.pop(ident, None)
        if not v:
            return
        if v.get('listener'):
            v['listener'].close()
        tasks = list(v.get('streams', []))
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if v.get('listener'):
            with contextlib.suppress(Exception):
                await asyncio.wait_for(v['listener'].wait_closed(), 5)
        if v.get('conn'):
            v['conn'].close()
        for k, link in list(self.forward_links.items()):
            if link['tunnel'] == ident and (not reconnecting):
                self.forward_links.pop(k, None)

    async def forward_relay(self, a, b, c, d):

        async def pump(reader, writer):
            while (data := (await reader.read(32768))):
                writer.write(data)
                await writer.drain()
        tasks = [asyncio.create_task(pump(a, d)), asyncio.create_task(pump(c, b))]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                t.result()
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for w in (b, d):
                w.close()
                with contextlib.suppress(Exception):
                    await w.wait_closed()

    async def forward_stream(self, p, v, reader, writer):
        task = asyncio.current_task()
        other = None
        if len(v['streams']) >= 8 or sum((len(x.get('streams', [])) for x in self.forward_live.values())) >= 32:
            writer.close()
            return
        v['streams'].add(task)
        try:
            dest, port = (p['destination_host'], p['destination_port'])
            if p['kind'] == 'socks':
                async with asyncio.timeout(10):
                    version, n = await reader.readexactly(2)
                    methods = await reader.readexactly(n)
                    if version != 5 or 0 not in methods:
                        writer.write(b'\x05\xff')
                        await writer.drain()
                        return
                    writer.write(b'\x05\x00')
                    await writer.drain()
                    version, cmd, res, typ = await reader.readexactly(4)
                    if version != 5 or cmd != 1 or res:
                        raise ValueError('SOCKS5 CONNECT only')
                    import socket
                    if typ == 1:
                        dest = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
                    elif typ == 4:
                        dest = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
                    elif typ == 3:
                        dest = (await reader.readexactly((await reader.readexactly(1))[0])).decode('ascii')
                    else:
                        raise ValueError('Unsupported address')
                    port = int.from_bytes(await reader.readexactly(2), 'big')
            if p['kind'] == 'remote' and p['endpoint'] == 'computer':
                channel = secrets.token_hex(20)
                future = asyncio.get_running_loop().create_future()
                self.forward_pending[channel] = {'tunnel': p['id'], 'created': time.time(), 'reader': reader, 'writer': writer, 'future': future, 'claimed': False}
                try:
                    await asyncio.wait_for(asyncio.shield(future), 20)
                    await future.result()
                finally:
                    self.forward_pending.pop(channel, None)
                return
            if p['kind'] == 'remote':
                r, other = await asyncio.wait_for(asyncio.open_connection(dest, port), 15)
            else:
                r, other = await asyncio.wait_for(v['conn'].open_connection(dest, port, encoding=None), 15)
            if p['kind'] == 'socks':
                writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
            v.pop('error', None)
            await self.forward_relay(reader, writer, r, other)
        except asyncssh.ChannelOpenError as e:
            v['error'] = 'SSH channel refused: forwarding may be disabled for this key/account, or the destination is unavailable. ' + str(e)[:120]
        except asyncio.CancelledError:
            pass
        except Exception:
            v['error'] = 'Connection failed: check destination address, service availability and forwarding policy.'
        finally:
            writer.close()
            if other:
                other.close()
            v['streams'].discard(task)

    async def forward_start(self, p):
        if p['kind'] == 'remote' and not self.allow_reverse:
            raise ValueError('Reverse forwarding is disabled.')
        ident = p['id']
        if ident in self.forward_live and self.forward_live[ident]['state'] == 'running':
            return self.forward_view(p)
        if len(self.forward_live) >= 8 and ident not in self.forward_live:
            raise ValueError('Limit: eight enabled tunnels')
        previous = self.forward_live.get(ident, {})
        attempt = previous.get('attempt', 0) + 1
        await self.forward_stop(ident, True)
        v = {'profile': p, 'state': 'connecting', 'streams': set(), 'attempt': attempt}
        self.forward_live[ident] = v
        try:
            conn = await self.forward_connection(p['host'])
            v['conn'] = conn
            handler = lambda r, w: self.forward_stream(p, v, r, w)
            if p['kind'] == 'remote':
                listener = await asyncio.wait_for(conn.start_server(lambda origin_host, origin_port: handler, '127.0.0.1', p['port'], encoding=None), 20)
            else:
                listener = await asyncio.start_server(handler, '127.0.0.1', p['port'])
            if listener is None:
                raise ValueError('Server refused remote forwarding')
            v.update(listener=listener, port=listener.get_port() if p['kind'] == 'remote' else listener.sockets[0].getsockname()[1], state='running', attempt=0)
        except asyncio.CancelledError:
            await self.forward_stop(ident)
            raise
        except Exception:
            v.update(state='retrying', error='SSH forwarding unavailable or listen port busy. Check SSH forwarding policy and endpoint.', retry_at=time.time() + min(60, 5 * 2 ** min(attempt, 4)))
        return self.forward_view(p)

    async def forward_worker(self):
        while True:
            try:
                async with self.forward_lock:
                    profiles = self.forward_profiles()
                    for p in profiles.values():
                        if p['autostart'] and (p['kind'] != 'remote' or self.allow_reverse) and p['id'] not in self.forward_live and (len(self.forward_live) < 8):
                            try:
                                self.store.target(p['host'])
                                await self.forward_start(p)
                            except (ValueError, KeyError):
                                pass
                    for ident, v in list(self.forward_live.items()):
                        try:
                            self.store.target(v['profile']['host'])
                        except Exception:
                            await self.forward_stop(ident)
                            continue
                        if v['state'] == 'running' and v.get('conn') and v['conn'].is_closed():
                            if v.get('listener'):
                                v['listener'].close()
                            v.update(state='retrying', retry_at=time.time() + 5)
                        if v['state'] == 'retrying' and v.get('retry_at', 0) <= time.time():
                            await self.forward_start(v['profile'])
                for ident, link in list(self.forward_links.items()):
                    if not self.forward_link_valid(link):
                        self.forward_links.pop(ident, None)
            except Exception:
                pass
            await asyncio.sleep(5)

    async def forwards_api(self, request):
        self.auth(request, True, request.method == 'POST')
        if request.method == 'GET':
            profiles = self.forward_profiles()
            rows = [self.forward_view(p) for p in profiles.values()]
            rows.extend((self.forward_view(v['profile']) for i, v in self.forward_live.items() if i not in profiles))
            return web.json_response(rows, headers={'Cache-Control': 'no-store'})
        b = await self.json(request)
        try:
            async with self.forward_lock:
                profiles = self.forward_profiles()
                ident = str(b.get('id', ''))
                action = b.get('action')
                if action == 'save':
                    if ident in self.forward_live:
                        raise ValueError('Stop this tunnel before editing')
                    if ident and ident not in profiles:
                        raise ValueError('Unknown tunnel')
                    if not ident and len(profiles) >= 24:
                        raise ValueError('Limit: 24 saved tunnels')
                    p = self.forward_spec(b)
                    p['id'] = ident or p['id']
                    profiles[p['id']] = p
                    self.forward_save(profiles)
                    return web.json_response(self.forward_view(p))
                p = profiles.get(ident) or self.forward_live.get(ident, {}).get('profile')
                if not p:
                    raise ValueError('Unknown tunnel')
                if action == 'start':
                    return web.json_response(await self.forward_start(p))
                if action in ('stop', 'delete'):
                    await self.forward_stop(ident)
                    if ident in profiles:
                        if action == 'delete':
                            profiles.pop(ident)
                        else:
                            profiles[ident]['autostart'] = False
                        self.forward_save(profiles)
                    return web.json_response({'ok': True})
                raise ValueError('Unknown tunnel action')
        except (ValueError, TypeError, KeyError) as e:
            raise web.HTTPBadRequest(text=str(e)) from None

    def forward_link_valid(self, link):
        return link['expires'] > time.time() and link['tunnel'] in self.forward_live and self.store.valid_grant(link['grant']) and self.store.db.execute('SELECT 1 FROM sessions WHERE token=? AND expires>?', (link['session'], time.time())).fetchone()

    def forward_link_auth(self, request):
        link = self.forward_links.get(request.match_info['link'])
        token = request.headers.get('Authorization', '').removeprefix('Bearer ')
        if not link or not hmac.compare_digest(link['token'], digest(token)) or (not self.forward_link_valid(link)):
            raise web.HTTPUnauthorized()
        return link

    async def forward_bundle(self, request):
        grant = self.auth(request, True, True)
        b = await self.json(request)
        ident = str(b.get('id', ''))
        v = self.forward_live.get(ident)
        if not v or v['state'] != 'running':
            raise web.HTTPBadRequest(text='Start the tunnel first')
        if len(self.forward_links) >= 24:
            raise web.HTTPTooManyRequests()
        p = v['profile']
        if p['kind'] == 'remote' and p['endpoint'] != 'computer':
            raise web.HTTPBadRequest(text='Select your computer as the source service before downloading a reverse bridge')
        port = b.get('local_port', 1080 if p['kind'] == 'socks' else p['destination_port'])
        if type(port) != int or not 1024 <= port <= 65535:
            raise web.HTTPBadRequest(text='Computer listen port must be 1024–65535')
        key = secrets.token_hex(16)
        token = secrets.token_urlsafe(40)
        expires = min(grant['expires'], time.time() + 43200)
        self.forward_links[key] = {'token': digest(token), 'expires': expires, 'grant': grant['id'], 'session': digest(request.cookies['__Host-murashka-remote']), 'tunnel': ident}
        cfg = {'url': self.base().replace('https://', 'wss://', 1) + '/connector/forward/' + key + '/socket', 'token': token, 'expires': expires, 'protocol': 'SOCKS5' if p['kind'] == 'socks' else 'TCP', 'local_port': port, 'reverse': p['kind'] == 'remote', 'service_port': p['destination_port'], 'pending_url': self.base() + '/connector/forward/' + key + '/pending'}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('bridge.py', Path(__file__).with_name('forward_client.py').read_text())
            z.writestr('desktop_client.py', Path(__file__).with_name('desktop_client.py').read_text())
            z.writestr('connection.json', json.dumps(cfg, indent=2))
            z.writestr('README.txt', 'Python 3.10+ required. Extract, then run: python3 bridge.py (Windows: py -3 bridge.py).\nKeep running; new connections reconnect automatically. Existing TCP connections cannot survive a broken network.\nLocal/SOCKS: use 127.0.0.1:' + str(port) + '. SOCKS uses remote DNS (socks5h).\nRemote: serves your computer localhost:' + str(p['destination_port']) + ' via selected server loopback:' + str(v['port']) + '.\nExpires with workspace / logout; download a fresh bundle afterwards. Treat connection.json as a password.\nNo automatic OS-startup installation is performed.\n')
        return web.Response(body=buf.getvalue(), headers={'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="murashka-tunnel.zip"', 'Cache-Control': 'no-store'})

    async def forward_pending_api(self, request):
        link = self.forward_link_auth(request)
        return web.json_response([k for k, p in self.forward_pending.items() if p['tunnel'] == link['tunnel'] and (not p['claimed'])], headers={'Cache-Control': 'no-store'})

    async def forward_socket(self, request):
        link = self.forward_link_auth(request)
        v = self.forward_live[link['tunnel']]
        p = v['profile']
        pending = None
        if v['state'] != 'running':
            raise web.HTTPServiceUnavailable(text='Tunnel is reconnecting')
        if p['kind'] == 'remote':
            pending = self.forward_pending.get(request.query.get('channel', ''))
            if not pending or pending['claimed'] or pending['tunnel'] != p['id']:
                raise web.HTTPNotFound()
            pending['claimed'] = True
            reader, writer = (pending['reader'], pending['writer'])
        else:
            if sum((1 for x in self.websockets.values() if x.get('forward_link'))) >= 16:
                raise web.HTTPTooManyRequests()
            reader, writer = await asyncio.open_connection('127.0.0.1', v['port'])
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=65536, compress=False, protocols=('binary',))
        tasks = []
        try:
            await ws.prepare(request)
        except BaseException:
            writer.close()
            raise
        self.websockets[ws] = {'grant': link['grant'], 'session': link['session'], 'target': p['host'], 'process': None, 'forward_link': True}
        if pending:
            pending['future'].set_result(asyncio.current_task())
        try:

            async def up():
                while (data := (await reader.read(32768))):
                    await ws.send_bytes(data)
                await ws.close()

            async def expiry():
                while self.forward_link_valid(link):
                    await asyncio.sleep(2)
                await ws.close(code=4003)
            tasks = [asyncio.create_task(up()), asyncio.create_task(expiry())]
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
        finally:
            writer.close()
            self.websockets.pop(ws, None)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            with contextlib.suppress(Exception):
                await ws.close()
        return ws

    def forward_routes(self, app):
        app.router.add_get('/api/forwards', self.forwards_api)
        app.router.add_post('/api/forwards', self.forwards_api)
        app.router.add_post('/api/forwards/bridge', self.forward_bundle)
        app.router.add_get('/connector/forward/{link}/pending', self.forward_pending_api)
        app.router.add_get('/connector/forward/{link}/socket', self.forward_socket)
