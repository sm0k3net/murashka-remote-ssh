"""Exercise the public release against ephemeral authenticated SSH endpoints."""
import asyncio
import json
import re
import time
import tempfile
import unittest
from pathlib import Path

import asyncssh
from aiohttp.test_utils import TestClient, TestServer
from cryptography.fernet import Fernet

from app import COOKIE, Gateway
from telegram_bot import Telegram


class SSHServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == 'demo' and password == 'synthetic-test-password'

    def connection_requested(self, *args):
        return True

    def server_requested(self, *args):
        return True


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        data = self.root / 'data'
        data.mkdir()
        (data / 'fernet-key').write_bytes(Fernet.generate_key())
        self.gateway = Gateway(data, 'https://remote.example.org', allow_reverse=True)
        self.client = TestClient(TestServer(self.gateway.application()))
        await self.client.start_server()
        self.origin = {'Origin': self.gateway.base()}
        self.review_hash = 'a' * 64
        self.desktop_installs = []
        self.hosts = []
        self.folders = []
        for index in range(2):
            folder = self.root / str(index)
            folder.mkdir()
            self.folders.append(folder)
            key = asyncssh.generate_private_key('ssh-ed25519')
            server = await asyncssh.create_server(
                SSHServer, '127.0.0.1', 0, server_host_keys=[key],
                process_factory=self.shell, sftp_factory=lambda chan, root=folder: asyncssh.SFTPServer(chan, chroot=root),
            )
            self.addAsyncCleanup(self.close_server, server)
            self.hosts.append(dict(name=f'Fixture {index}', host='127.0.0.1', port=server.get_port(),
                                   username='demo', hostkey=key.export_public_key().decode(),
                                   auth={'password': 'synthetic-test-password'}))

        self.addAsyncCleanup(self.client.close)

    async def close_server(self, server):
        server.close()
        await server.wait_closed()

    async def shell(self, process):
        if process.command == 'id -u':
            process.stdout.write('1000\n')
            process.exit(0)
            return
        if process.command and 'Provision or manage only' in process.command:
            fixture = json.loads(await process.stdin.read())
            self.desktop_installs.append(fixture['action'])
            process.stdout.write(json.dumps({'installed': fixture['action'] != 'remove', 'port': 5901}))
            process.exit(0)
            return
        if process.command and 'Bounded read-only Linux audit' in process.command:
            process.stdout.write(json.dumps({
                'uid': 1000, 'config_hashes': {'/etc/ssh/sshd_config': self.review_hash},
                'coverage': ['fixture'], 'findings': [{'severity': 'info', 'title': '<unsafe>', 'detail': 'test'}],
            }))
            process.exit(0)
            return
        if process.command and process.command.startswith('python3 -c '):
            process.stdout.write('{"cpu": 8.5, "disk": 23, "top": []}')
            process.exit(0)
            return
        process.stdout.write('demo$ ')
        line = await process.stdin.readline()
        process.stdout.write('echoed: ' + line)
        process.exit(0)

    async def login(self, host=None):
        grant = self.gateway.store.grant(host or 0, 'guest' if host else 'owner', 1800)
        response = await self.client.post('/api/login', json=grant, headers=self.origin)
        self.assertEqual(response.status, 200, await response.text())
        self.assertTrue(response.cookies[COOKIE]['secure'])
        token = response.cookies[COOKIE].value
        return grant, dict(self.origin, Cookie=COOKIE + '=' + token, **{'X-CSRF': self.gateway.csrf(token)})

    async def post(self, path, body, headers):
        response = await self.client.post(path, json=body, headers=headers)
        self.assertEqual(response.status, 200, await response.text())
        return await response.json()

    async def test_first_login_pin_terminal_and_revoke(self):
        grant, headers = await self.login()
        empty = await self.client.get('/api/session', headers=headers)
        self.assertEqual((await empty.json())['targets'], [])
        host = self.hosts[0]
        fingerprint = await self.post('/api/probe', host, headers)
        self.assertEqual(asyncssh.import_public_key(host['hostkey']).get_fingerprint(), fingerprint['fingerprint'])
        self.assertEqual((await self.client.post('/api/targets', json=host, headers={**headers, 'Origin': 'https://wrong.example'})).status, 403)
        added = await self.post('/api/targets', host, headers)
        ws = await self.client.ws_connect('/ws/' + str(added['id']), headers=headers)
        self.assertEqual((await ws.receive_json(timeout=3))['type'], 'ready')
        self.assertIn('demo$', (await ws.receive_json(timeout=3))['data'])
        await ws.send_json({'type': 'input', 'data': 'hello\n'})
        self.assertIn('echoed: hello', (await ws.receive_json(timeout=3))['data'])
        await ws.close()
        self.gateway.store.revoke(grant['id'])
        self.assertEqual((await self.client.get('/api/session', headers=headers)).status, 401)

    async def test_copy_guest_scope_and_metrics(self):
        _, owner = await self.login()
        source, dest = [(await self.post('/api/targets', host, owner))['id'] for host in self.hosts]
        original = self.folders[0] / 'hello.txt'
        original.write_text('a file to copy')
        _, guest = await self.login(source)
        self.assertEqual((await self.client.get(f'/api/files/{dest}/list', headers=guest)).status, 403)
        self.assertEqual((await self.client.get('/api/copies', headers=guest)).status, 403)
        self.assertEqual((await self.client.get('/api/forwards', headers=guest)).status, 403)
        usage = await self.client.get(f'/api/metrics/{source}', headers=owner)
        self.assertEqual(usage.status, 200, await usage.text())
        self.assertEqual((await usage.json())['sample']['cpu'], 8.5)
        job = await self.post('/api/copies', dict(source_host=source, destination_host=dest, source='/hello.txt',
                              destination='/hello.txt', confirm=True), owner)
        task = self.gateway.transfer_tasks.get(job['id'])
        if task:
            await asyncio.wait_for(task, 8)
        response = await self.client.get('/api/copies', headers=owner)
        current = (await response.json())[0]
        self.assertEqual(current['state'], 'done', current)
        self.assertEqual((self.folders[1] / 'hello.txt').read_text(), original.read_text())

    async def test_forward_local_reverse_and_socks(self):
        _, headers = await self.login()
        host = (await self.post('/api/targets', self.hosts[0], headers))['id']

        async def echo(reader, writer):
            try:
                while data := await reader.read(32768):
                    writer.write(data.upper())
                    await writer.drain()
            finally:
                writer.close()

        server = await asyncio.start_server(echo, '127.0.0.1', 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            for kind in ('local', 'remote', 'socks'):
                profile = await self.post('/api/forwards', dict(action='save', host=host, kind=kind,
                                          destination_host='127.0.0.1', destination_port=port), headers)
                live = await self.post('/api/forwards', dict(action='start', id=profile['id']), headers)
                self.assertEqual(live['state'], 'running', live)
                reader, writer = await asyncio.open_connection('127.0.0.1', live['listen_port'])
                try:
                    async with asyncio.timeout(3):
                        if kind == 'socks':
                            writer.write(b'\x05\x01\x00')
                            await writer.drain()
                            self.assertEqual(await reader.readexactly(2), b'\x05\x00')
                            writer.write(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + port.to_bytes(2, 'big'))
                            await writer.drain()
                            self.assertEqual((await reader.readexactly(10))[:2], b'\x05\x00')
                        writer.write(b'hello')
                        await writer.drain()
                        self.assertEqual(await reader.readexactly(5), b'HELLO')
                finally:
                    writer.close()
                await self.post('/api/forwards', dict(action='delete', id=profile['id']), headers)



    async def test_owner_review_baseline_report_and_desktop_lifecycle(self):
        _, headers = await self.login()
        host = (await self.post('/api/targets', self.hosts[0], headers))['id']
        _, guest = await self.login(host)
        for endpoint, kind in ((f'/api/host-review/{host}', 'review'), (f'/api/desktop/{host}', 'desktop')):
            self.assertEqual((await self.client.get(endpoint, headers=guest)).status, 403)
            self.assertEqual((await self.client.post(endpoint, json={'action':'run'}, headers=guest)).status, 403)

        async def operation(endpoint, body, kind):
            response = await self.client.post(endpoint, json=body, headers=headers)
            self.assertEqual(response.status, 202, await response.text())
            task = self.gateway.host_tasks.get((host, kind))
            if task:
                await asyncio.wait_for(task, 5)
            self.assertEqual(self.gateway.host_jobs[(host, kind)]['state'], 'done', self.gateway.host_jobs)

        endpoint = f'/api/host-review/{host}'
        await operation(endpoint, {'action':'run'}, 'review')
        reports = await (await self.client.get(endpoint, headers=headers)).json()
        latest = reports['reports'][0]['id']
        report = await self.client.get(endpoint + '/report/' + latest, headers=headers)
        self.assertIn('&lt;unsafe&gt;', await report.text())
        self.assertIn('attachment', report.headers['Content-Disposition'])
        await self.post(endpoint, {'action':'baseline','report':latest,'confirm':True}, headers)
        self.review_hash = 'b' * 64
        await operation(endpoint, {'action':'run'}, 'review')
        reports = await (await self.client.get(endpoint, headers=headers)).json()
        self.assertEqual(reports['reports'][0]['changes'], [{'path':'/etc/ssh/sshd_config', 'change':'Changed'}])

        endpoint = f'/api/desktop/{host}'
        request = {'action':'install','variant':'xfce'}
        self.assertEqual((await self.client.post(endpoint, json=request, headers=headers)).status, 400)
        await operation(endpoint, {**request, 'confirm':True}, 'desktop')
        password = (await self.post(endpoint+'/credentials', {}, headers))['password']
        self.assertRegex(password, r'^[A-Za-z0-9]{8}$')
        self.assertNotIn(password, self.gateway.store.setting('desktop-password-' + str(host)))
        self.assertEqual((await self.client.post(endpoint + '/credentials', json={}, headers=guest)).status, 403)
        await operation(endpoint, {'action':'restart', 'confirm':True}, 'desktop')
        await operation(endpoint, {'action':'remove', 'confirm':True}, 'desktop')
        self.assertIsNone((await self.post(endpoint + '/credentials', {}, headers))['password'])
        self.assertEqual(self.desktop_installs, ['install', 'restart', 'remove'])

    async def test_browser_vnc_relays_loopback_and_checks_origin(self):
        _, owner = await self.login()
        host = (await self.post('/api/targets', self.hosts[0], owner))['id']
        _, guest = await self.login(host)

        async def fake_display(reader, writer):
            try:
                writer.write(b'RFB 003.008\n')
                await writer.drain()
                writer.write(await reader.readexactly(12))
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        for port in (5900, 5901):
            try:
                listener = await asyncio.start_server(fake_display, '127.0.0.1', port)
            except OSError:
                continue
            break
        else:
            self.skipTest('Both loopback fixture ports are in use')
        async with listener:
            endpoint = f'/api/desktop/{host}/ws?port={port}'
            self.assertEqual((await self.client.get(endpoint, headers=guest)).status, 403)
            self.assertEqual((await self.client.get(endpoint, headers={**owner,'Origin':'https://other.example'})).status, 403)
            async with self.client.ws_connect(endpoint, headers=owner) as ws:
                self.assertEqual((await ws.receive(timeout=3)).data, b'RFB 003.008\n')
                await ws.send_bytes(b'RFB 003.008\n')
                self.assertEqual((await ws.receive(timeout=3)).data, b'RFB 003.008\n')

    async def test_telegram_private_access_and_revocation(self):
        _, headers = await self.login()
        host = (await self.post('/api/targets', self.hosts[0], headers))['id']
        bot = Telegram(self.gateway.store, self.gateway.base(), 'unused-fixture-token', 42)
        now = int(time.time())
        message = {'chat':{'type':'private','id':42}, 'from':{'id':42}, 'date':now, 'text':f'/connect {host}'}
        self.assertIsNone(bot.reply({'message':{**message, 'from':{'id':43}}}, now))
        self.assertIsNone(bot.reply({'message':{**message, 'chat':{'type':'group','id':42}}}, now))
        self.assertIsNone(bot.reply({'message':{**message, 'date':now-121}}, now))
        reply = bot.reply({'message':message}, now)
        ident = re.search(r'Revoke: /revoke (\S+)', reply)[1]
        grant = self.gateway.store.valid_grant(ident)
        self.assertEqual((grant['target'],grant['role']), (host,'guest'))
        self.assertEqual(bot.reply({'message':{**message,'text':'/revoke '+ident}}, now), 'Workspace revoked.')
        self.assertIsNone(self.gateway.store.valid_grant(ident))


if __name__ == '__main__':
    unittest.main()
