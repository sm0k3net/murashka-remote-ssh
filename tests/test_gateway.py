"""Exercise the public release against ephemeral authenticated SSH endpoints."""
import asyncio
import tempfile
import unittest
from pathlib import Path

import asyncssh
from aiohttp.test_utils import TestClient, TestServer
from cryptography.fernet import Fernet

from app import COOKIE, Gateway


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


if __name__ == '__main__':
    unittest.main()
