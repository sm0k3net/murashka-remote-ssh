import asyncio
import json
import secrets
import socket
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

from db import Store
from helper_broker import serve


class BrokerTests(unittest.IsolatedAsyncioTestCase):
    async def test_socket_permissions_allowlist_guest_and_revoke(self):
        try:
            with socket.socket(socket.AF_UNIX):
                pass
        except PermissionError:
            self.skipTest('Sandbox disallows AF_UNIX sockets')
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            key = Fernet.generate_key()
            (state / 'fernet-key').write_bytes(key)
            token = secrets.token_urlsafe(48)
            token_path = state / 'helper-token'
            token_path.write_text(token)
            token_path.chmod(0o600)
            store = Store(state / 'gateway.sqlite', key)
            try:
                def target(name):
                    return store.add_target({'name': name, 'host': '127.0.0.1', 'port': 22,
                                             'username': 'fixture', 'hostkey': 'fixture', 'auth': {}})
                staging, private = target('Staging'), target('Outside allowlist')
                owner = store.grant(private, 'owner', 1800)
                path = state / 'helper.sock'
                broker = asyncio.create_task(serve(state, 'https://remote.example.org', path, [staging]))
                try:
                    for _ in range(100):
                        if path.is_socket():
                            break
                        if broker.done():
                            broker.result()
                        await asyncio.sleep(.01)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o660)

                    async def send(op, secret=token, **kw):
                        reader, writer = await asyncio.open_unix_connection(path)
                        try:
                            writer.write((json.dumps({'op': op, 'token': secret, **kw}) + '\n').encode())
                            await writer.drain()
                            return json.loads(await reader.readline())
                        finally:
                            writer.close()
                            await writer.wait_closed()

                    self.assertEqual((await send('hosts'))['result'], [{'id': staging, 'name': 'Staging'}])
                    self.assertFalse((await send('hosts', secret='bad'))['ok'])
                    self.assertFalse((await send('grant', host=private))['ok'])
                    self.assertFalse((await send('revoke', id=owner['id']))['ok'])
                    self.assertTrue(store.valid_grant(owner['id']))
                    reply = (await send('grant', host=staging, role='owner'))['result']
                    grant = store.valid_grant(reply['id'])
                    self.assertEqual((grant['role'], grant['target']), ('guest', staging))
                    self.assertTrue((await send('revoke', id=reply['id']))['ok'])
                    self.assertIsNone(store.valid_grant(reply['id']))
                finally:
                    broker.cancel()
                    await asyncio.gather(broker, return_exceptions=True)
                self.assertFalse(path.exists())
            finally:
                store.db.close()
