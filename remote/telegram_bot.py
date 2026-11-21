"""Optional private Telegram control for a single operator."""
import asyncio
import getpass
import json
import os
import re
import time

import aiohttp

from db import Store

COMMANDS = (
    '/hosts — list saved hosts and IDs\n'
    '/status HOST_ID — last resource sample and review time\n'
    '/connect HOST_ID — issue a 30-minute workspace for that host\n'
    '/revoke GRANT_ID — revoke an access link issued by this bot'
)


def setup(state):
    token = getpass.getpass('Telegram bot token: ').strip()
    operator = input('Your numeric Telegram user ID: ').strip()
    if not re.fullmatch(r'[0-9]{5,16}:[A-Za-z0-9_-]{20,128}', token) or not operator.isdecimal() or int(operator) < 1:
        raise ValueError('Enter a BotFather token and a positive Telegram user ID.')
    path = state / 'telegram.json'
    if path.is_symlink():
        raise ValueError('Refusing a linked Telegram configuration.')
    temporary = state / '.telegram.new'
    with temporary.open('x') as output:
        json.dump({'token': token, 'operator': int(operator)}, output)
        output.write('\n')
    os.replace(temporary, path)
    print('Telegram saved. Start ./murashka telegram, then open a private chat with your bot.')


class Telegram:
    def __init__(self, store, origin, token, operator):
        self.store = store
        self.origin = origin
        self.token = token
        self.operator = operator

    def reply(self, update, now):
        message = update.get('message', {})
        chat, sender = message.get('chat', {}), message.get('from', {})
        text = message.get('text')
        if not (
            chat.get('type') == 'private' and chat.get('id') == self.operator
            and sender.get('id') == self.operator and isinstance(text, str)
            and isinstance(message.get('date'), int) and -10 <= now - message['date'] <= 120
        ):
            return None
        command, _, argument = text.strip().partition(' ')
        command, argument = command.lower(), argument.strip()
        if command in ('/start', '/help'):
            return 'Murashka Remote SSH\n\n' + COMMANDS
        if command == '/hosts':
            hosts = self.store.targets()
            return '\n'.join(str(host['id']) + ' · ' + host['name'] for host in hosts) or 'Add a host in the owner workspace first.'
        if command in ('/status', '/connect'):
            if not argument.isdecimal() or len(argument) > 12:
                return 'Usage: ' + command + ' HOST_ID. Use /hosts to find IDs.'
            try:
                target = self.store.target(int(argument))
            except ValueError:
                return 'Unknown host. Use /hosts to find IDs.'
            if command == '/connect':
                grant = self.store.grant(target['id'], 'guest', 1800)
                created = {ident: expiry for ident, expiry in self.store.setting('telegram-grants', {}).items()
                           if expiry > now}
                if len(created) >= 20:
                    self.store.revoke(grant['id'])
                    return 'The bot already has 20 active links. Revoke one or wait for expiry.'
                created[grant['id']] = grant['expires']
                self.store.set('telegram-grants', created)
                return (target['name'] + ' · expires in 30 minutes\n\n' + self.origin + '/#g='
                        + grant['id'] + '.' + grant['token'] + '\nPassword: ' + grant['password']
                        + '\n\nRevoke: /revoke ' + grant['id'])
            row = self.store.db.execute('SELECT value,checked FROM metrics WHERE target=?', (target['id'],)).fetchone()
            summary = 'No resource sample yet. Open Monitoring in the browser.'
            if row:
                sample = json.loads(row[0])
                age = max(0, int(now - row[1]) // 60)
                metrics = ['{} {}%'.format(label, sample[key]) for key, label in
                           (('cpu', 'CPU'), ('ram', 'RAM'), ('disk', 'Disk'))
                           if isinstance(sample.get(key), (int, float))]
                summary = f'Sample age: {age} min\n' + ' · '.join(metrics)
            has_review_table = self.store.db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_reviews'"
            ).fetchone()
            if has_review_table:
                review = self.store.db.execute('SELECT MAX(created) FROM host_reviews WHERE target=?', (target['id'],)).fetchone()[0]
                if review:
                    summary += '\nLatest security review: ' + time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(review))
            return target['name'] + '\n' + summary
        if command == '/revoke':
            created = self.store.setting('telegram-grants', {})
            if argument not in created:
                return 'Unknown bot-issued grant. Use the local CLI for other workspace links.'
            self.store.revoke(argument)
            created.pop(argument)
            self.store.set('telegram-grants', created)
            return 'Workspace revoked.'
        return COMMANDS

    async def api(self, client, method, body):
        async with client.post(
            'https://api.telegram.org/bot' + self.token + '/' + method,
            json=body, allow_redirects=False,
        ) as response:
            if response.status == 401:
                raise ValueError('Telegram rejected the bot token. Run telegram-setup again.')
            if response.status == 409:
                raise ValueError('Telegram reports a competing poller or an active webhook. Use a dedicated bot.')
            if response.status != 200:
                raise OSError('Telegram API returned HTTP ' + str(response.status))
            data = await response.json()
            if not data.get('ok'):
                raise OSError('Telegram API rejected the request.')
            return data['result']

    async def run(self):
        offset = self.store.setting('telegram-offset', 0)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as client:
            while True:
                try:
                    updates = await self.api(client, 'getUpdates', {
                        'offset': offset, 'timeout': 25, 'allowed_updates': ['message'],
                    })
                    for update in updates:
                        offset = max(offset, update['update_id'] + 1)
                        self.store.set('telegram-offset', offset)
                        reply = self.reply(update, time.time())
                        if reply:
                            await self.api(client, 'sendMessage', {
                                'chat_id': self.operator, 'text': reply[:4000],
                                'protect_content': True, 'link_preview_options': {'is_disabled': True},
                            })
                except (aiohttp.ClientError, OSError, TimeoutError):
                    print('Telegram request failed. Retrying in 5 seconds.', flush=True)
                    await asyncio.sleep(5)


def run(state, origin):
    path = state / 'telegram.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('Telegram configuration must be a private regular file.')
    config = json.loads(path.read_text())
    store = Store(state / 'gateway.sqlite', (state / 'fernet-key').read_bytes().strip())
    try:
        asyncio.run(Telegram(store, origin, config['token'], config['operator']).run())
    finally:
        store.db.close()
