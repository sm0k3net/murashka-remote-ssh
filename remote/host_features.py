"""Owner-only defensive host reviews and managed remote desktops."""
import asyncio
import html
import json
import logging
import secrets
import shlex
import string
import time
from pathlib import Path

import aiohttp
from aiohttp import web

from db import digest

ROOT = Path(__file__).resolve().parent
LOG = logging.getLogger(__name__)


class HostFeatures:
    def host_features_init(self):
        self.host_jobs = {}
        self.host_tasks = {}
        self.review_slot = asyncio.Semaphore(1)
        self.desktop_slot = asyncio.Semaphore(1)
        self.store.db.execute(
            'CREATE TABLE IF NOT EXISTS host_reviews (id TEXT PRIMARY KEY, target INTEGER, created REAL, report TEXT)'
        )

    def feature_routes(self, app):
        app.router.add_get('/api/host-review/{id}', self.host_review)
        app.router.add_post('/api/host-review/{id}', self.host_review)
        app.router.add_get('/api/host-review/{id}/report/{report}', self.review_file)
        app.router.add_get('/api/desktop/{id}', self.desktop_details)
        app.router.add_post('/api/desktop/{id}', self.desktop_details)
        app.router.add_post('/api/desktop/{id}/credentials', self.desktop_credentials)
        app.router.add_get('/api/desktop/{id}/ws', self.desktop_socket)
        app.router.add_get('/desktop/{id}', self.desktop_page)

    def feature_host(self, request):
        grant = self.auth(request, True, request.method == 'POST')
        host = int(request.match_info['id'])
        self.scoped_target(grant, host)
        return host, grant

    def queue_host_job(self, host, kind, callback):
        key = (host, kind)
        if key in self.host_tasks or len(self.host_tasks) >= 3:
            raise web.HTTPTooManyRequests(text='A host job is already active or the job limit has been reached.')
        status = self.host_jobs[key] = {'state': 'running', 'started': time.time()}

        async def work():
            try:
                slot = self.review_slot if kind == 'review' else self.desktop_slot
                async with slot:
                    await callback()
                status['state'] = 'done'
            except asyncio.CancelledError:
                status.update(state='interrupted', error='Gateway stopped. Check the host before retrying.')
                raise
            except (ValueError, TimeoutError) as error:
                status.update(state='error', error=str(error)[:250] or 'Operation timed out.')
            except Exception as error:
                LOG.warning('Host operation %s failed (%s)', kind, type(error).__name__)
                status.update(state='error', error='SSH operation failed. Check the host connection and permissions.')
            finally:
                self.host_tasks.pop(key, None)

        self.host_tasks[key] = asyncio.create_task(work())
        return status

    async def collect_review(self, host):
        connection = await self.connection(host)
        script = '\n'.join((ROOT / 'scripts' / name).read_text() for name in ('account_policy.py', 'security_collect.py'))
        async with asyncio.timeout(95), connection.create_process('python3 -c ' + shlex.quote(script)) as process:
            raw = await process.stdout.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('Host inventory exceeds the 1 MiB review limit.')
            result = await process.wait()
        if result.exit_status:
            raise ValueError('Collector could not run. Check Python 3, Linux and account permissions.')
        report = json.loads(raw)
        report['scope'] = 'Root host review' if report.get('uid') == 0 else 'Limited to SSH account permissions'
        baseline = self.store.setting('review-baseline-' + str(host))
        hashes = report.get('config_hashes', {})
        report['has_baseline'] = baseline is not None
        report['integrity_changes'] = []
        if baseline is not None:
            report['integrity_changes'] = [
                {'path': path, 'change': 'Changed' if path in baseline else 'Added'}
                for path, value in hashes.items() if baseline.get(path) != value
            ] + [{'path': path, 'change': 'Missing or unreadable'} for path in baseline if path not in hashes]
        self.store.target(host)
        with self.store.db:
            self.store.db.execute(
                'INSERT INTO host_reviews VALUES (?,?,?,?)',
                (secrets.token_hex(12), host, time.time(), self.store.seal(report)),
            )
            self.store.db.execute(
                'DELETE FROM host_reviews WHERE target=? AND id NOT IN '
                '(SELECT id FROM host_reviews WHERE target=? ORDER BY created DESC LIMIT 5)', (host, host)
            )

    def review_record(self, host, ident):
        row = self.store.db.execute('SELECT report FROM host_reviews WHERE target=? AND id=?', (host, ident)).fetchone()
        if not row:
            raise web.HTTPNotFound(text='Review not found.')
        return self.store.unseal(row[0])

    async def host_review(self, request):
        host, _ = self.feature_host(request)
        if request.method == 'POST':
            body = await self.json(request)
            if body.get('action') == 'run':
                return web.json_response(self.queue_host_job(host, 'review', lambda: self.collect_review(host)), status=202)
            if body.get('action') == 'baseline' and body.get('confirm') is True:
                report = self.review_record(host, body.get('report'))
                if not report.get('config_hashes'):
                    raise web.HTTPBadRequest(text='The selected review has no readable configuration hashes.')
                self.store.set('review-baseline-' + str(host), report['config_hashes'])
                return web.json_response({'ok': True})
            raise web.HTTPBadRequest(text='Unknown review action.')
        rows = self.store.db.execute(
            'SELECT id,created,report FROM host_reviews WHERE target=? ORDER BY created DESC LIMIT 5', (host,)
        ).fetchall()
        summaries = []
        for row in rows:
            report = self.store.unseal(row['report'])
            summaries.append({
                'id': row['id'], 'created': row['created'], 'scope': report['scope'],
                'findings': report.get('findings', [])[:120], 'changes': report.get('integrity_changes', []),
                'coverage': report.get('coverage', []), 'baseline': report.get('has_baseline', False),
            })
        return web.json_response({'job': self.host_jobs.get((host, 'review')), 'reports': summaries})

    async def review_file(self, request):
        host, _ = self.feature_host(request)
        report = self.review_record(host, request.match_info['report'])
        name = self.store.target(host)['name']
        esc = lambda value: html.escape(str(value))
        sections = [
            ('Findings', '\n'.join(item['severity'].upper() + ' | ' + item['title'] + '\n' + item['detail']
                                  for item in report.get('findings', []))),
            ('Coverage', '\n'.join(report.get('coverage', []))),
            ('Integrity changes', '\n'.join(item['change'] + ' | ' + item['path']
                                           for item in report.get('integrity_changes', []))),
            ('Configuration fingerprints', json.dumps(report.get('config_hashes', {}), indent=2)),
            ('Accounts', json.dumps(report.get('users', []), indent=2)),
            ('SSH policy', json.dumps(report.get('ssh_effective', {}), indent=2)),
            ('Local package update candidates', '\n'.join(report.get('available_updates', []))),
            ('Listening sockets', report.get('listeners', '')),
            ('Services', report.get('services', '')),
            ('Firewall', report.get('firewall', '')),
        ]
        navigation = ''.join(f'<a href="#section-{i}">{esc(title)}</a>' for i, (title, _) in enumerate(sections))
        content = ''.join(f'<section id="section-{i}"><h2>{esc(title)}</h2><pre>{esc(data or "No entries captured.")}</pre></section>'
                          for i, (title, data) in enumerate(sections))
        document = (
            '<!doctype html><html lang="en"><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">'
            '<title>Murashka Remote SSH · Security review</title><style>'
            'body{max-width:65rem;margin:2rem auto;padding:0 1rem;font:16px/1.55 system-ui;background:#f5f7f9;color:#172838}'
            'a{display:inline-block;margin:.4rem;color:#205087}section{margin:1rem 0;padding:1rem;background:white;border:1px solid #d8e0e8;border-radius:10px}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere}h1,h2{line-height:1.15}</style>'
            f'<body><h1>Security review · {esc(name)}</h1><p>{esc(report["scope"])}</p>'
            '<p>Read-only observations from the target. Review the coverage before acting on findings.</p>'
            f'<nav aria-label="Report sections">{navigation}</nav>{content}</body></html>'
        )
        return web.Response(text=document, content_type='text/html', headers={
            'Content-Disposition': 'attachment; filename="murashka-security-review.html"',
        })

    async def provision_desktop(self, host, action, variant):
        connection = await self.connection(host)
        identity = await connection.run('id -u', check=True, timeout=8)
        prefix = '' if identity.stdout.strip() == '0' else 'sudo -n '
        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        script = (ROOT / 'scripts/desktop_service.py').read_text()
        result = await connection.run(
            prefix + 'python3 -c ' + shlex.quote(script),
            input=json.dumps({'action': action, 'variant': variant, 'password': password}),
            timeout=900,
        )
        try:
            values = json.loads(result.stdout)
        except ValueError:
            raise ValueError('Desktop operation returned no result. Check non-interactive sudo, Python 3 and systemd.') from None
        if result.exit_status:
            raise ValueError(values.get('error', 'Desktop operation failed.'))
        self.store.target(host)
        key = 'desktop-password-' + str(host)
        if action == 'install':
            self.store.set(key, self.store.seal(password))
        elif action == 'remove':
            self.store.set(key, None)

    async def desktop_details(self, request):
        host, _ = self.feature_host(request)
        if request.method == 'GET':
            return web.json_response({'port': 5901, 'job': self.host_jobs.get((host, 'desktop')),
                                      'managed_credentials': bool(self.store.setting('desktop-password-' + str(host)))})
        body = await self.json(request)
        action, variant = body.get('action'), body.get('variant')
        if action not in ('install', 'restart', 'remove') or body.get('confirm') is not True:
            raise web.HTTPBadRequest(text='Review and confirm a managed desktop operation.')
        if action == 'install' and variant not in ('openbox', 'xfce'):
            raise web.HTTPBadRequest(text='Choose Openbox or Xfce.')
        return web.json_response(self.queue_host_job(
            host, 'desktop', lambda: self.provision_desktop(host, action, variant)
        ), status=202)

    async def desktop_credentials(self, request):
        host, _ = self.feature_host(request)
        password = self.store.setting('desktop-password-' + str(host))
        return web.json_response({'password': self.store.unseal(password) if password else None})

    async def desktop_page(self, request):
        self.feature_host(request)
        return web.FileResponse(ROOT / 'static/desktop.html')

    async def desktop_socket(self, request):
        host, grant = self.feature_host(request)
        if not self.origin_ok(request):
            raise web.HTTPForbidden()
        if len(self.websockets) >= 24:
            raise web.HTTPTooManyRequests()
        port = int(request.query.get('port', '5901'))
        if port not in (5900, 5901):
            raise web.HTTPBadRequest(text='Use a loopback VNC display on port 5900 or 5901.')
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=1024 * 1024, compress=False)
        await ws.prepare(request)
        self.websockets[ws] = {
            'target': host, 'grant': grant['id'], 'session': digest(request.cookies['__Host-murashka-remote']),
        }
        writer = output = None
        try:
            connection = await self.connection(host)
            reader, writer = await asyncio.wait_for(connection.open_connection('127.0.0.1', port, encoding=None), 10)

            async def send():
                while data := await reader.read(65536):
                    await ws.send_bytes(data)
                await ws.close()

            output = asyncio.create_task(send())
            async for message in ws:
                if message.type == aiohttp.WSMsgType.BINARY:
                    writer.write(message.data)
                    await writer.drain()
        except Exception:
            await ws.close(code=1011, message=b'VNC unavailable. Check service, port and SSH forwarding.')
        finally:
            if output:
                output.cancel()
                await asyncio.gather(output, return_exceptions=True)
            if writer:
                writer.close()
            self.websockets.pop(ws, None)
        return ws
