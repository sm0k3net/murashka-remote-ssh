"""Bounded cross-host SFTP copies."""
import asyncio, contextlib, hashlib, json, posixpath, stat, time
import asyncssh
from aiohttp import web

MAX_BYTES = 256 * 1024**2
MAX_ITEMS = 5000

class FileJobs:

    async def fs_scan(self, sftp, path, limit=MAX_BYTES, allow_missing=False):
        path = self.file_path(path)
        parent = await sftp.realpath(posixpath.dirname(path))
        path = posixpath.normpath(posixpath.join(parent, posixpath.basename(path)))
        if path == '/':
            raise ValueError('Filesystem root is not a transfer/archive target')
        entries = []
        total = 0

        async def walk(p, relative='', depth=0):
            nonlocal total
            if depth > 30 or len(entries) >= MAX_ITEMS:
                raise ValueError('Tree limit: 5,000 entries / 30 levels')
            a = await sftp.lstat(p)
            mode = a.permissions or 0
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ValueError('Links and special files are not followed/copied; select a regular tree')
            size = a.size or 0 if stat.S_ISREG(mode) else 0
            total += size
            if total > limit:
                raise ValueError('Transfer exceeds the selected byte limit')
            entries.append({'path': p, 'relative': relative, 'directory': stat.S_ISDIR(mode), 'size': size, 'mtime': a.mtime, 'mode': stat.S_IMODE(mode) & 511})
            if stat.S_ISDIR(mode):
                async for item in sftp.scandir(p):
                    if item.filename not in ('.', '..'):
                        await walk(posixpath.join(p, item.filename), posixpath.join(relative, item.filename), depth + 1)
        try:
            async with asyncio.timeout(60):
                await walk(path)
        except asyncssh.SFTPNoSuchFile:
            if not entries and allow_missing:
                return {'path': path, 'entries': [], 'bytes': 0, 'revision': None}
            raise
        revision = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
        return {'path': path, 'entries': entries, 'bytes': total, 'revision': revision}

    def transfer_view(self, run):
        return {k: run.get(k) for k in ('id', 'kind', 'state', 'source_host', 'destination_host', 'source', 'destination', 'created', 'finished', 'bytes_done', 'bytes', 'entries', 'log', 'result', 'error', 'rule')}

    def transfer_save(self, run):
        view = self.transfer_view(run)
        with self.store.db:
            self.store.db.execute('INSERT OR REPLACE INTO file_job_history VALUES (?,?,?,?,?,?,?,?)', (run['id'], run['kind'], run['state'], run['source_host'], run['destination_host'], self.store.seal(view), run['created'], run.get('finished')))

    def transfer_log(self, run, text):
        run['log'] = (run.get('log', '') + str(text) + '\n')[-32000:]
        if time.monotonic() - run.get('_saved', 0) > 1:
            run['_saved'] = time.monotonic()
            self.transfer_save(run)

    def transfer_live(self, run):
        if run.get('rule'):
            row = self.store.db.execute('SELECT enabled FROM sync_rules WHERE id=?', (run['rule'],)).fetchone()
            return bool(row and row[0])
        return bool(self.store.session(run.get('cookie', '')))

    async def stream_copy(self, run):
        src = await self.connection(run['source_host'])
        dst = await self.connection(run['destination_host'])
        async with src.start_sftp_client() as a, dst.start_sftp_client() as b:
            scan = await self.fs_scan(a, run['source'], run['max_bytes'])
            target = await self.fs_scan(b, run['destination'], MAX_BYTES, True)
            if scan['revision'] != run['source_revision'] or target['revision'] != run['destination_revision']:
                raise ValueError('Source/destination changed after preview; create a fresh plan')
            if target['entries']:
                raise ValueError('Destination exists; copy will not overwrite it')
            started = time.monotonic()
            for entry in scan['entries']:
                if not self.transfer_live(run):
                    raise ValueError('File job access expired or was revoked')
                path = posixpath.join(run['destination'], entry['relative']) if entry['relative'] else run['destination']
                if entry['directory']:
                    await b.mkdir(path, attrs=asyncssh.SFTPAttrs(permissions=448))
                    continue
                temp = path + '.murashka-transfer-' + run['id']
                try:
                    async with a.open(entry['path'], 'rb') as source, b.open(temp, 'xb', attrs=asyncssh.SFTPAttrs(permissions=384)) as dest:
                        count = 0
                        while (block := (await source.read(65536))):
                            if not self.transfer_live(run):
                                raise ValueError('Access expired during copy')
                            count += len(block)
                            run['bytes_done'] += len(block)
                            if count > entry['size'] or run['bytes_done'] > run['max_bytes']:
                                raise ValueError('Source grew beyond the approved byte limit')
                            await dest.write(block)
                            self.transfer_log(run, 'Transferred ' + str(run['bytes_done']) + ' / ' + str(run['bytes']) + ' bytes')
                            delay = run['bytes_done'] / (run['bandwidth_kib'] * 1024) - (time.monotonic() - started)
                            if delay > 0:
                                await asyncio.sleep(min(delay, 1))
                    after = await a.stat(entry['path'])
                    if count != entry['size'] or after.size != entry['size'] or after.mtime != entry['mtime']:
                        raise ValueError('Source changed during copy; partial file not published')
                    with contextlib.suppress(asyncssh.SFTPError):
                        await b.setstat(temp, asyncssh.SFTPAttrs(permissions=entry['mode'], mtime=entry['mtime']))
                    try:
                        await b.lstat(path)
                    except asyncssh.SFTPNoSuchFile:
                        pass
                    else:
                        raise ValueError('Destination appeared during copy; refusing replacement')
                    await b.rename(temp, path)
                finally:
                    with contextlib.suppress(asyncssh.SFTPError):
                        await b.remove(temp)
            for entry in reversed(scan['entries']):
                if entry['directory']:
                    path = posixpath.join(run['destination'], entry['relative']) if entry['relative'] else run['destination']
                    with contextlib.suppress(asyncssh.SFTPError):
                        await b.chmod(path, entry['mode'])
            return {'copied_entries': len(scan['entries']), 'bytes': run['bytes_done'], 'note': 'Copy completed. A failed/cancelled directory job can leave already completed files; source files are never removed.'}

    def copy_init(self):
        self.transfer_tasks = {}
        self.transfer_slots = asyncio.Semaphore(2)
        self.store.db.execute(
            "CREATE TABLE IF NOT EXISTS file_job_history("
            "id TEXT PRIMARY KEY, kind TEXT, state TEXT, source INTEGER, destination INTEGER,"
            "body TEXT, created REAL, finished REAL)"
        )
        for row in self.store.db.execute("SELECT body FROM file_job_history WHERE state IN ('queued','running')"):
            result = self.store.unseal(row[0])
            result.update(state='interrupted', finished=time.time(), error='Gateway restarted. Inspect the destination before retrying.')
            self.transfer_save(result)

    async def copies(self, request):
        self.auth(request, True, request.method == 'POST')
        cookie = request.cookies['__Host-murashka-remote']
        if request.method == 'GET':
            rows = self.store.db.execute('SELECT body FROM file_job_history ORDER BY created DESC LIMIT 30')
            return web.json_response([self.store.unseal(row[0]) for row in rows])
        body = await self.json(request)
        if body.get('action') == 'cancel':
            task = self.transfer_tasks.get(str(body.get('id', '')))
            if task:
                task.cancel()
            return web.json_response({'ok': True})
        if body.get('confirm') is not True:
            raise web.HTTPBadRequest(text='Confirm the source and destination first.')
        if len(self.transfer_tasks) >= 6:
            raise web.HTTPTooManyRequests(text='File queue is full.')
        import secrets
        source_host, destination_host = int(body['source_host']), int(body['destination_host'])
        self.store.target(source_host)
        self.store.target(destination_host)
        run = dict(
            id=secrets.token_hex(12), kind='copy', state='queued', cookie=cookie, source_host=source_host,
            destination_host=destination_host, source=self.file_path(body['source']),
            destination=self.file_path(body['destination']), created=time.time(), bytes_done=0, log='',
            max_bytes=MAX_BYTES, bandwidth_kib=2048,
        )
        self.transfer_save(run)
        task = asyncio.create_task(self.execute_copy(run))
        self.transfer_tasks[run['id']] = task

        def finished(done):
            self.transfer_tasks.pop(run['id'], None)
            if done.cancelled() and run['state'] == 'queued':
                run.update(state='cancelled', finished=time.time())
                self.transfer_save(run)

        task.add_done_callback(finished)
        return web.json_response(self.transfer_view(run))

    async def execute_copy(self, run):
        try:
            async with self.transfer_slots, asyncio.timeout(600):
                if not self.transfer_live(run):
                    raise ValueError('Workspace expired or was revoked.')
                source = await self.connection(run['source_host'])
                destination = await self.connection(run['destination_host'])
                async with source.start_sftp_client() as a, destination.start_sftp_client() as b:
                    original = await self.fs_scan(a, run['source'])
                    target = await self.fs_scan(b, run['destination'], allow_missing=True)
                if target['entries']:
                    raise ValueError('The destination already exists. Choose another path.')
                if run['source_host'] == run['destination_host'] and target['path'].startswith(original['path'].rstrip('/') + '/'):
                    raise ValueError('The destination cannot be inside the source.')
                run.update(
                    state='running', source=original['path'], destination=target['path'],
                    source_revision=original['revision'], destination_revision=target['revision'],
                    bytes=original['bytes'], entries=len(original['entries']),
                )
                self.transfer_save(run)
                run['result'] = await self.stream_copy(run)
                run['state'] = 'done'
        except asyncio.CancelledError:
            run.update(state='cancelled', error='Inspect the destination for completed files.')
        except (ValueError, asyncssh.Error, web.HTTPException) as exc:
            run.update(state='error', error=str(exc)[:250])
        except (TimeoutError, OSError):
            run.update(state='error', error='Transfer timed out or the endpoint could not be reached.')
        finally:
            run['finished'] = time.time()
            self.transfer_save(run)
            with self.store.db:
                self.store.db.execute("DELETE FROM file_job_history WHERE state NOT IN ('queued','running') AND id NOT IN (SELECT id FROM file_job_history ORDER BY created DESC LIMIT 30)")
