"""SFTP workspace."""
import asyncio, contextlib, hashlib, posixpath, secrets, stat
import asyncssh
from aiohttp import web

MAX_FILE = 10 * 1024 * 1024
MAX_EDIT = 512 * 1024

class Workspace:

    def file_path(self, value):
        if not isinstance(value, str) or not value or len(value) > 4096 or ('\x00' in value):
            raise web.HTTPBadRequest(text='Invalid file path')
        return posixpath.normpath(value)

    async def files(self, request):
        grant = self.auth(request)
        ident = int(request.match_info['id'])
        self.scoped_target(grant, ident)
        action = request.match_info['action']
        path = self.file_path(request.query.get('path', '.'))
        conn = await self.connection(ident)
        try:
            async with conn.start_sftp_client() as sftp:
                path = await sftp.realpath(path)
                if action == 'list':
                    entries = []
                    truncated = False
                    async for item in sftp.scandir(path):
                        if item.filename in ('.', '..'):
                            continue
                        if len(entries) >= 1000:
                            truncated = True
                            break
                        a = item.attrs
                        entries.append({'name': item.filename, 'size': a.size or 0, 'mtime': a.mtime, 'directory': stat.S_ISDIR(a.permissions or 0), 'symlink': stat.S_ISLNK(a.permissions or 0), 'mode': stat.filemode(a.permissions or 0)})
                    return web.json_response({'path': path, 'parent': posixpath.dirname(path), 'entries': sorted(entries, key=lambda x: (not x['directory'], x['name'].lower())), 'truncated': truncated})
                attrs = await sftp.stat(path)
                if not stat.S_ISREG(attrs.permissions or 0):
                    raise web.HTTPBadRequest(text='Select a regular file')
                limit = MAX_EDIT if action == 'read' else MAX_FILE
                if (attrs.size or 0) > limit:
                    raise web.HTTPRequestEntityTooLarge(max_size=limit, actual_size=attrs.size)
                if action == 'read':
                    async with sftp.open(path, 'rb') as f:
                        data = await f.read(MAX_EDIT + 1)
                    if len(data) > MAX_EDIT:
                        raise web.HTTPBadRequest(text='Editor limit: 512 KB')
                    try:
                        text = data.decode('utf-8')
                    except UnicodeDecodeError:
                        raise web.HTTPBadRequest(text='Binary file: download it instead') from None
                    if '\x00' in text:
                        raise web.HTTPBadRequest(text='Binary file: download it instead')
                    return web.json_response({'path': path, 'text': text, 'revision': hashlib.sha256(data).hexdigest()})
                if action != 'download':
                    raise web.HTTPNotFound()
                from urllib.parse import quote
                response = web.StreamResponse(headers={'Content-Type': 'application/octet-stream', 'Content-Disposition': "attachment; filename*=UTF-8''" + quote(posixpath.basename(path), safe=''), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
                await response.prepare(request)
                count = 0
                async with sftp.open(path, 'rb') as f:
                    while True:
                        if not self.store.session(request.cookies.get('__Host-murashka-remote', '')):
                            break
                        block = await f.read(65536)
                        if not block:
                            break
                        count += len(block)
                        if count > MAX_FILE:
                            break
                        await response.write(block)
                await response.write_eof()
                return response
        except (asyncssh.SFTPError, OSError):
            raise web.HTTPBadRequest(text='File unavailable or permission denied by the SSH account') from None

    async def file_write(self, request):
        grant = self.auth(request, False, True)
        ident = int(request.match_info['id'])
        self.scoped_target(grant, ident)
        action = request.match_info['action']
        path = self.file_path(request.query.get('path', ''))
        conn = await self.connection(ident)
        lock = self.file_locks.setdefault((ident, path), asyncio.Lock())
        async with lock:
            try:
                async with conn.start_sftp_client() as sftp:
                    parent = await sftp.realpath(posixpath.dirname(path))
                    path = posixpath.join(parent, posixpath.basename(path))
                    temporary = path + '.murashka-' + secrets.token_hex(8)
                    old = None
                    try:
                        old = await sftp.lstat(path)
                    except asyncssh.SFTPNoSuchFile:
                        pass
                    if old and (not stat.S_ISREG(old.permissions or 0)):
                        raise web.HTTPBadRequest(text='Refusing to overwrite a directory or symbolic link')
                    if action == 'save':
                        body = await self.json(request)
                        data = str(body.get('text', '')).encode()
                        if len(data) > MAX_EDIT:
                            raise web.HTTPBadRequest(text='Editor limit: 512 KB')
                        if not old:
                            raise web.HTTPConflict(text='File no longer exists. Reload the directory.')
                        async with sftp.open(path, 'rb') as f:
                            current = await f.read(MAX_EDIT + 1)
                        if hashlib.sha256(current).hexdigest() != body.get('revision'):
                            raise web.HTTPConflict(text='File changed since you opened it. Reload before saving; your editor text is preserved.')
                    elif action == 'upload':
                        if old and request.headers.get('X-Overwrite') != 'yes':
                            raise web.HTTPConflict(text='A file with this name exists. Confirm replacement first.')
                        data = None
                    else:
                        raise web.HTTPNotFound()
                    try:
                        async with sftp.open(temporary, 'xb', attrs=asyncssh.SFTPAttrs(permissions=384)) as f:
                            if data is not None:
                                await f.write(data)
                            else:
                                size = 0
                                async for block in request.content.iter_chunked(65536):
                                    if not self.store.session(request.cookies.get('__Host-murashka-remote', '')):
                                        raise web.HTTPUnauthorized()
                                    size += len(block)
                                    if size > MAX_FILE:
                                        raise web.HTTPRequestEntityTooLarge(max_size=MAX_FILE, actual_size=size)
                                    await f.write(block)
                        if old:
                            await sftp.chmod(temporary, stat.S_IMODE(old.permissions))
                        if not self.store.session(request.cookies.get('__Host-murashka-remote', '')):
                            raise web.HTTPUnauthorized()
                        if old:
                            await sftp.posix_rename(temporary, path)
                        else:
                            await sftp.rename(temporary, path)
                    finally:
                        with contextlib.suppress(asyncssh.SFTPError):
                            await sftp.remove(temporary)
                    return web.json_response({'ok': True, 'path': path, 'revision': hashlib.sha256(data).hexdigest() if data is not None else None})
            except (asyncssh.SFTPError, OSError):
                raise web.HTTPBadRequest(text='Write failed: check directory permissions and SFTP support') from None
