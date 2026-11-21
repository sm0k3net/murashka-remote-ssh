"""SQLite storage and encrypted SSH credentials."""
import hashlib, json, secrets, sqlite3, time
from cryptography.fernet import Fernet

TTL = (1800, 7200, 43200)

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=1, maxmem=64*1024*1024).hex()

class Store:

    def __init__(self, path, key):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.cipher = Fernet(key)
        self.db.executescript('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;\n  CREATE TABLE IF NOT EXISTS targets(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,host TEXT,port INTEGER,username TEXT,hostkey TEXT,auth TEXT,enabled INTEGER DEFAULT 1);\n  CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,target INTEGER,role TEXT,token TEXT,salt TEXT,password TEXT,expires REAL,revoked INTEGER DEFAULT 0,created REAL);\n  CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,grant_id TEXT,expires REAL);\n  CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);\n  CREATE TABLE IF NOT EXISTS metrics(target INTEGER PRIMARY KEY,value TEXT,checked REAL);\n  CREATE TABLE IF NOT EXISTS monitor_state(target INTEGER PRIMARY KEY,value TEXT);\n  CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,target INTEGER,text TEXT,created REAL,acked INTEGER DEFAULT 0);\n  CREATE TABLE IF NOT EXISTS ai_usage(day TEXT PRIMARY KEY,calls INTEGER);\n  ')

    def setting(self, key, default=None):
        r = self.db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return json.loads(r[0]) if r else default

    def set(self, key, value):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', (key, json.dumps(value)))

    def seal(self, value):
        return self.cipher.encrypt(json.dumps(value).encode()).decode()

    def unseal(self, value):
        return json.loads(self.cipher.decrypt(value.encode()))

    def target(self, ident, secret=False):
        r = self.db.execute('SELECT * FROM targets WHERE id=?', (int(ident),)).fetchone()
        if not r:
            raise ValueError('Unknown target')
        result = dict(r)
        if secret:
            result['auth'] = self.unseal(result['auth'])
        else:
            result.pop('auth', None)
        return result

    def targets(self):
        return [self.target(r[0]) for r in self.db.execute('SELECT id FROM targets ORDER BY id')]

    def add_target(self, data):
        if len(self.targets()) >= 10:
            raise ValueError('Limit: 10 servers')
        with self.db:
            return self.db.execute('INSERT INTO targets(name,host,port,username,hostkey,auth) VALUES (?,?,?,?,?,?)', (data['name'], data['host'], data['port'], data['username'], data['hostkey'], self.seal(data['auth']))).lastrowid

    def grant(self, target, role, ttl):
        if role == 'guest' or target != 0:
            self.target(target)
        if role not in ['owner', 'guest'] or ttl not in TTL:
            raise ValueError('Invalid access scope')
        ident = secrets.token_urlsafe(12)
        token = secrets.token_urlsafe(32)
        password = secrets.token_urlsafe(12)
        salt = secrets.token_hex(16)
        expires = time.time() + ttl
        with self.db:
            self.db.execute('INSERT INTO grants VALUES (?,?,?,?,?,?,?,0,?)', (ident, target, role, digest(token), salt, password_hash(password, salt), expires, time.time()))
        return {'id': ident, 'token': token, 'password': password, 'expires': expires, 'role': role, 'target': target}

    def valid_grant(self, ident):
        r = self.db.execute('SELECT * FROM grants WHERE id=? AND revoked=0 AND expires>?', (ident, time.time())).fetchone()
        return dict(r) if r else None

    def session(self, token):
        r = self.db.execute('SELECT grant_id FROM sessions WHERE token=? AND expires>?', (digest(token), time.time())).fetchone()
        return self.valid_grant(r[0]) if r else None

    def login(self, grant):
        token = secrets.token_urlsafe(32)
        with self.db:
            self.db.execute('DELETE FROM sessions WHERE grant_id=?', (grant['id'],))
            self.db.execute('INSERT INTO sessions VALUES (?,?,?)', (digest(token), grant['id'], grant['expires']))
        return token

    def revoke(self, ident):
        with self.db:
            self.db.execute('UPDATE grants SET revoked=1 WHERE id=?', (ident,))
            self.db.execute('DELETE FROM sessions WHERE grant_id=?', (ident,))
