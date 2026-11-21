#!/usr/bin/env python3
"""Temporary localhost TCP client bridge; Python standard library, Windows/Mac/Linux."""
import argparse,asyncio,base64,contextlib,hashlib,json,secrets,ssl,struct,time
from pathlib import Path
from urllib.parse import urlsplit
GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
async def frame(reader):
 h=await reader.readexactly(2);n=h[1]&127
 if not h[0]&128 or h[0]&112 or h[1]&128:raise ValueError('Invalid WebSocket frame')
 if n==126:n=struct.unpack('!H',await reader.readexactly(2))[0]
 elif n==127:n=struct.unpack('!Q',await reader.readexactly(8))[0]
 if n>1024*1024 or (h[0]&15>=8 and n>125):raise ValueError('Oversized frame')
 return h[0]&15,await reader.readexactly(n)
async def send(writer,op,data,lock):
 n=len(data);mask=secrets.token_bytes(4);head=bytes([128|op,128|n]) if n<126 else bytes([128|op,254])+struct.pack('!H',n) if n<65536 else bytes([128|op,255])+struct.pack('!Q',n)
 async with lock:writer.write(head+mask+bytes(v^mask[i%4] for i,v in enumerate(data)));await writer.drain()
async def connection(reader,writer,config):
 remote=None;tasks=[]
 try:
  if time.time()>=config['expires']:raise ValueError('Bridge link expired; download a new ZIP')
  u=urlsplit(config['url'])
  if u.scheme!='wss' or u.username or u.password:raise ValueError('A trusted WSS gateway is required')
  r,remote=await asyncio.wait_for(asyncio.open_connection(u.hostname,u.port or 443,ssl=ssl.create_default_context(),server_hostname=u.hostname),20);key=base64.b64encode(secrets.token_bytes(16)).decode()
  remote.write(('GET '+u.path+('?' + u.query if u.query else '')+' HTTP/1.1\r\nHost: '+u.netloc+'\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: '+key+'\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\nUser-Agent: Murashka-Desktop/1.0\r\nAuthorization: Bearer '+config['token']+'\r\n\r\n').encode());await remote.drain();headers=await asyncio.wait_for(r.readuntil(b'\r\n\r\n'),20)
  fields={s.split(':',1)[0].lower():s.split(':',1)[1].strip() for s in headers.decode().split('\r\n')[1:] if ':' in s}
  if not headers.startswith(b'HTTP/1.1 101') or fields.get('sec-websocket-accept')!=base64.b64encode(hashlib.sha1((key+GUID).encode()).digest()).decode():raise ValueError('Gateway refused bridge; check expiry or workspace revocation')
  lock=asyncio.Lock()
  async def up():
   while data:=await reader.read(32768):await send(remote,2,data,lock)
  async def down():
   while True:
    op,data=await frame(r)
    if op==2:writer.write(data);await writer.drain()
    elif op==9:await send(remote,10,data,lock)
    elif op==8:return
    elif op!=10:raise ValueError('Unexpected WebSocket message')
  tasks=[asyncio.create_task(up()),asyncio.create_task(down())];done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
  for task in done:task.result()
 except Exception as ex:print('Bridge:',str(ex),flush=True)
 finally:
  for task in tasks:task.cancel()
  await asyncio.gather(*tasks,return_exceptions=True)
  for stream in (writer,remote):
   if stream:
    stream.close()
    with contextlib.suppress(Exception):await stream.wait_closed()
async def main(config):
 server=await asyncio.start_server(lambda r,w:connection(r,w,config),'127.0.0.1',int(config['local_port']))
 print('Connect your '+config['protocol'].upper()+' client to 127.0.0.1:'+str(config['local_port'])+'. Keep this window open. Ctrl-C stops the bridge.',flush=True)
 async with server:await asyncio.sleep(max(0,config['expires']-time.time()))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--config',default='connection.json');a=p.parse_args()
 try:asyncio.run(main(json.loads(Path(a.config).read_text())))
 except KeyboardInterrupt:pass
