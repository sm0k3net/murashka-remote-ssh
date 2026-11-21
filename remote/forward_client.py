#!/usr/bin/env python3
"""User-started expiring tunnel bridge; standard library only."""
import asyncio,json,time,urllib.request,urllib.error
from pathlib import Path
from desktop_client import connection,main as local_main
async def main(c):
 if not c.get('reverse'):return await local_main(c)
 tasks={}
 def pending():
  req=urllib.request.Request(c['pending_url'],headers={'Authorization':'Bearer '+c['token'],'User-Agent':'Murashka-Desktop/1.0'})
  with urllib.request.urlopen(req,timeout=15) as r:return json.load(r)
 async def serve(channel):
  try:
   r,w=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',c['service_port']),10)
   await connection(r,w,{**c,'url':c['url']+'?channel='+channel})
  except Exception:print('Local service unavailable; check its port.',flush=True)
 print('Serving your localhost:'+str(c['service_port'])+' through the remote SSH tunnel. Ctrl-C stops.',flush=True)
 try:
  while time.time()<c['expires']:
   try:
    for channel in await asyncio.to_thread(pending):
     if channel not in tasks and len(tasks)<8:tasks[channel]=asyncio.create_task(serve(channel))
    tasks={k:v for k,v in tasks.items() if not v.done()}
   except urllib.error.HTTPError as e:
    if e.code in (401,403):print('Bridge expired, revoked or blocked. Download a fresh bridge.');break
   except Exception:print('Gateway disconnected; retrying.',flush=True)
   await asyncio.sleep(2)
 finally:
  for t in tasks.values():t.cancel()
  await asyncio.gather(*tasks.values(),return_exceptions=True)
if __name__=='__main__':
 try:asyncio.run(main(json.loads(Path('connection.json').read_text())))
 except KeyboardInterrupt:pass
