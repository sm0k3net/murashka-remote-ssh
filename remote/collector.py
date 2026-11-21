"""Executed via SSH on Linux; no daemon, installation, command arguments or environments collected."""
import os,json,time,shutil
from pathlib import Path

def ticks():
 a=[int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]];return sum(a),a[3]+a[4]
def processes():
 out={}
 for p in Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   raw=(p/'stat').read_text();v=raw[raw.rindex(')')+2:].split();out[int(p.name)]=(raw[raw.index('(')+1:raw.rindex(')')][:30],int(v[11])+int(v[12]),int(v[19]),max(0,int(v[21]))*os.sysconf('SC_PAGE_SIZE')/1024**2,os.stat(p).st_uid,int(v[17]),int(v[16]))
  except (OSError,ValueError,IndexError):pass
 return out
def cgroup_cpu():
 try:return int(dict(line.split() for line in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())['usage_usec'])
 except (OSError,ValueError,KeyError):return None
cg_before=cgroup_cpu()
before=processes();a=ticks();started=time.monotonic();time.sleep(.5);b=ticks();after=processes();elapsed=time.monotonic()-started
mem={k:int(v.strip().split()[0])*1024 for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())};disk=shutil.disk_usage('/');cpus=os.cpu_count() or 1;load=os.getloadavg();rows=[]
for pid,p in after.items():
 old=before.get(pid);cpu=max(0,(p[1]-old[1])/os.sysconf('SC_CLK_TCK')/elapsed*100) if old and old[2]==p[2] else 0
 rows.append({'pid':pid,'name':p[0],'cpu':round(cpu,1),'ram_mb':round(p[3],1),'started':p[2],'uid':p[4],'threads':p[5],'nice':p[6]})
result={'cpu':round(max(0,100*(1-(b[1]-a[1])/max(1,b[0]-a[0]))),1),'cpus':cpus,'ram':round(100*(1-mem['MemAvailable']/mem['MemTotal']),1),'ram_total':mem['MemTotal'],'ram_used':mem['MemTotal']-mem['MemAvailable'],'swap_total':mem.get('SwapTotal',0),'swap_used':mem.get('SwapTotal',0)-mem.get('SwapFree',0),'disk':round(100*disk.used/disk.total,1),'disk_total':disk.total,'disk_used':disk.used,'disk_free':disk.free,'loads':load,'load':load[0]/cpus,'uptime':float(Path('/proc/uptime').read_text().split()[0]),'top':sorted(rows,key=lambda p:(p['cpu'],p['ram_mb']),reverse=True)[:10]}
result['processes']=sorted(rows,key=lambda p:(p['cpu'],p['ram_mb']),reverse=True)[:50]
result['boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
net=[line.split() for line in Path('/proc/net/dev').read_text().splitlines()[2:] if not line.strip().startswith('lo:')]
result['network']={'rx_bytes':sum(int(v[1]) for v in net),'tx_bytes':sum(int(v[9]) for v in net)}
# Respect cgroup v2 limits in containers; host RAM is misleading on shared runtimes.
try:
 limit=Path('/sys/fs/cgroup/memory.max').read_text().strip()
 if limit!='max' and 0<int(limit)<result['ram_total']:
  used=int(Path('/sys/fs/cgroup/memory.current').read_text());result.update(ram_total=int(limit),ram_used=used,ram=round(min(100,100*used/int(limit)),1))
 quota,period=Path('/sys/fs/cgroup/cpu.max').read_text().split()
 if quota!='max':
  cores=float(quota)/float(period);cg_after=cgroup_cpu()
  if cg_before is not None and cg_after is not None:result['cpu']=round(min(100,max(0,(cg_after-cg_before)/1e6/elapsed/cores*100)),1)
except (OSError,ValueError,ZeroDivisionError):pass
result['sampled_at']=time.time()
# Optional /proc counters only; no expensive shell commands in the sampler.
result['process_count']=len(rows);result['threads']=sum(p['threads'] for p in rows)
try:
 st=os.statvfs('/');result['inodes']=round(100*(1-st.f_favail/max(1,st.f_files)),2)
 result['open_files']=int(Path('/proc/sys/fs/file-nr').read_text().split()[0])
except (OSError,ValueError):pass
try:
 result['pressure']={k:float(Path('/proc/pressure/'+k).read_text().splitlines()[0].split()[1].split('=')[1]) for k in ('cpu','memory','io')}
except (OSError,IndexError,ValueError):pass
ports=set();sockets=0
for filename in ('tcp','tcp6'):
 try:
  for line in Path('/proc/net/'+filename).read_text().splitlines()[1:]:
   v=line.split();sockets+=1
   if v[3]=='0A':ports.add(int(v[1].split(':')[1],16))
 except (OSError,IndexError,ValueError):pass
result['tcp_sockets']=sockets;result['listening_ports']=sorted(ports)[:100]
try:
 diskrows=[line.split() for line in Path('/proc/diskstats').read_text().splitlines()]
 diskrows=[v for v in diskrows if not v[2].startswith(('loop','ram','dm-')) and Path('/sys/block',v[2]).exists()]
 result['disk_io']={'read_bytes':sum(int(v[5])*512 for v in diskrows),'write_bytes':sum(int(v[9])*512 for v in diskrows)}
except (OSError,ValueError,IndexError):pass
result['reboot_required']=Path('/var/run/reboot-required').exists()
print(json.dumps(result))

