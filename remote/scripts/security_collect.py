"""Bounded read-only Linux audit. No shadow data, private keys or config contents returned."""
import hashlib,json,os,pwd,re,shutil,stat,subprocess,time
from pathlib import Path

# account_records is supplied by account_policy.py in the same read-only collector.

def command(args,timeout=15):
 try:
  p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,text=True);return p.stdout[:512000],p.returncode
 except (OSError,subprocess.TimeoutExpired):return '',-1
release={}
for line in Path('/etc/os-release').read_text().splitlines():
 if '=' in line:k,v=line.split('=',1);release[k]=v.strip('"')
report={'os':release,'created':time.time(),'uid':os.geteuid(),'findings':[],'coverage':[]}
def finding(kind,title,detail):
 item={'severity':kind,'title':title,'detail':detail}
 report['findings'].append(item)
login=pwd.getpwuid(os.geteuid()).pw_name
users=account_records(login);report['users']=users;report['account_policy_version']=2;report['ssh_login']=login
for u in users:
 if u['uid']==0 and u['name']!='root':finding('high','Additional UID 0 account',u['name']+' has root-equivalent UID. Review provenance; do not remove access without a verified recovery path.')

ports,rc=command(['ss','-H','-lntup']);report['listeners']=ports[:32000];report['coverage'].append('Listening ports: '+('available' if rc==0 else 'ss unavailable'))
services,rc=command(['systemctl','list-units','--type=service','--state=running,failed','--no-pager','--no-legend']);report['services']=services[:32000]
failed,rc=command(['systemctl','--failed','--no-legend','--plain']);report['failed_services']=failed[:8000]
if failed.strip():finding('medium','Failed services',failed[:2000])
sshd=shutil.which('sshd') or '/usr/sbin/sshd';config,rc=command([sshd,'-T']);effective={}
for line in config.splitlines():
 k,_,v=line.partition(' ')
 if k in ('permitrootlogin','passwordauthentication','permitemptypasswords','pubkeyauthentication','maxauthtries','x11forwarding'):effective[k]=v
report['ssh_effective']=effective;report['coverage'].append('sshd -T: '+('available; Match rules may differ' if rc==0 else 'unavailable; root may be required'))
for key,bad,severity in [('permitrootlogin','yes','medium'),('permitemptypasswords','yes','high'),('passwordauthentication','yes','medium')]:
 if effective.get(key)==bad:finding(severity,'SSH '+key+' is '+bad,'Review remote account access before changing SSH policy.')
report['config_hashes']={};report['config_unreadable']=[];paths=[Path('/etc/passwd'),Path('/etc/group'),Path('/etc/ssh/sshd_config'),Path('/etc/sudoers')]
for folder in ('/etc/ssh/sshd_config.d','/etc/sudoers.d','/etc/systemd/system'):
 try:paths.extend(sorted(Path(folder).glob('*'))[:100])
 except OSError:pass
for p in paths[:150]:
 try:
  st=p.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_size>1024*1024:continue
  report['config_hashes'][str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
  if st.st_mode&0o002:finding('high','World-writable configuration',str(p))
 except OSError:report['config_unreadable'].append(str(p));continue
report['coverage'].append('Unreadable configuration paths: '+str(len(report['config_unreadable'])))
report['coverage'].append('Integrity: SHA-256 hashes of selected readable configuration files. Review and approve a baseline before making comparisons.')
report['package_count']=0
if shutil.which('dpkg-query'):
 installed,rc=command(['dpkg-query','-W','-f=${db:Status-Status}\n']);report['package_count']=installed.splitlines().count('installed') if rc==0 else None
 updates,rc=command(['apt-get','-s','upgrade'],30);report['available_updates']=[line[:300] for line in updates.splitlines() if line.startswith('Inst ')][:500];report['coverage'].append('APT update candidates use existing local indexes; audit does not refresh them' if rc==0 else 'APT update simulation failed; update candidates were not checked')
 for line in report['available_updates'][:100]:
  finding('medium' if '-security' in line else 'info','Package update available',line)
else:report['coverage'].append('Package update review unavailable for this package manager')
fw,rc=command(['ufw','status']);report['firewall']=fw[:8000] if rc==0 else 'UFW not available/readable; provider firewall is outside this audit'
report['reboot_required']=Path('/var/run/reboot-required').exists()
if report['reboot_required']:finding('medium','Reboot required','Schedule a maintenance window; no automatic reboot is performed.')
report['coverage'].append('No exploit tests, application dependency/container image scans, shadow/password reads or full filesystem integrity scan')
print(json.dumps(report))
