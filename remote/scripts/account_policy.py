"""Conservative access-account assessment. Never reads password hashes or key contents."""
import os,pwd,grp,stat
from pathlib import Path
CLOUD_LOGINS={'ubuntu','debian','ec2-user','admin','centos','rocky','almalinux','fedora','azureuser','opc','bitnami','cloud-user','core'}
ADMIN_GROUPS={'sudo','wheel','admin','google-sudoers','google-sudoers-groups','osadmin','adm-oslogin'}
NO_SHELL={'/usr/sbin/nologin','/sbin/nologin','/bin/false','/usr/bin/false',''}
def account_records(login):
 groups=list(grp.getgrall());records=[]
 for u in pwd.getpwall():
  if not (u.pw_uid==0 or 1000<=u.pw_uid<65534):continue
  memberships=sorted(g.gr_name for g in groups if u.pw_name in g.gr_mem or g.gr_gid==u.pw_gid);interactive=u.pw_shell not in NO_SHELL
  keys='unknown'
  try:
   p=Path(u.pw_dir)/'.ssh/authorized_keys';keys='present' if p.is_file() and p.stat().st_size>0 else 'not found'
  except OSError:pass
  reasons=[]
  if u.pw_uid==0:reasons.append('UID 0 / recovery access')
  if u.pw_name==login:reasons.append('Current gateway SSH login')
  if u.pw_name in CLOUD_LOGINS:reasons.append('Cloud-provider/default access account')
  if ADMIN_GROUPS.intersection(memberships):reasons.append('Administrative group membership')
  if u.pw_name.startswith('murashka-'):reasons.append('Managed service account')
  records.append({'name':u.pw_name,'uid':u.pw_uid,'gid':u.pw_gid,'shell':u.pw_shell,'home':u.pw_dir,'groups':memberships,'interactive':interactive,'authorized_keys':keys,'protected_reasons':reasons})
 usable=[r for r in records if r['uid']!=0 and r['interactive']]
 for r in usable:
  if len(usable)==1:r['protected_reasons'].append('Last non-root interactive account')
 for r in records:
  r['protected']=bool(r['protected_reasons']);r['assessment']='Access inventory; an interactive shell alone is not a vulnerability'
 return records

def require_account_change(login,user,alternative_confirmed=False):
 records=account_records(login);selected=next((r for r in records if r['name']==user),None)
 if not selected or selected['protected']:raise ValueError('Access account is protected: '+('; '.join(selected['protected_reasons']) if selected else 'system/unknown account'))
 alternatives=[r for r in records if r['name']!=user and r['uid']!=0 and r['interactive'] and (r['name'] in CLOUD_LOGINS or ADMIN_GROUPS.intersection(r['groups'])) and r['authorized_keys']=='present']
 if not alternative_confirmed or not alternatives:raise ValueError('An independently verified alternative non-root administrative login with an installed key is required. Use the terminal for exceptional account maintenance.')
 for process in Path('/proc').iterdir():
  if process.name.isdigit():
   try:
    if process.stat().st_uid==selected['uid']:raise ValueError('Account has running processes; review active access before modifying it')
   except FileNotFoundError:pass
 return selected
