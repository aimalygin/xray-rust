import ctypes,json,os,platform,re,socket,sys
from pathlib import Path
root=Path('/tmp/xray-v08-ss2022-mtu-20261004')
run='shadowsocks2022-native'
profile=str(root/run/'server.json')
matches=[]
for p in Path('/proc').glob('[0-9]*'):
 try:
  args=(p/'cmdline').read_bytes().split(b'\0')
  if profile.encode() in args and os.readlink(p/'exe')=='/usr/local/x-ui/bin/xray-linux-amd64':matches.append(int(p.name))
 except (FileNotFoundError,PermissionError):pass
assert len(matches)==1,matches
pid=matches[0];inodes=set()
for line in Path(f'/proc/{pid}/net/udp').read_text().splitlines()[1:]:
 parts=line.split()
 if int(parts[1].split(':')[1],16)==53053:inodes.add(parts[9])
fds=[]
for p in Path(f'/proc/{pid}/fd').iterdir():
 link=os.readlink(p);m=re.fullmatch(r'socket:\[(\d+)\]',link)
 if m and m[1] in inodes:fds.append(int(p.name))
assert len(fds)==1,fds
assert platform.machine()=='x86_64'
header=Path('/usr/include/x86_64-linux-gnu/asm/unistd_64.h').read_text();number=int(re.search(r'#define __NR_pidfd_getfd (\d+)',header)[1])
libc=ctypes.CDLL(None,use_errno=True);handle=os.pidfd_open(pid);fd=libc.syscall(number,handle,fds[0],0);os.close(handle)
if fd<0:raise OSError(ctypes.get_errno(),'pidfd_getfd on owned test process failed')
with socket.socket(fileno=fd) as s:
 before=s.getsockopt(socket.IPPROTO_IP,10)
 mode=os.environ.get('XRAY_TEST_DF_MODE')
 if mode is not None:
  assert mode in ('0','1');s.setsockopt(socket.IPPROTO_IP,10,int(mode))
 print(json.dumps({'testPID':pid,'fd':fds[0],'port':s.getsockname()[1],'before':before,'after':s.getsockopt(socket.IPPROTO_IP,10)}))
