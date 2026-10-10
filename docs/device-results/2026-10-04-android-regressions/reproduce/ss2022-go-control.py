import hashlib,json,os,socket,struct,subprocess,time
from pathlib import Path
import drive as d

root=Path(os.environ.get('XRAY_CORE_ROOT', Path(__file__).resolve().parents[2])).resolve(); binary=root/'target/v08-comparison/bin/xray'
assert hashlib.sha256(binary.read_bytes()).hexdigest()=='fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99'
env=json.loads((d.ROOT/'fixture-ss2022-control/v07-probe.json').read_text()); log=d.ROOT/'fixture-ss2022-control.log'
def rows(run):
    found=[]
    for l in log.read_text().splitlines():
        try:r=json.loads(l)
        except ValueError:continue
        if r.get('id')==run:found.append(r)
    return found

def wait_row(run,kind,timeout):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        found=[r for r in rows(run) if r['backend']==kind]
        if found:return found[0]
        time.sleep(.03)
    raise RuntimeError('backend '+kind+' not observed')

def recv(sock,count):
    data=b''
    while len(data)<count:
        part=sock.recv(count-len(data))
        if not part:raise RuntimeError('unexpected SOCKS EOF')
        data+=part
    return data

for run,case in enumerate([c for c in env['cases'] if c['format']=='shadowsocks2022'],7001):
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}], 'outbounds':json.loads(case['configJSON'])['outbounds']}
    path=d.ROOT/f'go-client-{run}.json';path.write_text(json.dumps(config))
    try:
        with (d.ROOT/f'go-client-{run}.log').open('w') as output:
            child=subprocess.Popen([str(binary),'run','-config',str(path)],cwd=root,stdout=output,stderr=subprocess.STDOUT)
            try:
                end=time.monotonic()+8
                while True:
                    if child.poll() is not None:raise RuntimeError('reference client startup failed')
                    try:sock=socket.create_connection(('127.0.0.1',port),timeout=1);break
                    except OSError:
                        if time.monotonic()>end:raise
                        time.sleep(.1)
                sock.settimeout(5);sock.sendall(b'\x05\x01\x00');assert recv(sock,2)==b'\x05\x00'
                sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('198.51.100.7')+struct.pack('!H',env['tcpPort']))
                head=recv(sock,4);assert head[:2]==b'\x05\x00',head
                recv(sock,6 if head[3]==1 else 18)
                sock.sendall(f'GET /v08-hold/{run} HTTP/1.1\r\nHost: synthetic.test\r\nConnection: close\r\n\r\n'.encode())
                opened=wait_row(run,'hold-open',6)
                close_time=time.time();sock.shutdown(socket.SHUT_RDWR);sock.close()
                time.sleep(3)
                before_exit=rows(run)
                stop_time=time.time();child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait()
                exited=time.time();closed=wait_row(run,'hold-close',22)
                d.emit('ss2022-go-control',case=case['caseId'],id=run,client='Xray-core v26.7.28',
                       opened=opened,closed=closed,socksCloseTime=close_time,processStopTime=stop_time,
                       processExitTime=exited,processExitCode=child.returncode,backendBeforeClientExit=before_exit,
                       remoteCloseAfterSocksSeconds=closed['time']-close_time)
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
    finally:path.unlink(missing_ok=True)
