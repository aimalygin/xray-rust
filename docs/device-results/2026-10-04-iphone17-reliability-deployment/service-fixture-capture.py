import base64,importlib.util,json,os,secrets,sys,time
from pathlib import Path
from urllib.parse import quote
R=Path('/tmp/xray-v08-reliability-20261004');ACTIVE=R/'active'
count=int((R/'counter').read_text()) if (R/'counter').exists() else 0
if ACTIVE.exists():
 assert not ACTIVE.is_symlink()
 assert not any((ACTIVE/n).exists() for n in ['server.json','v07-probe.json','tls.key','tls.crt'])
 ACTIVE.rename(R/('archive-%03d'%count))
count+=1;(R/'counter').write_text(str(count))
method=(R/'method').read_text().strip()
assert method in ['2022-blake3-chacha20-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm']
spec=importlib.util.spec_from_file_location('fixture',R/'fixture.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
original=fixture.write_fixtures;events=[]
def write(*args,**kwargs):
 original(*args,**kwargs)
 server=json.loads((ACTIVE/'server.json').read_text());profile=json.loads((ACTIVE/'v07-probe.json').read_text());password=base64.b64encode(secrets.token_bytes(16 if method.endswith('128-gcm') else 32)).decode()
 settings=server['inbounds'][0]['settings'];settings.update(method=method,password=password)
 case=profile['cases'][0];config=json.loads(case['configJSON']);out=config['outbounds'][0]['settings'];out.update(method=method,password=password)
 case['configJSON']=json.dumps(config);case['label']='shadowsocks2022:'+method
 case['text']=f"ss://{method}:{quote(password,safe='')}@{out['address']}:{out['port']}"
 (ACTIVE/'server.json').write_text(json.dumps(server));(ACTIVE/'v07-probe.json').write_text(json.dumps(profile))
 (ACTIVE/'generation.json').write_text(json.dumps({'generation':count,'method':method,'unixTime':time.time()}))
class Echo(fixture.Echo):
 def datagram_received(self,data,address):
  events.append({'bytes':len(data),'unixTime':time.time()});(ACTIVE/'backend-metadata.json').write_text(json.dumps(events));super().datagram_received(data,address)
fixture.write_fixtures=write;fixture.Echo=Echo
# Header-only capture: Ethernet + IPv4 header, no UDP/application payload.
import asyncio,subprocess
original_serve=fixture.serve
async def captured_serve(args):
 client=(R/'capture-client').read_text().strip()
 import ipaddress
 client=str(ipaddress.IPv4Address(client))
 expression=f'(udp port 53053) or (ip proto 17 and (ip[6:2] & 0x1fff != 0) and host {client})'
 with (ACTIVE/'capture.log').open('w') as log:
  capture=subprocess.Popen(['tcpdump','-i','ens6','-nn','-s','34','-U','-w',str(ACTIVE/'carrier.pcap'),expression],stdout=log,stderr=log)
  try:
   await asyncio.sleep(.2)
   if capture.poll() is not None:raise RuntimeError('header capture failed')
   await original_serve(args)
  finally:
   if capture.poll() is None:
    capture.terminate()
    try:capture.wait(timeout=5)
    except subprocess.TimeoutExpired:capture.kill();capture.wait()
fixture.serve=captured_serve
bind=(R/'bind').read_text().strip()
sys.argv=['fixture.py','--bind',bind,'--reference-binary','/usr/local/x-ui/bin/xray-linux-amd64','--reference-sha256','64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d','--output',str(ACTIVE),'--protocol','shadowsocks2022','--port','53053','--mode','udp-sweep','--seconds','780']
fixture.main()
