import asyncio,importlib.util,json,subprocess,time,os
from pathlib import Path
s=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('fixture.py'));fixture=importlib.util.module_from_spec(s);s.loader.exec_module(fixture)
events=[];output=None
class Echo(fixture.Echo):
 def datagram_received(self,data,address):
  events.append({'event':'udp-echo','bytes':len(data),'unixTime':time.time(),'monotonic':time.monotonic()})
  (output/'backend-metadata.json').write_text(json.dumps(events))
  super().datagram_received(data,address)
original=fixture.serve
async def serve(args):
 global output
 output=args.output
 with (output/'capture.log').open('w') as log:
  p=subprocess.Popen(['tcpdump','-i','any','-nn','-s','128','-U','-w',str(output/'carrier.pcap'),'(udp port 53053) or (icmp and icmp[0] = 3 and icmp[1] = 4)'],stdout=log,stderr=log)
  try:
   await asyncio.sleep(.3)
   if p.poll() is not None:raise RuntimeError('capture failed')
   await original(args)
  finally:
   if p.poll() is None:
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()
fixture.Echo=Echo;fixture.serve=serve;fixture.main()
