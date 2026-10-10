import asyncio,importlib.util,json,sys,time
from pathlib import Path
root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('fixture',root/'scripts/run-v07-apple-protocol-fixture.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
output=Path(sys.argv[sys.argv.index('--output')+1]);events=[];next_flow=0
# Lengths and timing only; never record endpoints, keys, or user payloads.
def emit(**row):
 row['monotonic']=time.monotonic();events.append(row)
 (output/'backend-metadata.json').write_text(json.dumps(events))
async def echo(reader,writer,byte_limit=1024*1024):
 global next_flow
 next_flow+=1;flow=next_flow;received=0;sent=0;reason='eof';emit(event='tcp-open',flow=flow)
 try:
  while received<byte_limit:
   data=await asyncio.wait_for(reader.read(min(8192,byte_limit-received)),10)
   if not data:break
   received+=len(data);writer.write(data);await asyncio.wait_for(writer.drain(),10);sent+=len(data)
 except (TimeoutError,ConnectionError) as e:reason=type(e).__name__
 finally:
  writer.close()
  try:await writer.wait_closed()
  except ConnectionError:pass
  emit(event='tcp-close',flow=flow,received=received,sent=sent,reason=reason)
class Echo(fixture.Echo):
 def datagram_received(self,data,address):
  emit(event='udp-echo',bytes=len(data));super().datagram_received(data,address)
fixture.tcp_echo=echo;fixture.Echo=Echo
fixture.main()
