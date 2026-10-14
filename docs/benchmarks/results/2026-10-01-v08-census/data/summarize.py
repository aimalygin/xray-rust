#!/usr/bin/env python3
"""Validate full census matrices, normalize identical payload, retain all repeats."""
import json,statistics,hashlib
from pathlib import Path
ROOT=Path('/Users/antonmalygin/xray-rust');BASE=ROOT/'target/v08-census-investigation'
OPS=['read','write','recv','send','recvfrom','sendto','readv','writev','recvmsg','sendmsg','getentropy','kevent','kevent64','writev_requested_segments','writev_iov_count','arc4random_buf']
def load(p):return json.loads(p.read_text())
def summarize_rows(rows):
    return {key:{'median':statistics.median(r[key] for r in rows),'min':min(r[key] for r in rows),'max':max(r[key] for r in rows),'samples':[r[key] for r in rows]} for key in rows[0]}
def run(base=BASE,output=None):
    summary={'scope':'Darwin diagnostic census, not claimed optimization or isolated AEAD CPU profile. All complete repeated cases retained. Kernel means total Unix syscall count. libc entrypoints are partial: Xray directly invokes SYS_READV, bypassing libc. Rust send/recv wrap sendto/recvfrom; do not double-count both layers.','kernel':{},'libc':{},'internal':{},'validated_runs':{}}
    for campaign in ['kernel','libc','internal']:
        directory=base/campaign;m=load(directory/'manifest.json');assert m['status']=='pass' and m['repeats']==3 and not m['smoke']
        expected={(c['id'],v,i) for c in m['cases'] for v in m['versions'] for i in range(1,4)}
        actual={(r['case'],r['version'],r['repeat']) for r in m['runs']};assert actual==expected and len(actual)==len(m['runs'])
        groups={}
        for row in m['runs']:
            assert row['returncode']==0 and not row['remaining_engine_processes'] and not row['surviving_process_group'] and not row['ambient_cpu']['compiler_load_detected']
            report=load(directory/row['output_relative']/'result.json');assert report['status']=='pass'
            size=report['connections']*report['iterations']*report['payload_size'];assert report['bytes_sent']+report['bytes_received']==size
            assert (report['bytes_sent']==size)==(report['traffic']=='upload')
            before=report['process_census']['before']['os'];after=report['process_census']['after_settle']['os']
            assert before['timebase_numer']==after['timebase_numer']==125 and before['timebase_denom']==after['timebase_denom']==3
            for snapshot in report['process_census'].values():
                s=snapshot['os']
                for name in ['user','system']:assert s[name+'_ns']==s[name+'_mach_ticks']*s['timebase_numer']//s['timebase_denom']
            d={k:after[k]-before[k] for k in ['user_ns','system_ns','syscalls_unix','syscalls_mach','context_switches']};assert all(v>=0 for v in d.values())
            metrics={'unix_calls':d['syscalls_unix'],'unix_calls_per_mib':d['syscalls_unix']/(size/1048576),'mach_calls':d['syscalls_mach'],'context_switches':d['context_switches'],'user_ms':d['user_ns']/1e6,'system_ms':d['system_ns']/1e6,'cpu_ms':(d['user_ns']+d['system_ns'])/1e6,'system_cpu_pct':100*d['system_ns']/(d['user_ns']+d['system_ns']),'ps_cpu_ms':report['cpu_millis'],'throughput_mib_s':report['throughput_mib_s'],'peak_rss_kib':report['peak_rss_kib']}
            # The ps snapshots are a separate, coarser window. Allow boundary/background CPU, not arbitrary conversion mistakes.
            assert abs(metrics['cpu_ms']-metrics['ps_cpu_ms'])<max(30,metrics['cpu_ms']*.08),(row,metrics)
            if campaign=='libc':
                a=report['process_census']['before']['interpose'];b=report['process_census']['after_settle']['interpose'];assert a[:5]==b[:5] and a[0]==0x58524159434e5331 and a[3:5]==[16,16]
                delta=[v-u for u,v in zip(a[8:],b[8:])];assert min(delta)>=0
                metrics={}
                for i,op in enumerate(OPS):
                    v=delta[i*16:(i+1)*16]
                    for key,n in zip(['calls','requested','returned','would_block','errors','zero'],v[:6]):metrics[op+'_'+key]=n
                    metrics[op+'_mean_returned_per_success']=v[2]/(v[0]-v[3]-v[4]) if v[0]-v[3]-v[4] else 0
                    for j,n in enumerate(v[6:]):metrics[op+'_bucket_'+str(j)]=n
                    assert sum(v[6:])+v[3]+v[4]==v[0],(op,v)
                # Check actual observed write bytes cover the full traffic. Read-side libc coverage is deliberately incomplete for Xray.
                writes=sum(metrics[op+'_returned'] for op in ['write','sendto','writev','sendmsg'])
                assert writes>=size and writes<size*1.05,(row,writes,size)
                metrics['deduplicated_write_calls']=sum(metrics[op+'_calls'] for op in ['write','sendto','writev','sendmsg'])
                metrics['deduplicated_write_bytes']=writes
                metrics['mean_write_bytes']=writes/metrics['deduplicated_write_calls']
                metrics['getentropy_calls_per_mib']=metrics['getentropy_calls']/(size/1048576)
            if campaign=='internal':
                events=[json.loads(line.split('XRAY_CENSUS ',1)[1]) for line in (directory/row['output_relative']/'stderr.log').read_text().splitlines() if 'XRAY_CENSUS ' in line]
                assert events
                metrics={}
                scopes={}
                for e in events:
                    scope=e['scope'];scopes[scope]=scopes.get(scope,0)+1
                    for k,v in zip(e['names'],e['values']):metrics[scope+'.'+k]=metrics.get(scope+'.'+k,0)+v
                    for i,h in enumerate(e['hist']):
                        assert sum(h['buckets'])==h['count']
                        for k in ['count','sum']:
                            name=scope+'.hist'+str(i)+'.'+k;metrics[name]=metrics.get(name,0)+h[k]
                flows=report['connections']+1 # One verified 1024-byte warmup flow.
                assert scopes=={'relay_direction':2*flows,'relay_idle':flows,'vmess_stream':flows,'vmess_records':2*flows,'record_buffer':flows},scopes
                up=metrics['vmess_records.hist0.sum'];down=metrics['vmess_records.hist2.sum']
                assert metrics['vmess_stream.write_ready_payload_bytes']==up
                assert metrics['vmess_stream.plaintext_copy_bytes']==down
                assert metrics['relay_direction.hist0.sum']==up+down
                assert up+down==size+2048+report['connections']*(3 if report['traffic']=='upload' else 2),(row,up,down,size)
                assert metrics['vmess_records.seals']==metrics['vmess_records.aes_padding_random_calls']
                metrics['relay_mean_positive_read_bytes']=metrics['relay_direction.hist0.sum']/metrics['relay_direction.write_all_calls']
                metrics['record_mean_sealed_bytes']=up/metrics['vmess_records.seals']
                metrics['idle_notifications_per_mib']=metrics['relay_idle.activity_received']/(size/1048576)
                metrics['relay_reads_per_mib']=metrics['relay_direction.write_all_calls']/(size/1048576)
            groups.setdefault((row['case'],row['version']),[]).append(metrics)
        for (case,version),rows in groups.items():summary[campaign].setdefault(case,{})[version]=summarize_rows(rows)
        summary['validated_runs'][campaign]=len(m['runs'])
    path=output or base/'summary.json';path.write_text(json.dumps(summary,indent=2)+'\n');return summary
if __name__=='__main__':
    s=run();print(s['validated_runs'])
    for c,versions in s['kernel'].items():
        print(c)
        for v,m in versions.items():print(v,{k:round(m[k]['median'],2) for k in ['unix_calls','user_ms','system_ms','cpu_ms','system_cpu_pct']})
