#!/usr/bin/env python3
"""Temporary census instrumentation; preserved patch, never a production build."""
from pathlib import Path
import subprocess
root=Path('/Users/antonmalygin/xray-rust')
out=root/'target/v08-census-investigation'
assert subprocess.check_output(['git','remote','get-url','origin'],cwd=root,text=True).strip()=='git@github.com:aimalygin/xray-rust.git'
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip()
paths=['crates/xray-core-rs/src/policy.rs','crates/xray-proxy/src/vmess/stream.rs','crates/xray-proxy/src/vmess/records.rs','crates/xray-proxy/src/record_buffer.rs','crates/xray-bench/src/protocol_bench.rs']
for name in paths:
    dest=out/'original'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((root/name).read_bytes())
helper='''#[allow(dead_code)]
mod census {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/v08-census-investigation/census.rs"));
}
'''
def edit(name, changes, include=True):
    p=root/name;s=p.read_text()
    for old,new in changes:
        assert s.count(old)>=1,(name,old,s.count(old))
        s=s.replace(old,new,1)
    if include:s+='\n'+helper
    p.write_text(s)
edit(paths[0],[
('    let (activity_tx, mut activity_rx) = mpsc::channel(1);','    let mut census = census::Stats::new("relay_idle", &["select_loops", "activity_received", "timer_expired"]);\n    let (activity_tx, mut activity_rx) = mpsc::channel(1);'),
('    loop {\n        tokio::select! {\n            result = &mut a_to_b,','    loop {\n        census.inc(0);\n        tokio::select! {\n            result = &mut a_to_b,'),
('                if activity.is_some() {','                if activity.is_some() {\n                    census.inc(1);'),
('            () = &mut idle_sleep => {','            () = &mut idle_sleep => {\n                census.inc(2);'),
('    let mut total = 0u64;','    let mut census = census::Stats::new("relay_direction", &["completed_reads", "write_all_calls", "traffic_updates", "activity_sent", "activity_full", "activity_closed", "buffer_growths", "threshold_flushes", "timer_flushes", "final_flushes", "shutdowns"]);\n    let mut total = 0u64;'),
('                let len = read?;','                let len = read?;\n                census.inc(0); census.hist(0, len); census.hist(1, buffer.len());'),
('                    if unflushed > 0 {\n                        writer.flush().await?;','                    if unflushed > 0 {\n                        census.inc(9);\n                        writer.flush().await?;'),
('                    writer.shutdown().await?;','                    census.inc(10);\n                    writer.shutdown().await?;'),
('                writer.write_all(&buffer[..len]).await?;','                census.inc(1);\n                writer.write_all(&buffer[..len]).await?;'),
('                    buffer.resize((buffer.len() * 2).min(buffer_cap), 0);','                    census.inc(6);\n                    buffer.resize((buffer.len() * 2).min(buffer_cap), 0);'),
('                    counter.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);','                    census.inc(2);\n                    counter.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);'),
('                let _ = activity.try_send(());','                match activity.try_send(()) {\n                    Ok(()) => census.inc(3),\n                    Err(mpsc::error::TrySendError::Full(())) => census.inc(4),\n                    Err(mpsc::error::TrySendError::Closed(())) => census.inc(5),\n                }'),
('                if unflushed >= COPY_FLUSH_THRESHOLD {','                if unflushed >= COPY_FLUSH_THRESHOLD {\n                    census.inc(7);'),
('            () = &mut flush_deadline, if unflushed > 0 => {','            () = &mut flush_deadline, if unflushed > 0 => {\n                census.inc(8);')])
edit(paths[1],[
('    inner: S,','    inner: S,\n    census: census::Stats,'),
('        Ok(Self {\n            inner,','        Ok(Self {\n            census: census::Stats::new("vmess_stream", &["drains", "inner_write_polls", "inner_write_pending", "inner_write_ready", "read_polls", "read_one_calls", "write_polls", "flush_polls", "body_records_opened", "plaintext_copy_bytes", "write_ready_payload_bytes"]),\n            inner,'),
('        while self.pending_pos < self.pending.len() {','        self.census.inc(0);\n        while self.pending_pos < self.pending.len() {'),
('            match ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]))\n            {','            self.census.inc(1);\n            self.census.hist(0, self.pending.len() - self.pending_pos);\n            let result = Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]);\n            if result.is_pending() { self.census.inc(2); }\n            match ready!(result) {'),
('                Ok(n) => self.pending_pos += n,','                Ok(n) => { self.census.inc(3); self.census.hist(1,n); self.pending_pos += n; },'),
('        let this = self.get_mut();\n        if this.failed {','        let this = self.get_mut();\n        this.census.inc(5);\n        if this.failed {'),
('                self.plain_len = self.reader.open_slice(self.body.frame(), self.padding)?;','                self.plain_len = self.reader.open_slice(self.body.frame(), self.padding)?;\n                self.census.inc(8); self.census.hist(2,self.plain_len);'),
('                    out.put_slice(&this.body.frame()[this.plain_pos..this.plain_pos + n]);','                    this.census.add(9,n as u64);\n                    out.put_slice(&this.body.frame()[this.plain_pos..this.plain_pos + n]);'),
('        if let Some(error) = self.read_error.take() {','        self.census.inc(4);\n        if let Some(error) = self.read_error.take() {'),
('        if this.failed || this.closing {','        this.census.inc(6);\n        if this.failed || this.closing {'),
('        Poll::Ready(Ok(n))\n    }\n    fn poll_flush','        this.census.add(10,n as u64); this.census.hist(3,n);\n        Poll::Ready(Ok(n))\n    }\n    fn poll_flush'),
('    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<\'_>) -> Poll<io::Result<()>> {\n        let this = self.get_mut();','    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<\'_>) -> Poll<io::Result<()>> {\n        let this = self.get_mut();\n        this.census.inc(7);')])
edit(paths[2],[
('    body: crypto::Counter,','    body: crypto::Counter,\n    census: census::Stats,'),
('        Self {\n            body:', '        Self {\n            census: census::Stats::new("vmess_records", &["seals", "opens", "aes_padding_random_calls", "chacha_padding_cache_calls"]),\n            body:'),
('        let padding = (self.next_mask() % 64) as usize;\n        let size = payload.len() + 16 + padding;','        self.census.inc(0); self.census.hist(0,payload.len());\n        let padding = (self.next_mask() % 64) as usize;\n        self.census.hist(1,padding);\n        let size = payload.len() + 16 + padding;'),
('        if self.batch_padding {\n            padding::fill','        if self.batch_padding {\n            self.census.inc(3);\n            padding::fill'),
('        } else {\n            random(&mut output[start..])?;','        } else {\n            self.census.inc(2);\n            random(&mut output[start..])?;'),
('        self.body.open(&mut bytes[..end])','        let size = self.body.open(&mut bytes[..end])?;\n        self.census.inc(1); self.census.hist(2,size);\n        Ok(size)')])
edit(paths[3],[
('    bytes: Zeroizing<Vec<u8>>,','    bytes: Zeroizing<Vec<u8>>,\n    census: census::Stats,'),
('            bytes: Zeroizing::new(Vec::new()),','            bytes: Zeroizing::new(Vec::new()),\n            census: census::Stats::new("record_buffer", &["frame_polls", "inner_read_polls", "inner_read_pending", "inner_read_ready", "growths", "compactions", "compacted_ciphertext_bytes"]),'),
('        if self.filled - self.start >= self.needed {\n            return Poll::Ready','        self.census.inc(0);\n        if self.filled - self.start >= self.needed {\n            return Poll::Ready'),
('        if self.bytes.len() < size {','        if self.bytes.len() < size {\n            self.census.inc(4);'),
('            self.bytes.copy_within(self.start..self.filled, 0);','            self.census.inc(5); self.census.add(6,(self.filled - self.start) as u64);\n            self.bytes.copy_within(self.start..self.filled, 0);'),
('            ready!(Pin::new(&mut *inner).poll_read(cx, &mut read))?;','            self.census.inc(1); self.census.hist(0,read.remaining());\n            let result = Pin::new(&mut *inner).poll_read(cx, &mut read);\n            if result.is_pending() { self.census.inc(2); }\n            ready!(result)?;\n            self.census.inc(3); self.census.hist(1,read.filled().len());')])
# OS counters are captured by the driver, not by the measured client. No polling on its hot path.
edit(paths[4],[
('        phase.set(BenchmarkPhase::Traffic);','        let census_before = census_snapshot(child.child.id(), &r.client_env);\n        phase.set(BenchmarkPhase::Traffic);'),
('        let elapsed = started.elapsed();\n        phase.set(BenchmarkPhase::Settle);','        let elapsed = started.elapsed();\n        let census_after_workload = census_snapshot(child.child.id(), &r.client_env);\n        phase.set(BenchmarkPhase::Settle);'),
('        Ok((outcome, elapsed))','        let census_after_settle = census_snapshot(child.child.id(), &r.client_env);\n        Ok((outcome, elapsed, json!({"before":census_before,"after_workload":census_after_workload,"after_settle":census_after_settle})))'),
('        Ok(((outcome, elapsed), samples)) => {','        Ok(((outcome, elapsed, census), samples)) => {'),
('            json!({"status":"pass", "path":r.path,"traffic":r.traffic,','            json!({"diagnostic_only":true,"process_census":census,"status":"pass", "path":r.path,"traffic":r.traffic,')],include=False)
p=root/paths[4];p.write_text(p.read_text()+'\n'+(out/'task_info.rs').read_text())
(out/'instrumentation.patch').write_bytes(subprocess.check_output(['git','diff','--binary'],cwd=root))
print('Temporary instrumentation applied; original files and exact patch saved.')
