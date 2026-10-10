#[derive(Default)]
struct Histogram { count: u64, sum: u64, min: u64, max: u64, buckets: [u64; 10] }
pub struct Stats { scope: &'static str, names: &'static [&'static str], values: [u64; 16], hist: [Histogram;4] }
impl Stats {
    pub fn new(scope: &'static str, names: &'static [&'static str]) -> Self { Self { scope,names,values:[0;16],hist:std::array::from_fn(|_|Histogram::default()) } }
    pub fn inc(&mut self,i:usize) { self.values[i]+=1; }
    pub fn add(&mut self,i:usize,n:u64) { self.values[i]+=n; }
    pub fn hist(&mut self,i:usize,n:usize) {
        let h=&mut self.hist[i];let n=n as u64;
        h.min=if h.count==0 {n}else{h.min.min(n)};h.count+=1;h.sum+=n;h.max=h.max.max(n);
        let b=[0,1024,2048,4096,8192,16384,32768,65536,131072].iter().position(|&bound|n<=bound).unwrap_or(9);
        h.buckets[b]+=1;
    }
}
impl Drop for Stats {
    fn drop(&mut self) {
        let h:Vec<_>=self.hist.iter().map(|h|format!("{{\"count\":{},\"sum\":{},\"min\":{},\"max\":{},\"buckets\":{:?}}}",h.count,h.sum,h.min,h.max,h.buckets)).collect();
        eprintln!("XRAY_CENSUS {{\"scope\":{:?},\"names\":{:?},\"values\":{:?},\"hist\":[{}]}}", self.scope,self.names,&self.values[..self.names.len()],h.join(","));
    }
}
