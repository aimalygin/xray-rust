// Diagnostic Darwin kernel task counters. Layout from SDK sys/proc_info.h.
#[repr(C)]
#[derive(Default)]
struct CensusTaskInfo {
    virtual_size:u64, resident_size:u64, total_user:u64,total_system:u64,
    threads_user:u64,threads_system:u64,policy:i32,faults:i32,pageins:i32,cow_faults:i32,
    messages_sent:i32,messages_received:i32,syscalls_mach:i32,syscalls_unix:i32,
    context_switches:i32,threadnum:i32,numrunning:i32,priority:i32,
}
#[repr(C)]
struct CensusTimebase { numer:u32, denom:u32 }
unsafe extern "C" { fn mach_timebase_info(info:*mut CensusTimebase)->i32; fn proc_pidinfo(pid:libc::c_int,flavor:libc::c_int,arg:u64,buffer:*mut libc::c_void,buffersize:libc::c_int)->libc::c_int; }
fn census_snapshot(pid:u32,env:&std::collections::BTreeMap<String,String>)->Value {
    let mut info=CensusTaskInfo::default();let size=std::mem::size_of::<CensusTaskInfo>();
    let rc=unsafe { proc_pidinfo(pid as i32,4,0,std::ptr::from_mut(&mut info).cast(),size as i32) };
    let mut tb=CensusTimebase {numer:0,denom:0}; assert_eq!(unsafe {mach_timebase_info(&mut tb)},0); assert!(tb.denom>0);
    let ns=|ticks:u64|((ticks as u128)*(tb.numer as u128)/(tb.denom as u128)) as u64;
    let os=if rc as usize==size {json!({"syscalls_unix":info.syscalls_unix,"syscalls_mach":info.syscalls_mach,"context_switches":info.context_switches,"user_mach_ticks":info.total_user,"system_mach_ticks":info.total_system,"user_ns":ns(info.total_user),"system_ns":ns(info.total_system),"timebase_numer":tb.numer,"timebase_denom":tb.denom,"rss_bytes":info.resident_size,"faults":info.faults})}else{json!({"error":io::Error::last_os_error().to_string(),"return":rc})};
    let interpose=env.get("XRAY_CENSUS_MAP").and_then(|p|fs::read(p).ok()).map(|b|b.chunks_exact(8).map(|s|u64::from_le_bytes(s.try_into().unwrap())).collect::<Vec<_>>());
    json!({"os":os,"interpose":interpose})
}
