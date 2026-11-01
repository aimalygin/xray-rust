/// Physical footprint of another live process in KiB, as `(current, lifetime
/// peak)`. Footprint counts dirty and compressed pages, unlike RSS, and is the
/// measure iOS jetsam limits apply to. The lifetime peak is exact, whereas a
/// sampled RSS can miss a short spike between samples. macOS only.
#[cfg(target_os = "macos")]
pub(crate) fn process_footprint_kib(pid: u32) -> Option<(u64, u64)> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v4>::uninit();
    // SAFETY: the buffer is a writable rusage_info_v4, the layout the V4
    // flavor fills; it is read only after the call reports success.
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V4,
            info.as_mut_ptr().cast::<libc::rusage_info_t>(),
        )
    };
    if rc != 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    Some((
        info.ri_phys_footprint / 1024,
        info.ri_lifetime_max_phys_footprint / 1024,
    ))
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn process_footprint_kib(_pid: u32) -> Option<(u64, u64)> {
    None
}

/// Peak resident set size of this process in KiB (`ru_maxrss` is bytes on
/// macOS and KiB on Linux).
pub(crate) fn current_peak_rss_kib() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if rc != 0 {
        return 0;
    }
    let usage = unsafe { usage.assume_init() };
    let max_rss = u64::try_from(usage.ru_maxrss).unwrap_or_default();
    if cfg!(target_os = "macos") {
        max_rss / 1024
    } else {
        max_rss
    }
}
