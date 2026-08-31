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
