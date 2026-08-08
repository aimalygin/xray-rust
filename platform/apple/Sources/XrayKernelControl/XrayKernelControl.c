#include "include/XrayKernelControl.h"

#include <stddef.h>

/*
 * A hand-declared ABI is only safe while it matches the kernel's, so the match
 * is checked by the compiler rather than by review.
 *
 * The absolute assertions below hold on every platform, including the iOS and
 * tvOS builds this shim exists for -- the ones whose SDK has nothing to compare
 * against. Getting a field offset wrong would not fail loudly at runtime:
 * `getpeername` and `ioctl` would fill neighbouring bytes and utun discovery
 * would simply stop finding anything.
 */

_Static_assert(sizeof(struct xray_ctl_info) == 100,
               "struct ctl_info is a u_int32_t and a 96-byte name");
_Static_assert(offsetof(struct xray_ctl_info, ctl_id) == 0, "ctl_id leads");
_Static_assert(offsetof(struct xray_ctl_info, ctl_name) == 4, "ctl_name follows");

_Static_assert(sizeof(struct xray_sockaddr_ctl) == 32, "sockaddr_ctl is 32 bytes");
_Static_assert(offsetof(struct xray_sockaddr_ctl, sc_len) == 0, "sc_len leads");
_Static_assert(offsetof(struct xray_sockaddr_ctl, sc_family) == 1, "sc_family follows");
_Static_assert(offsetof(struct xray_sockaddr_ctl, ss_sysaddr) == 2, "ss_sysaddr follows");
_Static_assert(offsetof(struct xray_sockaddr_ctl, sc_id) == 4, "sc_id follows");
_Static_assert(offsetof(struct xray_sockaddr_ctl, sc_unit) == 8, "sc_unit follows");
_Static_assert(offsetof(struct xray_sockaddr_ctl, sc_reserved) == 12, "sc_reserved trails");

/*
 * Where the SDK does declare the ABI -- macOS, today -- the transcription is
 * held against it directly. That makes the macOS build a standing check on the
 * iOS and tvOS ones: if Apple ever moves a field, this stops compiling on the
 * host instead of silently diverging on the platforms that cannot check.
 */
#if __has_include(<sys/kern_control.h>)
#include <sys/kern_control.h>

_Static_assert(XRAY_MAX_KCTL_NAME == MAX_KCTL_NAME, "control name length drifted");
_Static_assert(XRAY_CTLIOCGINFO == CTLIOCGINFO, "CTLIOCGINFO encoding drifted");

_Static_assert(sizeof(struct xray_ctl_info) == sizeof(struct ctl_info),
               "ctl_info size drifted from the SDK");
_Static_assert(offsetof(struct xray_ctl_info, ctl_id) == offsetof(struct ctl_info, ctl_id),
               "ctl_id offset drifted from the SDK");
_Static_assert(offsetof(struct xray_ctl_info, ctl_name) == offsetof(struct ctl_info, ctl_name),
               "ctl_name offset drifted from the SDK");

_Static_assert(sizeof(struct xray_sockaddr_ctl) == sizeof(struct sockaddr_ctl),
               "sockaddr_ctl size drifted from the SDK");
_Static_assert(offsetof(struct xray_sockaddr_ctl, sc_family) == offsetof(struct sockaddr_ctl, sc_family),
               "sc_family offset drifted from the SDK");
_Static_assert(offsetof(struct xray_sockaddr_ctl, sc_id) == offsetof(struct sockaddr_ctl, sc_id),
               "sc_id offset drifted from the SDK");
_Static_assert(offsetof(struct xray_sockaddr_ctl, sc_unit) == offsetof(struct sockaddr_ctl, sc_unit),
               "sc_unit offset drifted from the SDK");
#endif

/*
 * The assertions are the whole translation unit; this keeps it from being
 * empty, which is undefined in C.
 */
const int xray_kernel_control_abi_checked = 1;
