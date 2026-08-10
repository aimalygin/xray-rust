#ifndef XRAY_KERNEL_CONTROL_H
#define XRAY_KERNEL_CONTROL_H

#include <sys/ioccom.h>
#include <sys/types.h>

/*
 * The `AF_SYSTEM` kernel-control ABI, declared here because the SDK does not
 * declare it everywhere we build.
 *
 * `<sys/kern_control.h>` ships in the macOS SDK only: it is absent from the
 * iOS and tvOS SDKs entirely, so `import Darwin` yields `struct ctl_info` and
 * `struct sockaddr_ctl` on the host and nothing at all on the platforms this
 * package actually ships to. Swift code written against the Darwin module
 * therefore compiles under `swift test` on macOS and fails to compile for
 * every iOS and tvOS triple.
 *
 * The kernel reads and writes these structures either way -- utun discovery
 * needs `getpeername` and `CTLIOCGINFO` on iOS most of all -- so the layout is
 * restated here, verbatim from XNU's `bsd/sys/kern_control.h`. The names carry
 * an `xray_` prefix so that on macOS, where the SDK declares its own, the two
 * cannot collide or be confused for one another.
 *
 * The layout is not taken on trust: `XrayKernelControl.c` asserts the sizes and
 * every field offset at compile time, and cross-checks all of it against the
 * SDK's own declaration on the platforms that have one.
 */

/* XNU: MAX_KCTL_NAME */
#define XRAY_MAX_KCTL_NAME 96

/* XNU: struct ctl_info -- maps a control name to its id via CTLIOCGINFO. */
struct xray_ctl_info {
    u_int32_t ctl_id;                    /* kernel control id, filled on return */
    char ctl_name[XRAY_MAX_KCTL_NAME];   /* kernel control name (a C string) */
};

/* XNU: struct sockaddr_ctl -- the peer address of an AF_SYSTEM socket. */
struct xray_sockaddr_ctl {
    u_char sc_len;             /* depends on size of bundle ID string */
    u_char sc_family;          /* AF_SYSTEM */
    u_int16_t ss_sysaddr;      /* AF_SYS_KERNCONTROL */
    u_int32_t sc_id;           /* controller unique identifier */
    u_int32_t sc_unit;         /* developer private unit number */
    u_int32_t sc_reserved[5];  /* reserved, must be zero */
};

/*
 * XNU: CTLIOCGINFO, `_IOWR('N', 3, struct ctl_info)`.
 *
 * Swift cannot import a macro whose value depends on `sizeof`, which is why
 * the Swift side used to rebuild the `_IOC` encoding by hand. Evaluating the
 * SDK's own macro here keeps that arithmetic where the compiler can do it.
 */
static const unsigned long XRAY_CTLIOCGINFO =
    _IOWR('N', 3, struct xray_ctl_info);

#endif /* XRAY_KERNEL_CONTROL_H */
