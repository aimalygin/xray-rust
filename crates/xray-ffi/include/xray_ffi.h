#ifndef XRAY_FFI_H
#define XRAY_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum XrayStatus {
  XRAY_STATUS_OK = 0,
  XRAY_STATUS_NULL_ARGUMENT = 1,
  XRAY_STATUS_INVALID_UTF8 = 2,
  XRAY_STATUS_CONFIG_ERROR = 3,
  XRAY_STATUS_CORE_NOT_LOADED = 4,
  XRAY_STATUS_RUNTIME_ERROR = 5,
  XRAY_STATUS_NO_PACKET = 6,
  XRAY_STATUS_BUFFER_TOO_SMALL = 7,
  XRAY_STATUS_TUN_ERROR = 8,
  XRAY_STATUS_PANIC = 255
} XrayStatus;

typedef struct XrayTunStats {
  uint64_t inbound_packets;
  uint64_t outbound_packets;
  uint64_t dropped_packets;
  uint64_t inbound_dropped_packets;
  uint64_t outbound_dropped_packets;
  uint64_t tcp_stack_to_remote_bytes;
  uint64_t tcp_remote_written_bytes;
  uint64_t tcp_remote_read_bytes;
  uint64_t tcp_backpressure_events;
  uint64_t tcp_stack_to_remote_backpressure_events;
  uint64_t tcp_remote_to_stack_backpressure_events;
  uint64_t tcp_remote_write_batches;
  uint64_t tcp_remote_write_batch_messages;
  uint64_t tcp_remote_write_batch_max_messages;
  uint64_t tcp_remote_write_batch_max_bytes;
  uint64_t tcp_pending_remote_bytes;
  uint64_t tcp_pending_remote_flows;
  uint64_t tcp_pending_remote_max_bytes;
  uint64_t tcp_remote_buffer_limit_bytes;
  uint64_t tcp_remote_buffer_pressure_active;
  uint64_t tcp_remote_write_errors;
  uint64_t tcp_remote_closed_events;
  uint64_t tcp_remote_read_errors;
  uint64_t tcp_open_errors;
  uint64_t active_tcp_flows;
  uint64_t active_udp_flows;
  uint64_t udp_flow_limit;
  uint64_t udp_budget_drops;
  uint64_t udp_evicted_flows;
  uint64_t udp_channel_dropped_packets;
  uint64_t udp_open_errors;
  uint64_t udp_vision_udp443_rejections;
  uint64_t udp_remote_write_errors;
  uint64_t udp_remote_read_errors;
  uint64_t udp_remote_closed_events;
  uint64_t udp_quic_blocked_packets;
} XrayTunStats;

typedef enum XrayTunFdPacketFormat {
  XRAY_TUN_FD_PACKET_FORMAT_RAW_IP = 0,
  XRAY_TUN_FD_PACKET_FORMAT_DARWIN_UTUN = 1
} XrayTunFdPacketFormat;

typedef enum XrayTunFdClosePolicy {
  XRAY_TUN_FD_CLOSE_POLICY_BORROWED = 0,
  XRAY_TUN_FD_CLOSE_POLICY_OWNED = 1
} XrayTunFdClosePolicy;

typedef struct XrayCoreHandle XrayCoreHandle;
typedef struct XrayError XrayError;
typedef int32_t (*XraySocketProtectCallback)(int32_t fd, void *user_data);

uint32_t xray_ffi_version_major(void);

XrayCoreHandle *xray_core_new(XrayError **error);
XrayStatus xray_core_load_config_json(
    XrayCoreHandle *handle,
    const char *json,
    XrayError **error);
XrayStatus xray_core_start(XrayCoreHandle *handle, XrayError **error);
XrayStatus xray_core_stop(XrayCoreHandle *handle, XrayError **error);
XrayStatus xray_core_set_socket_protect_callback(
    XrayCoreHandle *handle,
    XraySocketProtectCallback callback,
    void *user_data,
    XrayError **error);
XrayStatus xray_core_set_tun_fd(
    XrayCoreHandle *handle,
    int32_t fd,
    XrayTunFdPacketFormat packet_format,
    XrayTunFdClosePolicy close_policy,
    XrayError **error);
XrayStatus xray_core_set_tun_block_quic(
    XrayCoreHandle *handle,
    int32_t block_quic,
    XrayError **error);
void xray_core_free(XrayCoreHandle *handle);

XrayStatus xray_error_code(const XrayError *error);
const char *xray_error_message(const XrayError *error);
void xray_error_free(XrayError *error);

XrayStatus xray_tun_push_packet(
    XrayCoreHandle *handle,
    const uint8_t *data,
    size_t len,
    XrayError **error);
XrayStatus xray_tun_poll_packet(
    XrayCoreHandle *handle,
    uint8_t *buffer,
    size_t buffer_len,
    size_t *written,
    XrayError **error);
XrayStatus xray_tun_stats(
    XrayCoreHandle *handle,
    XrayTunStats *stats,
    XrayError **error);

#ifdef __cplusplus
}
#endif

#endif
