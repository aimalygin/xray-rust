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
  uint64_t tcp_remote_write_wait_events;
  uint64_t tcp_remote_write_wait_ms_total;
  uint64_t tcp_remote_write_wait_ms_max;
  uint64_t tcp_remote_flush_wait_events;
  uint64_t tcp_remote_flush_wait_ms_total;
  uint64_t tcp_remote_flush_wait_ms_max;
  uint64_t tcp_pending_remote_bytes;
  uint64_t tcp_pending_remote_flows;
  uint64_t tcp_pending_remote_max_bytes;
  uint64_t tcp_remote_buffer_limit_bytes;
  uint64_t tcp_remote_buffer_pressure_active;
  uint64_t tcp_remote_write_errors;
  uint64_t tcp_remote_closed_events;
  uint64_t tcp_remote_read_errors;
  uint64_t tcp_open_errors;
  uint64_t tcp_open_events;
  uint64_t tcp_open_duration_ms_total;
  uint64_t tcp_open_duration_ms_max;
  uint64_t tcp_first_byte_events;
  uint64_t tcp_first_byte_duration_ms_total;
  uint64_t tcp_first_byte_duration_ms_max;
  uint64_t tcp443_open_events;
  uint64_t tcp443_open_duration_ms_total;
  uint64_t tcp443_open_duration_ms_max;
  uint64_t tcp443_first_byte_events;
  uint64_t tcp443_first_byte_duration_ms_total;
  uint64_t tcp443_first_byte_duration_ms_max;
  uint64_t active_tcp_flows;
  uint64_t active_udp_flows;
  uint64_t udp_flow_limit;
  uint64_t udp_budget_drops;
  uint64_t udp_evicted_flows;
  uint64_t udp_channel_dropped_packets;
  uint64_t udp_remote_open_events;
  uint64_t udp_remote_udp443_open_events;
  uint64_t udp_remote_written_bytes;
  uint64_t udp_remote_read_bytes;
  uint64_t udp_open_errors;
  uint64_t udp_vision_udp443_rejections;
  uint64_t udp_remote_write_errors;
  uint64_t udp_remote_read_errors;
  uint64_t udp_remote_closed_events;
  uint64_t udp_quic_blocked_packets;
  uint64_t inbound_queue_depth;
  uint64_t outbound_queue_depth;
  uint64_t inbound_queue_max_packets;
  uint64_t outbound_queue_max_packets;
  uint64_t tun_fd_write_batches;
  uint64_t tun_fd_write_batch_packets;
  uint64_t tun_fd_write_batch_max_packets;
} XrayTunStats;

typedef enum XrayTunFdPacketFormat {
  XRAY_TUN_FD_PACKET_FORMAT_RAW_IP = 0,
  XRAY_TUN_FD_PACKET_FORMAT_DARWIN_UTUN = 1
} XrayTunFdPacketFormat;

typedef enum XrayTunFdClosePolicy {
  XRAY_TUN_FD_CLOSE_POLICY_BORROWED = 0,
  XRAY_TUN_FD_CLOSE_POLICY_OWNED = 1
} XrayTunFdClosePolicy;

typedef enum XrayTunRuntimeProfile {
  XRAY_TUN_RUNTIME_PROFILE_DEFAULT = 0,
  XRAY_TUN_RUNTIME_PROFILE_MOBILE = 1,
  XRAY_TUN_RUNTIME_PROFILE_DESKTOP = 2,
  XRAY_TUN_RUNTIME_PROFILE_LOW_MEMORY = 3,
  XRAY_TUN_RUNTIME_PROFILE_THROUGHPUT = 4,
  XRAY_TUN_RUNTIME_PROFILE_MOBILE_PLUS = 5
} XrayTunRuntimeProfile;

typedef enum XrayTcpSlowFlowKind {
  XRAY_TCP_SLOW_FLOW_KIND_UNKNOWN = 0,
  XRAY_TCP_SLOW_FLOW_KIND_OPEN = 1,
  XRAY_TCP_SLOW_FLOW_KIND_FIRST_BYTE = 2
} XrayTcpSlowFlowKind;

typedef struct XrayTcpSlowFlowEvent {
  XrayTcpSlowFlowKind kind;
  uint64_t open_duration_ms;
  uint64_t first_byte_duration_ms;
} XrayTcpSlowFlowEvent;

typedef struct XrayTcpFlowSummaryEvent {
  uint64_t closed;
  uint64_t duration_ms;
  uint64_t open_duration_ms;
  uint64_t first_byte_duration_ms;
  uint64_t remote_read_bytes;
  uint64_t ms_to_64kib;
  uint64_t ms_to_128kib;
  uint64_t ms_to_256kib;
  uint64_t ms_to_512kib;
  uint64_t ms_to_1mib;
} XrayTcpFlowSummaryEvent;

typedef struct XrayTcpRemoteWriteSlowEvent {
  uint64_t duration_ms;
  uint64_t bytes;
  uint64_t messages;
} XrayTcpRemoteWriteSlowEvent;

typedef struct XrayUdpSlowFlowEvent {
  uint64_t first_response_duration_ms;
  uint64_t written_bytes;
  uint64_t read_bytes;
} XrayUdpSlowFlowEvent;

typedef struct XrayUdpResponseGapEvent {
  uint64_t response_gap_duration_ms;
  uint64_t written_bytes;
  uint64_t read_bytes;
} XrayUdpResponseGapEvent;

typedef struct XrayUdpQuicBlockedEvent {
  uint64_t bytes;
} XrayUdpQuicBlockedEvent;

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
XrayStatus xray_core_set_tun_collect_tcp_timings(
    XrayCoreHandle *handle,
    int32_t collect_tcp_timings,
    XrayError **error);
XrayStatus xray_core_set_tun_runtime_profile(
    XrayCoreHandle *handle,
    XrayTunRuntimeProfile profile,
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
/* Blocks up to wait_ms for the first packet (0 polls without waiting), then
 * drains ready packets back-to-back into buffer; packet_lengths[i] receives
 * each length and *packet_count the number written. At most
 * min(max_packets, buffer_len / mtu) packets are returned per call.
 * May be called concurrently with xray_tun_push_packet / xray_tun_poll_packet
 * / xray_tun_stats on the same handle, but never concurrently with lifecycle
 * calls (load_config / start / stop / set_* / free). */
XrayStatus xray_tun_poll_packets(
    XrayCoreHandle *handle,
    uint8_t *buffer,
    size_t buffer_len,
    size_t *packet_lengths,
    size_t max_packets,
    size_t *packet_count,
    uint32_t wait_ms,
    XrayError **error);
XrayStatus xray_tun_poll_tcp_slow_flow_event(
    XrayCoreHandle *handle,
    XrayTcpSlowFlowEvent *event,
    char *target_buffer,
    size_t target_buffer_len,
    size_t *target_written,
    XrayError **error);
XrayStatus xray_tun_poll_tcp_flow_summary_event(
    XrayCoreHandle *handle,
    XrayTcpFlowSummaryEvent *event,
    char *target_buffer,
    size_t target_buffer_len,
    size_t *target_written,
    char *outbound_tag_buffer,
    size_t outbound_tag_buffer_len,
    size_t *outbound_tag_written,
    XrayError **error);
XrayStatus xray_tun_poll_tcp_remote_write_slow_event(
    XrayCoreHandle *handle,
    XrayTcpRemoteWriteSlowEvent *event,
    char *target_buffer,
    size_t target_buffer_len,
    size_t *target_written,
    char *outbound_tag_buffer,
    size_t outbound_tag_buffer_len,
    size_t *outbound_tag_written,
    XrayError **error);
XrayStatus xray_tun_poll_udp_slow_flow_event(
    XrayCoreHandle *handle,
    XrayUdpSlowFlowEvent *event,
    char *target_buffer,
    size_t target_buffer_len,
    size_t *target_written,
    XrayError **error);
XrayStatus xray_tun_poll_udp_response_gap_event(
    XrayCoreHandle *handle,
    XrayUdpResponseGapEvent *event,
    char *target_buffer,
    size_t target_buffer_len,
    size_t *target_written,
    XrayError **error);
XrayStatus xray_tun_poll_udp_quic_blocked_event(
    XrayCoreHandle *handle,
    XrayUdpQuicBlockedEvent *event,
    char *target_buffer,
    size_t target_buffer_len,
    size_t *target_written,
    XrayError **error);
XrayStatus xray_tun_stats(
    XrayCoreHandle *handle,
    XrayTunStats *stats,
    XrayError **error);

#ifdef __cplusplus
}
#endif

#endif
