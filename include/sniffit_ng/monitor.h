#ifndef SNIFFIT_NG_MONITOR_H
#define SNIFFIT_NG_MONITOR_H

#include "sniffit_ng/capture.h"
#include "sniffit_ng/flow.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SN_MONITOR_EVENT_CAPACITY 128U
#define SN_MONITOR_RATE_INTERVAL_NS 3000000000ULL
#define SN_MONITOR_FULL_DECODE_HISTORY_CAPACITY 8U
#define SN_MONITOR_FULL_DECODE_PACKET_CAPACITY 65535U

struct sn_full_decode_record {
    bool active;
    struct sn_flow_endpoint endpoints[2];
    uint64_t sequence;
    struct timeval timestamp;
    enum sn_packet_link_type link_type;
    size_t captured_length;
    size_t wire_length;
    size_t stored_length;
    uint8_t bytes[SN_MONITOR_FULL_DECODE_PACKET_CAPACITY];
};

struct sn_monitor_stats {
    uint64_t captured_packets;
    uint64_t ipv4_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t igmp_packets;
    uint64_t vrrp_packets;
    uint64_t tcp_bytes;
    uint64_t udp_bytes;
    uint64_t bad_ipv4_checksums;
    uint64_t truncated_packets;
    uint64_t malformed_packets;
    uint64_t unsupported_packets;
    uint64_t invalid_packets;
    uint64_t dropped_events;
};

struct sn_monitor_rates {
    uint64_t ipv4_packets_per_second;
    uint64_t tcp_packets_per_second;
    uint64_t udp_packets_per_second;
    uint64_t icmp_packets_per_second;
    uint64_t igmp_packets_per_second;
    uint64_t vrrp_packets_per_second;
    uint64_t tcp_bytes_per_second;
    uint64_t udp_bytes_per_second;
};

struct sn_monitor_rate_sampler {
    struct sn_monitor_stats previous;
    uint64_t sampled_at_ns;
    bool initialized;
};

enum sn_monitor_result {
    SN_MONITOR_PROCESSED,
    SN_MONITOR_TRUNCATED,
    SN_MONITOR_MALFORMED,
    SN_MONITOR_UNSUPPORTED,
    SN_MONITOR_INVALID,
    SN_MONITOR_EVENT_DROPPED
};

enum sn_monitor_event_kind {
    SN_MONITOR_FLOW_CREATED,
    SN_MONITOR_FLOW_UPDATED,
    SN_MONITOR_FLOW_EVICTED
};

struct sn_monitor_event {
    enum sn_monitor_event_kind kind;
    struct sn_flow flow;
};

struct sn_monitor {
    struct sn_flow_table flows;
    struct sn_monitor_stats stats;
    struct sn_monitor_event events[SN_MONITOR_EVENT_CAPACITY];
    size_t event_head;
    size_t event_count;
    struct sn_full_decode_record *full_decode_records;
    size_t full_decode_next;
    size_t full_decode_count;
    uint64_t full_decode_sequence;
    bool full_decode_enabled;
};

void sn_monitor_init(struct sn_monitor *monitor, uint64_t idle_timeout_ns);

bool sn_monitor_set_full_decode(struct sn_monitor *monitor, bool enabled);

void sn_monitor_clear_full_decode(struct sn_monitor *monitor);

void sn_monitor_destroy(struct sn_monitor *monitor);

size_t sn_monitor_full_decode_count(const struct sn_monitor *monitor);

const struct sn_full_decode_record *sn_monitor_full_decode_at(
    const struct sn_monitor *monitor,
    size_t chronological_index);

void sn_monitor_set_payload_inspection(struct sn_monitor *monitor, bool enabled);

void sn_monitor_set_decode_options(struct sn_monitor *monitor,
                                   bool show_raw_flows,
                                   bool tainted_extensions,
                                   const enum sn_decoder_mode modes[
                                       SN_DECODER_MODULE_COUNT]);

void sn_monitor_rate_sampler_init(struct sn_monitor_rate_sampler *sampler);

bool sn_monitor_rate_sample(
    struct sn_monitor_rate_sampler *sampler,
    const struct sn_monitor_stats *stats,
    uint64_t now_ns,
    struct sn_monitor_rates *rates);

enum sn_monitor_result sn_monitor_process(
    struct sn_monitor *monitor,
    const struct sn_capture_packet *packet);

bool sn_monitor_next_event(struct sn_monitor *monitor, struct sn_monitor_event *event);

#endif
