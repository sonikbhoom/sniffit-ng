#ifndef SNIFFIT_NG_MONITOR_H
#define SNIFFIT_NG_MONITOR_H

#include "sniffit_ng/capture.h"
#include "sniffit_ng/flow.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SN_MONITOR_EVENT_CAPACITY 128U
#define SN_MONITOR_RATE_INTERVAL_NS 3000000000ULL

struct sn_monitor_stats {
    uint64_t captured_packets;
    uint64_t ipv4_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
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
};

void sn_monitor_init(struct sn_monitor *monitor, uint64_t idle_timeout_ns);

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
