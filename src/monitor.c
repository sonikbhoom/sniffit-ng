#include "sniffit_ng/monitor.h"

#include <limits.h>
#include <string.h>

#define NANOSECONDS_PER_SECOND 1000000000ULL
#define NANOSECONDS_PER_MICROSECOND 1000ULL

static void increment_saturated(uint64_t *value)
{
    if (*value < UINT64_MAX) {
        ++*value;
    }
}

static void add_saturated(uint64_t *value, uint64_t amount)
{
    if (UINT64_MAX - *value < amount) {
        *value = UINT64_MAX;
    } else {
        *value += amount;
    }
}

static uint64_t counter_delta(uint64_t current, uint64_t previous)
{
    return current >= previous ? current - previous : current;
}

static bool timestamp_to_nanoseconds(const struct timeval *timestamp, uint64_t *value)
{
    uint64_t seconds;
    uint64_t microseconds;

    if (timestamp == NULL || value == NULL || timestamp->tv_sec < 0 ||
        timestamp->tv_usec < 0 || timestamp->tv_usec >= 1000000) {
        return false;
    }
    seconds = (uint64_t)timestamp->tv_sec;
    microseconds = (uint64_t)timestamp->tv_usec;
    if (seconds > (UINT64_MAX - microseconds * NANOSECONDS_PER_MICROSECOND) /
                  NANOSECONDS_PER_SECOND) {
        return false;
    }
    *value = seconds * NANOSECONDS_PER_SECOND +
             microseconds * NANOSECONDS_PER_MICROSECOND;
    return true;
}

static bool enqueue_event(struct sn_monitor *monitor,
                          enum sn_monitor_event_kind kind,
                          const struct sn_flow *flow)
{
    size_t tail;

    if (monitor->event_count == SN_MONITOR_EVENT_CAPACITY) {
        increment_saturated(&monitor->stats.dropped_events);
        return false;
    }
    tail = (monitor->event_head + monitor->event_count) % SN_MONITOR_EVENT_CAPACITY;
    monitor->events[tail].kind = kind;
    monitor->events[tail].flow = *flow;
    ++monitor->event_count;
    return true;
}

void sn_monitor_init(struct sn_monitor *monitor, uint64_t idle_timeout_ns)
{
    if (monitor == NULL) {
        return;
    }
    memset(monitor, 0, sizeof(*monitor));
    sn_flow_table_init(&monitor->flows, idle_timeout_ns);
}

void sn_monitor_set_payload_inspection(struct sn_monitor *monitor, bool enabled)
{
    if (monitor != NULL) {
        sn_flow_table_set_payload_inspection(&monitor->flows, enabled);
    }
}

void sn_monitor_rate_sampler_init(struct sn_monitor_rate_sampler *sampler)
{
    if (sampler != NULL) {
        *sampler = (struct sn_monitor_rate_sampler){0};
    }
}

bool sn_monitor_rate_sample(
    struct sn_monitor_rate_sampler *sampler,
    const struct sn_monitor_stats *stats,
    uint64_t now_ns,
    struct sn_monitor_rates *rates)
{
    uint64_t elapsed_seconds;

    if (sampler == NULL || stats == NULL || rates == NULL) {
        return false;
    }
    if (!sampler->initialized || now_ns < sampler->sampled_at_ns) {
        sampler->previous = *stats;
        sampler->sampled_at_ns = now_ns;
        sampler->initialized = true;
        *rates = (struct sn_monitor_rates){0};
        return false;
    }
    if (now_ns - sampler->sampled_at_ns < SN_MONITOR_RATE_INTERVAL_NS) {
        return false;
    }

    elapsed_seconds = (now_ns - sampler->sampled_at_ns) / 1000000000ULL;
    if (elapsed_seconds == 0U) {
        return false;
    }
    rates->ipv4_packets_per_second =
        counter_delta(stats->ipv4_packets, sampler->previous.ipv4_packets) / elapsed_seconds;
    rates->tcp_packets_per_second =
        counter_delta(stats->tcp_packets, sampler->previous.tcp_packets) / elapsed_seconds;
    rates->udp_packets_per_second =
        counter_delta(stats->udp_packets, sampler->previous.udp_packets) / elapsed_seconds;
    rates->icmp_packets_per_second =
        counter_delta(stats->icmp_packets, sampler->previous.icmp_packets) / elapsed_seconds;
    rates->tcp_bytes_per_second =
        counter_delta(stats->tcp_bytes, sampler->previous.tcp_bytes) / elapsed_seconds;
    rates->udp_bytes_per_second =
        counter_delta(stats->udp_bytes, sampler->previous.udp_bytes) / elapsed_seconds;

    sampler->previous = *stats;
    sampler->sampled_at_ns = now_ns;
    return true;
}

enum sn_monitor_result sn_monitor_process(
    struct sn_monitor *monitor,
    const struct sn_capture_packet *packet)
{
    struct sn_packet_view view;
    const struct sn_flow *flow = NULL;
    uint64_t timestamp_ns;
    enum sn_packet_result parse_result;
    enum sn_flow_update_result flow_result;
    enum sn_monitor_event_kind event_kind;

    if (monitor == NULL || packet == NULL || packet->data == NULL) {
        if (monitor != NULL) {
            increment_saturated(&monitor->stats.invalid_packets);
        }
        return SN_MONITOR_INVALID;
    }
    increment_saturated(&monitor->stats.captured_packets);
    if (!timestamp_to_nanoseconds(&packet->timestamp, &timestamp_ns)) {
        increment_saturated(&monitor->stats.invalid_packets);
        return SN_MONITOR_INVALID;
    }

    parse_result = sn_packet_parse_ethernet_ipv4(
        packet->data, packet->captured_length, &view);
    if (parse_result == SN_PACKET_TRUNCATED) {
        increment_saturated(&monitor->stats.truncated_packets);
        return SN_MONITOR_TRUNCATED;
    }
    if (parse_result == SN_PACKET_MALFORMED) {
        increment_saturated(&monitor->stats.malformed_packets);
        return SN_MONITOR_MALFORMED;
    }
    if (view.ipv4_total_length != 0U) {
        increment_saturated(&monitor->stats.ipv4_packets);
        if (!view.ipv4_checksum_valid) {
            increment_saturated(&monitor->stats.bad_ipv4_checksums);
        }
    }
    if (parse_result == SN_PACKET_UNSUPPORTED) {
        increment_saturated(&monitor->stats.unsupported_packets);
        return SN_MONITOR_UNSUPPORTED;
    }

    switch (view.protocol) {
    case 6U:
        increment_saturated(&monitor->stats.tcp_packets);
        add_saturated(&monitor->stats.tcp_bytes, view.ipv4_total_length);
        break;
    case 17U:
        increment_saturated(&monitor->stats.udp_packets);
        add_saturated(&monitor->stats.udp_bytes, view.ipv4_total_length);
        break;
    case 1U:
        increment_saturated(&monitor->stats.icmp_packets);
        break;
    default:
        increment_saturated(&monitor->stats.unsupported_packets);
        return SN_MONITOR_UNSUPPORTED;
    }

    flow_result = sn_flow_table_update(&monitor->flows, &view, timestamp_ns, &flow);
    if (flow_result == SN_FLOW_IGNORED) {
        return SN_MONITOR_PROCESSED;
    }
    if (flow_result == SN_FLOW_INVALID || flow == NULL) {
        increment_saturated(&monitor->stats.invalid_packets);
        return SN_MONITOR_INVALID;
    }

    switch (flow_result) {
    case SN_FLOW_CREATED:
        event_kind = SN_MONITOR_FLOW_CREATED;
        break;
    case SN_FLOW_EVICTED:
        event_kind = SN_MONITOR_FLOW_EVICTED;
        break;
    case SN_FLOW_UPDATED:
        event_kind = SN_MONITOR_FLOW_UPDATED;
        break;
    default:
        increment_saturated(&monitor->stats.invalid_packets);
        return SN_MONITOR_INVALID;
    }

    if (!enqueue_event(monitor, event_kind, flow)) {
        return SN_MONITOR_EVENT_DROPPED;
    }
    return SN_MONITOR_PROCESSED;
}

bool sn_monitor_next_event(struct sn_monitor *monitor, struct sn_monitor_event *event)
{
    if (monitor == NULL || event == NULL || monitor->event_count == 0U) {
        return false;
    }
    *event = monitor->events[monitor->event_head];
    monitor->events[monitor->event_head] = (struct sn_monitor_event){0};
    monitor->event_head = (monitor->event_head + 1U) % SN_MONITOR_EVENT_CAPACITY;
    --monitor->event_count;
    return true;
}
