#ifndef SNIFFIT_NG_FLOW_H
#define SNIFFIT_NG_FLOW_H

#include "sniffit_ng/packet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SN_FLOW_TABLE_CAPACITY 256U
#define SN_FLOW_DEFAULT_IDLE_TIMEOUT_NS 60000000000ULL
#define SN_FLOW_ICMP_SAMPLE_CAPACITY 64U

struct sn_flow_endpoint {
    uint8_t ipv4[4];
    uint16_t port;
};

struct sn_flow {
    bool active;
    uint8_t protocol;
    struct sn_flow_endpoint endpoints[2];
    uint64_t packets[2];
    uint64_t bytes[2];
    uint64_t last_seen_ns;
    bool has_icmp_echo_sample;
    uint8_t icmp_type;
    uint16_t icmp_identifier;
    uint16_t icmp_sequence;
    uint8_t icmp_payload_sample[SN_FLOW_ICMP_SAMPLE_CAPACITY];
    size_t icmp_payload_sample_length;
};

struct sn_flow_table {
    struct sn_flow entries[SN_FLOW_TABLE_CAPACITY];
    uint64_t idle_timeout_ns;
    bool inspect_payloads;
};

enum sn_flow_update_result {
    SN_FLOW_INVALID,
    SN_FLOW_IGNORED,
    SN_FLOW_CREATED,
    SN_FLOW_UPDATED,
    SN_FLOW_EVICTED
};

void sn_flow_table_init(struct sn_flow_table *table, uint64_t idle_timeout_ns);

void sn_flow_table_set_payload_inspection(struct sn_flow_table *table, bool enabled);

enum sn_flow_update_result sn_flow_table_update(
    struct sn_flow_table *table,
    const struct sn_packet_view *packet,
    uint64_t timestamp_ns,
    const struct sn_flow **flow_out);

size_t sn_flow_table_count(const struct sn_flow_table *table);

#endif
