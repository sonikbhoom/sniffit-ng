#ifndef SNIFFIT_NG_FLOW_H
#define SNIFFIT_NG_FLOW_H

#include "sniffit_ng/packet.h"
#include "sniffit_ng/protocol_decode.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SN_FLOW_TABLE_CAPACITY 256U
#define SN_FLOW_DEFAULT_IDLE_TIMEOUT_NS 60000000000ULL
#define SN_FLOW_ICMP_SAMPLE_CAPACITY 256U
#define SN_FLOW_ICMP_HISTORY_CAPACITY 16U

struct sn_flow_endpoint {
    uint8_t ipv4[4];
    uint16_t port;
};

struct sn_icmp_echo_sample {
    uint8_t type;
    uint8_t direction;
    uint16_t identifier;
    uint16_t sequence;
    size_t original_payload_length;
    uint8_t payload[SN_FLOW_ICMP_SAMPLE_CAPACITY];
    size_t payload_length;
    bool payload_truncated;
};

struct sn_flow {
    bool active;
    uint8_t protocol;
    struct sn_flow_endpoint endpoints[2];
    uint64_t packets[2];
    uint64_t bytes[2];
    uint64_t last_seen_ns;
    struct sn_icmp_echo_sample icmp_history[SN_FLOW_ICMP_HISTORY_CAPACITY];
    size_t icmp_history_count;
    size_t icmp_history_next;
    struct sn_packet_decode_record decode_history[SN_FLOW_DECODE_HISTORY_CAPACITY];
    size_t decode_history_count;
    size_t decode_history_next;
};

struct sn_flow_table {
    struct sn_flow entries[SN_FLOW_TABLE_CAPACITY];
    uint64_t idle_timeout_ns;
    bool inspect_payloads;
    bool show_raw_flows;
    bool tainted_extensions;
    enum sn_decoder_mode decoder_modes[SN_DECODER_MODULE_COUNT];
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

void sn_flow_table_set_decode_options(struct sn_flow_table *table,
                                      bool show_raw_flows,
                                      bool tainted_extensions,
                                      const enum sn_decoder_mode modes[
                                          SN_DECODER_MODULE_COUNT]);

enum sn_flow_update_result sn_flow_table_update(
    struct sn_flow_table *table,
    const struct sn_packet_view *packet,
    uint64_t timestamp_ns,
    const struct sn_flow **flow_out);

size_t sn_flow_table_count(const struct sn_flow_table *table);

const struct sn_icmp_echo_sample *sn_flow_icmp_history_at(
    const struct sn_flow *flow,
    size_t chronological_index);

const struct sn_packet_decode_record *sn_flow_decode_history_at(
    const struct sn_flow *flow,
    size_t chronological_index);

#endif
