#ifndef SNIFFIT_NG_ARP_STATE_H
#define SNIFFIT_NG_ARP_STATE_H

#include "sniffit_ng/arp.h"
#include "sniffit_ng/capture.h"

#define SN_ARP_HISTORY_CAPACITY 128U

struct sn_arp_observation {
    struct sn_arp_packet packet;
    struct timeval timestamp;
    size_t captured_length;
    size_t wire_length;
    enum sn_packet_link_type link_type;
};

struct sn_arp_state {
    struct sn_arp_observation history[SN_ARP_HISTORY_CAPACITY];
    size_t history_start;
    size_t history_count;
    uint64_t captured;
    uint64_t decoded;
    uint64_t truncated;
    uint64_t malformed;
    uint64_t unsupported;
};

void sn_arp_state_init(struct sn_arp_state *state);
enum sn_packet_result sn_arp_state_process(struct sn_arp_state *state,
                                           const struct sn_capture_packet *packet);
const struct sn_arp_observation *sn_arp_state_at(const struct sn_arp_state *state,
                                                 size_t index);

#endif