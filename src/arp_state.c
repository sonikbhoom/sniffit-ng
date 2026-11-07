#include "sniffit_ng/arp_state.h"

static void increment(uint64_t *value)
{
    if (*value < UINT64_MAX) {
        ++*value;
    }
}

void sn_arp_state_init(struct sn_arp_state *state)
{
    if (state != NULL) {
        *state = (struct sn_arp_state){0};
    }
}

enum sn_packet_result sn_arp_state_process(struct sn_arp_state *state,
                                           const struct sn_capture_packet *packet)
{
    struct sn_arp_packet decoded;
    enum sn_packet_result result;
    size_t position;

    if (state == NULL) {
        return SN_PACKET_MALFORMED;
    }
    increment(&state->captured);
    if (packet == NULL || packet->data == NULL ||
        packet->captured_length > packet->wire_length ||
        packet->timestamp.tv_sec < 0 || packet->timestamp.tv_usec < 0 ||
        packet->timestamp.tv_usec >= 1000000) {
        increment(&state->malformed);
        return SN_PACKET_MALFORMED;
    }
    result = sn_arp_parse_link(packet->data, packet->captured_length,
                               packet->link_type, &decoded);
    if (result != SN_PACKET_OK) {
        if (result == SN_PACKET_TRUNCATED) {
            increment(&state->truncated);
        } else if (result == SN_PACKET_MALFORMED) {
            increment(&state->malformed);
        } else {
            increment(&state->unsupported);
        }
        return result;
    }
    increment(&state->decoded);
    if (state->history_count == SN_ARP_HISTORY_CAPACITY) {
        position = state->history_start;
        state->history_start = (state->history_start + 1U) % SN_ARP_HISTORY_CAPACITY;
    } else {
        position = (state->history_start + state->history_count) % SN_ARP_HISTORY_CAPACITY;
        ++state->history_count;
    }
    state->history[position] = (struct sn_arp_observation){
        .packet = decoded,
        .timestamp = packet->timestamp,
        .captured_length = packet->captured_length,
        .wire_length = packet->wire_length,
        .link_type = packet->link_type
    };
    return SN_PACKET_OK;
}

const struct sn_arp_observation *sn_arp_state_at(const struct sn_arp_state *state,
                                                 size_t index)
{
    if (state == NULL || index >= state->history_count) {
        return NULL;
    }
    return &state->history[(state->history_start + index) % SN_ARP_HISTORY_CAPACITY];
}