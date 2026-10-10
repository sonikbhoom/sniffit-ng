#ifndef SNIFFIT_NG_PACKET_H
#define SNIFFIT_NG_PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum sn_packet_result {
    SN_PACKET_OK,
    SN_PACKET_UNSUPPORTED,
    SN_PACKET_TRUNCATED,
    SN_PACKET_MALFORMED
};

struct sn_packet_view {
    uint8_t source_ipv4[4];
    uint8_t destination_ipv4[4];
    uint8_t protocol;
    uint16_t fragment_offset;
    bool more_fragments;
    bool transport_header_present;
    bool ipv4_checksum_valid;
    size_t ipv4_header_length;
    size_t ipv4_total_length;
    const uint8_t *transport;
    size_t transport_length;
    const uint8_t *payload;
    size_t payload_length;
};

enum sn_packet_result sn_packet_parse_ethernet_ipv4(
    const uint8_t *captured,
    size_t captured_length,
    struct sn_packet_view *view);

#endif
