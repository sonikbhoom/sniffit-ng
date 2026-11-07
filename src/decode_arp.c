#include "decode_placeholder_internal.h"
#include "sniffit_ng/arp.h"

#include <stdio.h>
#include <string.h>

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8U) | bytes[1]);
}

enum sn_packet_result sn_arp_parse(const uint8_t *bytes, size_t length,
                                   struct sn_arp_packet *packet)
{
    size_t packet_length;
    uint16_t operation;

    if (packet == NULL) {
        return SN_PACKET_MALFORMED;
    }
    *packet = (struct sn_arp_packet){0};
    if (bytes == NULL) {
        return SN_PACKET_MALFORMED;
    }
    if (length < 8U) {
        return SN_PACKET_TRUNCATED;
    }
    if (bytes[4] == 0U || bytes[5] == 0U) {
        return SN_PACKET_MALFORMED;
    }
    packet_length = 8U + 2U * (size_t)bytes[4] + 2U * (size_t)bytes[5];
    if (length < packet_length) {
        return SN_PACKET_TRUNCATED;
    }
    operation = read_be16(bytes + 6U);
    if (read_be16(bytes) != 1U || read_be16(bytes + 2U) != 0x0800U ||
        bytes[4] != 6U || bytes[5] != 4U ||
        (operation != 1U && operation != 2U)) {
        return SN_PACKET_UNSUPPORTED;
    }
    packet->operation = operation;
    memcpy(packet->sender_mac, bytes + 8U, 6U);
    memcpy(packet->sender_ipv4, bytes + 14U, 4U);
    memcpy(packet->target_mac, bytes + 18U, 6U);
    memcpy(packet->target_ipv4, bytes + 24U, 4U);
    return SN_PACKET_OK;
}

enum sn_packet_result sn_arp_locate_link(const uint8_t *bytes, size_t length,
                                         enum sn_packet_link_type link_type,
                                         size_t *payload_offset)
{
    size_t offset;
    size_t protocol_offset;
    uint16_t protocol;

    if (payload_offset == NULL) {
        return SN_PACKET_MALFORMED;
    }
    *payload_offset = 0U;
    if (bytes == NULL) {
        return SN_PACKET_MALFORMED;
    }
    if (link_type == SN_PACKET_LINK_ETHERNET) {
        offset = 14U;
        protocol_offset = 12U;
    } else if (link_type == SN_PACKET_LINK_LINUX_SLL) {
        offset = 16U;
        protocol_offset = 14U;
    } else {
        return SN_PACKET_UNSUPPORTED;
    }
    if (length < offset) {
        return SN_PACKET_TRUNCATED;
    }
    protocol = read_be16(bytes + protocol_offset);
    for (size_t depth = 0U; protocol == 0x8100U || protocol == 0x88a8U ||
                            protocol == 0x9100U; ++depth) {
        if (depth == 2U) {
            return SN_PACKET_MALFORMED;
        }
        if (length - offset < 4U) {
            return SN_PACKET_TRUNCATED;
        }
        protocol = read_be16(bytes + offset + 2U);
        offset += 4U;
    }
    if (protocol != 0x0806U) {
        return SN_PACKET_UNSUPPORTED;
    }
    *payload_offset = offset;
    return SN_PACKET_OK;
}

enum sn_packet_result sn_arp_parse_link(const uint8_t *bytes, size_t length,
                                        enum sn_packet_link_type link_type,
                                        struct sn_arp_packet *packet)
{
    size_t offset;
    enum sn_packet_result result;

    if (packet == NULL) {
        return SN_PACKET_MALFORMED;
    }
    *packet = (struct sn_arp_packet){0};
    result = sn_arp_locate_link(bytes, length, link_type, &offset);
    if (result != SN_PACKET_OK) {
        return result;
    }
    return sn_arp_parse(bytes + offset, length - offset, packet);
}

bool sn_decode_arp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity)
{
    struct sn_arp_packet packet;
    int written;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (sn_arp_parse(bytes, length, &packet) != SN_PACKET_OK) {
        return false;
    }
    written = snprintf(output, output_capacity,
                       "ARP %s %u.%u.%u.%u (%02x:%02x:%02x:%02x:%02x:%02x) -> "
                       "%u.%u.%u.%u (%02x:%02x:%02x:%02x:%02x:%02x)",
                       packet.operation == 1U ? "request" : "reply",
                       packet.sender_ipv4[0], packet.sender_ipv4[1],
                       packet.sender_ipv4[2], packet.sender_ipv4[3],
                       packet.sender_mac[0], packet.sender_mac[1], packet.sender_mac[2],
                       packet.sender_mac[3], packet.sender_mac[4], packet.sender_mac[5],
                       packet.target_ipv4[0], packet.target_ipv4[1],
                       packet.target_ipv4[2], packet.target_ipv4[3],
                       packet.target_mac[0], packet.target_mac[1], packet.target_mac[2],
                       packet.target_mac[3], packet.target_mac[4], packet.target_mac[5]);
    if (written < 0 || (size_t)written >= output_capacity) {
        output[0] = '\0';
        return false;
    }
    return true;
}
