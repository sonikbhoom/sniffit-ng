#include "protocol_decode_internal.h"

#include <stdio.h>

#define SSH_PORT 22U
#define IPV4_MIN_HEADER_LENGTH 20U
#define IPV4_MAX_HEADER_LENGTH 60U
#define TCP_MIN_HEADER_LENGTH 20U
#define TCP_MAX_HEADER_LENGTH 60U

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static bool append_hex(char *output,
                       size_t output_capacity,
                       size_t *offset,
                       const uint8_t *bytes,
                       size_t length)
{
    for (size_t index = 0U; index < length; ++index) {
        int written;

        if (*offset >= output_capacity || output_capacity - *offset <= 2U) {
            return false;
        }
        written = snprintf(output + *offset, output_capacity - *offset,
                           "%02x", bytes[index]);
        if (written != 2) {
            return false;
        }
        *offset += (size_t)written;
    }
    return true;
}

bool sn_decode_ssh_raw_headers(const struct sn_packet_view *packet,
                               char *output,
                               size_t output_capacity)
{
    size_t tcp_header_length;
    size_t offset;
    int prefix_length;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (packet == NULL || packet->protocol != 6U ||
        !packet->transport_header_present || packet->ipv4_packet == NULL ||
        packet->transport == NULL ||
        packet->ipv4_header_length < IPV4_MIN_HEADER_LENGTH ||
        packet->ipv4_header_length > IPV4_MAX_HEADER_LENGTH ||
        packet->ipv4_packet_length != packet->ipv4_total_length ||
        packet->ipv4_header_length > packet->ipv4_packet_length ||
        packet->ipv4_packet[0] >> 4 != 4U ||
        (size_t)(packet->ipv4_packet[0] & 0x0fU) * 4U !=
            packet->ipv4_header_length ||
        packet->transport != packet->ipv4_packet + packet->ipv4_header_length ||
        packet->transport_length !=
            packet->ipv4_packet_length - packet->ipv4_header_length ||
        packet->transport_length < TCP_MIN_HEADER_LENGTH) {
        return false;
    }
    if (read_be16(packet->transport) != SSH_PORT &&
        read_be16(packet->transport + 2U) != SSH_PORT) {
        return false;
    }

    tcp_header_length = (size_t)(packet->transport[12] >> 4) * 4U;
    if (tcp_header_length < TCP_MIN_HEADER_LENGTH ||
        tcp_header_length > TCP_MAX_HEADER_LENGTH ||
        tcp_header_length > packet->transport_length ||
        packet->payload_length != packet->transport_length - tcp_header_length) {
        return false;
    }

    prefix_length = snprintf(output, output_capacity,
        "TCP %u->%u flags=0x%02x seq=%u ack=%u win=%u payload=%zu; "
        "SSH headers IPv4=%zu TCP=%zu hex=",
        read_be16(packet->transport), read_be16(packet->transport + 2U),
        packet->transport[13], read_be32(packet->transport + 4U),
        read_be32(packet->transport + 8U), read_be16(packet->transport + 14U),
        packet->payload_length, packet->ipv4_header_length, tcp_header_length);
    if (!sn_decode_result_fits(prefix_length, output_capacity) ||
        (size_t)prefix_length +
            2U * (packet->ipv4_header_length + tcp_header_length) >=
                output_capacity) {
        prefix_length = snprintf(output, output_capacity, "SSH hdr %zu/%zu ",
                                 packet->ipv4_header_length, tcp_header_length);
    }
    if (!sn_decode_result_fits(prefix_length, output_capacity)) {
        output[0] = '\0';
        return false;
    }
    offset = (size_t)prefix_length;
    if (!append_hex(output, output_capacity, &offset, packet->ipv4_packet,
                    packet->ipv4_header_length) ||
        !append_hex(output, output_capacity, &offset, packet->transport,
                    tcp_header_length)) {
        output[0] = '\0';
        return false;
    }
    return true;
}
