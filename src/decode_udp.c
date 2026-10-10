#include "protocol_decode_internal.h"

#include <stdio.h>

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

bool sn_decode_udp(const struct sn_packet_view *packet,
                   char *output,
                   size_t output_capacity)
{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t datagram_length;
    char application[96];

    if (packet == NULL || output == NULL || output_capacity == 0U ||
        !packet->transport_header_present || packet->transport == NULL ||
        packet->transport_length < 8U) {
        return false;
    }
    source_port = read_be16(packet->transport);
    destination_port = read_be16(packet->transport + 2U);
    datagram_length = read_be16(packet->transport + 4U);
    if (datagram_length < 8U || datagram_length > packet->transport_length ||
        packet->payload_length != (size_t)datagram_length - 8U) {
        return false;
    }
    application[0] = '\0';
    if ((source_port == 161U || source_port == 162U ||
         destination_port == 161U || destination_port == 162U) &&
        sn_decode_snmp(packet->payload, packet->payload_length,
                       application, sizeof(application))) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "UDP %u->%u len=%u payload=%zu; %s",
                        source_port, destination_port, datagram_length,
                packet->payload_length, application), output_capacity);
    }
    if ((source_port == 123U || destination_port == 123U) &&
        sn_decode_ntp(packet->payload, packet->payload_length,
                      application, sizeof(application))) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "UDP %u->%u len=%u payload=%zu; %s",
                        source_port, destination_port, datagram_length,
                        packet->payload_length, application), output_capacity);
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
                    "UDP %u->%u len=%u payload=%zu",
                    source_port, destination_port, datagram_length,
                    packet->payload_length), output_capacity);
}