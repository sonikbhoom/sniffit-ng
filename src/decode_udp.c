#include "protocol_decode_internal.h"
#include "sniffit_ng/protocol_decode.h"

#include <stdio.h>

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static bool is_media_port(uint16_t port)
{
    return port == 5004U || port == 5005U || (port >= 16384U && port <= 32767U);
}

bool sn_decode_udp(const struct sn_packet_view *packet,
                   char *output,
                   size_t output_capacity)
{
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t datagram_length;
    char application[SN_PACKET_DECODE_TEXT_CAPACITY];

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
    if ((source_port == 67U || source_port == 68U ||
         destination_port == 67U || destination_port == 68U) &&
        sn_decode_dhcp4(packet->payload, packet->payload_length,
                        application, sizeof(application))) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "UDP %u->%u len=%u payload=%zu; %s",
                        source_port, destination_port, datagram_length,
                        packet->payload_length, application), output_capacity);
    }
    if ((source_port == 53U || destination_port == 53U) &&
        sn_decode_dns(packet->payload, packet->payload_length,
                      output, output_capacity)) {
        return true;
    }
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
                      output, output_capacity)) {
        return true;
    }
    if ((source_port == 443U || destination_port == 443U) &&
        sn_decode_quic(packet->payload, packet->payload_length,
                       application, sizeof(application))) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "UDP %u->%u len=%u payload=%zu; %s",
                        source_port, destination_port, datagram_length,
                        packet->payload_length, application), output_capacity);
    }
    if ((source_port == 514U || destination_port == 514U) &&
        sn_decode_syslog(packet->payload, packet->payload_length,
                         application, sizeof(application))) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "UDP %u->%u len=%u payload=%zu; %s",
                        source_port, destination_port, datagram_length,
                        packet->payload_length, application), output_capacity);
    }
    if ((source_port == 1812U || source_port == 1813U ||
         source_port == 1645U || source_port == 1646U ||
         destination_port == 1812U || destination_port == 1813U ||
         destination_port == 1645U || destination_port == 1646U) &&
        sn_decode_radius(packet->payload, packet->payload_length,
                         application, sizeof(application))) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "UDP %u->%u len=%u payload=%zu; %s",
                        source_port, destination_port, datagram_length,
                        packet->payload_length, application), output_capacity);
    }
    if ((is_media_port(source_port) || is_media_port(destination_port)) &&
        sn_decode_rtcp(packet->payload, packet->payload_length,
                       application, sizeof(application))) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "UDP %u->%u len=%u payload=%zu; %s",
                        source_port, destination_port, datagram_length,
                        packet->payload_length, application), output_capacity);
    }
    if ((is_media_port(source_port) || is_media_port(destination_port)) &&
        sn_decode_rtp(packet->payload, packet->payload_length,
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