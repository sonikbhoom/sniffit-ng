#include "protocol_decode_internal.h"
#include "sniffit_ng/protocol_decode.h"

#include <stdio.h>

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

bool sn_decode_tcp(const struct sn_packet_view *packet,
                   char *output,
                   size_t output_capacity,
                   bool tainted_extensions)
{
    size_t header_length;
    const uint8_t *tcp;
    uint16_t source_port;
    uint16_t destination_port;
    char application[SN_PACKET_DECODE_TEXT_CAPACITY];
    int formatted_length;

    if (packet == NULL || output == NULL || output_capacity == 0U ||
        !packet->transport_header_present || packet->transport == NULL ||
        packet->transport_length < 20U) {
        return false;
    }
    tcp = packet->transport;
    source_port = read_be16(tcp);
    destination_port = read_be16(tcp + 2U);
    header_length = (size_t)(tcp[12] >> 4) * 4U;
    if (header_length < 20U || header_length > packet->transport_length ||
        packet->payload_length != packet->transport_length - header_length) {
        return false;
    }
    if ((source_port == 80U || destination_port == 80U ||
         source_port == 8000U || destination_port == 8000U ||
         source_port == 8080U || destination_port == 8080U) &&
        sn_decode_http(packet->payload, packet->payload_length,
                       application, sizeof(application), tainted_extensions)) {
        formatted_length = snprintf(output, output_capacity,
                    "TCP %u->%u flags=0x%02x seq=%u ack=%u win=%u payload=%zu; %s",
                    source_port, destination_port, tcp[13],
                    read_be32(tcp + 4U), read_be32(tcp + 8U),
                    read_be16(tcp + 14U), packet->payload_length, application);
    } else if ((source_port == 53U || destination_port == 53U) &&
               sn_decode_dns_tcp(packet->payload, packet->payload_length,
                                 application, sizeof(application))) {
        formatted_length = snprintf(output, output_capacity,
                    "TCP %u->%u flags=0x%02x seq=%u ack=%u win=%u payload=%zu; %s",
                    source_port, destination_port, tcp[13],
                    read_be32(tcp + 4U), read_be32(tcp + 8U),
                    read_be16(tcp + 14U), packet->payload_length, application);
    } else if ((source_port == 443U || destination_port == 443U ||
                source_port == 853U || destination_port == 853U ||
                source_port == 465U || destination_port == 465U ||
                source_port == 636U || destination_port == 636U ||
                source_port == 993U || destination_port == 993U ||
                source_port == 995U || destination_port == 995U ||
                source_port == 8443U || destination_port == 8443U) &&
               sn_decode_tls(packet->payload, packet->payload_length,
                             application, sizeof(application))) {
        formatted_length = snprintf(output, output_capacity,
                    "TCP %u->%u flags=0x%02x seq=%u ack=%u win=%u payload=%zu; %s",
                    source_port, destination_port, tcp[13],
                    read_be32(tcp + 4U), read_be32(tcp + 8U),
                    read_be16(tcp + 14U), packet->payload_length, application);
    } else if ((source_port == 49U || destination_port == 49U) &&
               sn_decode_tacacs(packet->payload, packet->payload_length,
                                application, sizeof(application))) {
        formatted_length = snprintf(output, output_capacity,
                    "TCP %u->%u flags=0x%02x seq=%u ack=%u win=%u payload=%zu; %s",
                    source_port, destination_port, tcp[13],
                    read_be32(tcp + 4U), read_be32(tcp + 8U),
                    read_be16(tcp + 14U), packet->payload_length, application);
    } else if ((source_port == 514U || destination_port == 514U) &&
               sn_decode_syslog(packet->payload, packet->payload_length,
                                application, sizeof(application))) {
        formatted_length = snprintf(output, output_capacity,
                    "TCP %u->%u flags=0x%02x seq=%u ack=%u win=%u payload=%zu; %s",
                    source_port, destination_port, tcp[13],
                    read_be32(tcp + 4U), read_be32(tcp + 8U),
                    read_be16(tcp + 14U), packet->payload_length, application);
    } else {
        formatted_length = snprintf(output, output_capacity,
                    "TCP %u->%u flags=0x%02x seq=%u ack=%u win=%u payload=%zu",
                    source_port, destination_port, tcp[13],
                    read_be32(tcp + 4U), read_be32(tcp + 8U),
                    read_be16(tcp + 14U), packet->payload_length);
    }
    return sn_decode_result_fits(formatted_length, output_capacity);
}