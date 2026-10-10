#include "sniffit_ng/protocol_decode.h"

#include "protocol_decode_internal.h"

#include <string.h>

bool sn_protocol_decode(const struct sn_packet_view *packet,
                        char *output,
                        size_t output_capacity)
{
    bool decoded = false;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (packet == NULL) {
        return false;
    }

    switch (packet->protocol) {
    case 1U:
        decoded = sn_decode_icmp(packet, output, output_capacity);
        break;
    case 2U:
        decoded = sn_decode_igmp(packet, output, output_capacity);
        break;
    case 6U:
        decoded = sn_decode_tcp(packet, output, output_capacity);
        break;
    case 17U:
        decoded = sn_decode_udp(packet, output, output_capacity);
        break;
    case 112U:
        decoded = sn_decode_vrrp(packet, output, output_capacity);
        break;
    default:
        break;
    }
    if (!decoded) {
        output[0] = '\0';
    }
    return decoded;
}