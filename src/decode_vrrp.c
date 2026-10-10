#include "protocol_decode_internal.h"

#include <stdio.h>

bool sn_decode_vrrp(const struct sn_packet_view *packet,
                    char *output,
                    size_t output_capacity)
{
    const uint8_t *vrrp;
    uint8_t version;
    uint8_t packet_type;
    size_t address_count;
    size_t minimum_length;
    uint16_t interval;

    if (packet == NULL || output == NULL || output_capacity == 0U ||
        !packet->transport_header_present || packet->transport == NULL ||
        packet->transport_length < 8U) {
        return false;
    }
    vrrp = packet->transport;
    version = (uint8_t)(vrrp[0] >> 4);
    packet_type = (uint8_t)(vrrp[0] & 0x0fU);
    address_count = vrrp[3];
    minimum_length = 8U + address_count * 4U;
    if ((version != 2U && version != 3U) || packet_type != 1U ||
        minimum_length > packet->transport_length) {
        return false;
    }
    interval = version == 2U ? vrrp[5] :
        (uint16_t)(((uint16_t)(vrrp[4] & 0x0fU) << 8) | vrrp[5]);
    return sn_decode_result_fits(snprintf(output, output_capacity,
                    "VRRPv%u advert vrid=%u priority=%u addresses=%zu interval=%u",
                    version, vrrp[1], vrrp[2], address_count, interval), output_capacity);
}