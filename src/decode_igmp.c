#include "protocol_decode_internal.h"

#include <stdio.h>

bool sn_decode_igmp(const struct sn_packet_view *packet,
                    char *output,
                    size_t output_capacity)
{
    const uint8_t *igmp;
    const char *type_name;

    if (packet == NULL || output == NULL || output_capacity == 0U ||
        !packet->transport_header_present || packet->transport == NULL ||
        packet->transport_length < 8U) {
        return false;
    }
    igmp = packet->transport;
    switch (igmp[0]) {
    case 0x11U: type_name = "Membership query"; break;
    case 0x12U: type_name = "v1 report"; break;
    case 0x16U: type_name = "v2 report"; break;
    case 0x17U: type_name = "Leave group"; break;
    case 0x22U:
        return sn_decode_result_fits(snprintf(output, output_capacity,
                "IGMP v3 report records=%u",
                (unsigned int)(((unsigned int)igmp[6] << 8) | igmp[7])),
                output_capacity);
    default: type_name = "message"; break;
    }
    if (igmp[0] == 0x11U || igmp[0] == 0x12U ||
        igmp[0] == 0x16U || igmp[0] == 0x17U) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "IGMP %s group=%u.%u.%u.%u",
                type_name, igmp[4], igmp[5], igmp[6], igmp[7]), output_capacity);
    }
        return sn_decode_result_fits(snprintf(output, output_capacity,
                "IGMP %s type=0x%02x", type_name, igmp[0]), output_capacity);
}