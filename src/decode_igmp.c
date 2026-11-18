#include "protocol_decode_internal.h"

#include <stdio.h>

static unsigned int read_count(const uint8_t *bytes)
{
    return ((unsigned int)bytes[0] << 8) | bytes[1];
}

static bool decode_v3_report(const uint8_t *igmp, size_t length,
                             char *output, size_t capacity)
{
    unsigned int count = read_count(igmp + 6U);
    size_t offset = 8U;
    const uint8_t *first_group = igmp + offset;

    for (unsigned int index = 0U; index < count; ++index) {
        if (length - offset < 8U) {
            return false;
        }
        const uint8_t *record = igmp + offset;
        size_t record_length = 8U + 4U * ((size_t)read_count(record + 2U) + record[1]);

        if (record_length > length - offset) {
            return false;
        }
        offset += record_length;
    }
    if (count == 0U) {
        return sn_decode_result_fits(snprintf(output, capacity, "IGMP v3 report records=0"), capacity);
    }
    return sn_decode_result_fits(snprintf(output, capacity,
                "IGMP v3 report records=%u first-group=%u.%u.%u.%u type=%u sources=%u",
                count, first_group[4], first_group[5], first_group[6], first_group[7],
                first_group[0], read_count(first_group + 2U)), capacity);
}

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
    case 0x11U:
        if (packet->transport_length > 8U) {
            if (packet->transport_length < 12U ||
                read_count(igmp + 10U) > (packet->transport_length - 12U) / 4U) {
                return false;
            }
            return sn_decode_result_fits(snprintf(output, output_capacity,
                "IGMP v3 query group=%u.%u.%u.%u max-response-code=%u sources=%u",
                igmp[4], igmp[5], igmp[6], igmp[7], igmp[1], read_count(igmp + 10U)),
                output_capacity);
        }
        type_name = "Membership query";
        break;
    case 0x12U: type_name = "v1 report"; break;
    case 0x16U: type_name = "v2 report"; break;
    case 0x17U: type_name = "Leave group"; break;
    case 0x22U:
        return decode_v3_report(igmp, packet->transport_length, output, output_capacity);
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
