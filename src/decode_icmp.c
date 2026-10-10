#include "protocol_decode_internal.h"

#include <stdio.h>

bool sn_decode_icmp(const struct sn_packet_view *packet,
                    char *output,
                    size_t output_capacity)
{
    const char *name;

    if (packet == NULL || output == NULL || output_capacity == 0U ||
        !packet->transport_header_present || packet->transport_length < 4U) {
        return false;
    }
    switch (packet->icmp_type) {
    case 0U: name = "Echo reply"; break;
    case 3U: name = "Destination unreachable"; break;
    case 5U: name = "Redirect"; break;
    case 8U: name = "Echo request"; break;
    case 11U: name = "Time exceeded"; break;
    case 12U: name = "Parameter problem"; break;
    default: name = "message"; break;
    }
    if (packet->icmp_type == 0U || packet->icmp_type == 8U) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                        "ICMP %s code=%u id=%u seq=%u payload=%zu",
                        name, packet->icmp_code, packet->icmp_identifier,
                packet->icmp_sequence, packet->payload_length), output_capacity);
    }
        return sn_decode_result_fits(snprintf(output, output_capacity,
                "ICMP %s type=%u code=%u", name, packet->icmp_type,
                packet->icmp_code), output_capacity);
}