#include "protocol_decode_internal.h"

#include <stdio.h>

bool sn_decode_bgp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity)
{
    static const char *const types[] = {"OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH"};
    static const unsigned int minimum[] = {29U, 23U, 21U, 19U, 23U};

    if (bytes == NULL || length < 19U || output == NULL || output_capacity == 0U ||
        bytes[18] == 0U || bytes[18] > 5U) {
        return false;
    }
    for (size_t index = 0U; index < 16U; ++index) {
        if (bytes[index] != 0xffU) {
            return false;
        }
    }
    unsigned int declared = ((unsigned int)bytes[16] << 8) | bytes[17];
    size_t type = bytes[18] - 1U;

    if (declared < minimum[type] || declared > length || (type == 3U && declared != 19U)) {
        return false;
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
                "BGP %s length=%u", types[type], declared), output_capacity);
}
