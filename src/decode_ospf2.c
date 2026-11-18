#include "protocol_decode_internal.h"

#include <stdio.h>

bool sn_decode_ospf2(const uint8_t *bytes, size_t length, char *output, size_t output_capacity)
{
    static const char *const types[] = {"Hello", "Database description", "Link-state request",
                                       "Link-state update", "Link-state acknowledgment"};
    if (bytes == NULL || length < 24U || output == NULL || output_capacity == 0U ||
        bytes[0] != 2U || bytes[1] == 0U || bytes[1] > 5U) {
        return false;
    }
    unsigned int declared = ((unsigned int)bytes[2] << 8) | bytes[3];
    if (declared < 24U || declared > length) {
        return false;
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
                "OSPFv2 %s length=%u router=%u.%u.%u.%u area=%u.%u.%u.%u auth-type=%u",
                types[bytes[1] - 1U], declared, bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11],
                ((unsigned int)bytes[14] << 8) | bytes[15]), output_capacity);
}
