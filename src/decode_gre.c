#include "protocol_decode_internal.h"

#include <stdio.h>

bool sn_decode_gre(const uint8_t *bytes, size_t length, char *output, size_t output_capacity)
{
    if (bytes == NULL || length < 4U || output == NULL || output_capacity == 0U) {
        return false;
    }
    unsigned int flags = ((unsigned int)bytes[0] << 8) | bytes[1];
    size_t header = 4U;

    if ((flags & ~0xb000U) != 0U) {
        return false;
    }
    header += (flags & 0x8000U) != 0U ? 4U : 0U;
    header += (flags & 0x2000U) != 0U ? 4U : 0U;
    header += (flags & 0x1000U) != 0U ? 4U : 0U;
    if (header > length) {
        return false;
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
                "GRE protocol=0x%02x%02x flags=0x%04x header=%zu payload=%zu",
                bytes[2], bytes[3], flags, header, length - header), output_capacity);
}
