#include "protocol_decode_internal.h"

#include <stdio.h>

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static const char *packet_type_name(uint8_t packet_type)
{
    switch (packet_type) {
    case 200U: return "SR";
    case 201U: return "RR";
    case 202U: return "SDES";
    case 203U: return "BYE";
    case 204U: return "APP";
    case 205U: return "RTPFB";
    case 206U: return "PSFB";
    case 207U: return "XR";
    default: return "other";
    }
}

bool sn_decode_rtcp(const uint8_t *bytes,
                    size_t length,
                    char *output,
                    size_t output_capacity)
{
    size_t packet_length;
    uint8_t packet_type;
    uint8_t report_count;
    uint16_t words_minus_one;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < 4U || (bytes[0] >> 6) != 2U ||
        (bytes[1] < 192U || bytes[1] > 223U)) {
        return false;
    }
    words_minus_one = read_be16(bytes + 2U);
    packet_length = ((size_t)words_minus_one + 1U) * 4U;
    if (packet_length < 4U || packet_length > length) {
        return false;
    }
    packet_type = bytes[1];
    report_count = (uint8_t)(bytes[0] & 0x1fU);
    return sn_decode_result_fits(snprintf(output, output_capacity,
        "RTCP %s count=%u bytes=%zu",
        packet_type_name(packet_type), report_count, packet_length), output_capacity);
}