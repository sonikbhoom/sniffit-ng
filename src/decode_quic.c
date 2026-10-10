#include "protocol_decode_internal.h"

#include <stdio.h>

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static const char *version_name(uint32_t version)
{
    switch (version) {
    case 0U: return "negotiation";
    case 1U: return "v1";
    case 0x6b3343cfU: return "v2";
    default: return "unknown";
    }
}

bool sn_decode_quic(const uint8_t *bytes,
                    size_t length,
                    char *output,
                    size_t output_capacity)
{
    uint8_t first_byte;
    int formatted_length;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length == 0U) {
        return false;
    }
    first_byte = bytes[0];
    if ((first_byte & 0x40U) == 0U) {
        return false;
    }
    if ((first_byte & 0x80U) == 0U) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
                                "QUIC short-header payload=%zu",
                                length - 1U), output_capacity);
    }
    if (length < 7U) {
        return false;
    }
    uint32_t version = read_be32(bytes + 1U);
    size_t cursor = 5U;
    size_t destination_id_length = bytes[cursor++];

    if (destination_id_length > 20U || destination_id_length > length - cursor) {
        return false;
    }
    cursor += destination_id_length;
    if (cursor >= length) {
        return false;
    }
    size_t source_id_length = bytes[cursor++];
    if (source_id_length > 20U || source_id_length > length - cursor) {
        return false;
    }
    cursor += source_id_length;
    if (version == 0U && (length - cursor == 0U || (length - cursor) % 4U != 0U)) {
        return false;
    }
    formatted_length = snprintf(output, output_capacity,
        "QUIC %s long-header type=%u version=0x%08x dcid-len=%zu scid-len=%zu",
        version_name(version), (unsigned int)((first_byte >> 4) & 0x03U), version,
        destination_id_length, source_id_length);
    return sn_decode_result_fits(formatted_length, output_capacity);
}