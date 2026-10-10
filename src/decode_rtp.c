#include "protocol_decode_internal.h"

#include <stdio.h>

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

bool sn_decode_rtp(const uint8_t *bytes,
                   size_t length,
                   char *output,
                   size_t output_capacity)
{
    uint8_t version;
    uint8_t csrc_count;
    size_t header_length;
    uint8_t payload_type;
    bool marker;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < 12U) {
        return false;
    }
    version = (uint8_t)(bytes[0] >> 6);
    csrc_count = (uint8_t)(bytes[0] & 0x0fU);
    if (version != 2U) {
        return false;
    }
    header_length = 12U + (size_t)csrc_count * 4U;
    if (header_length > length) {
        return false;
    }
    if ((bytes[0] & 0x10U) != 0U) {
        size_t extension_length;
        if (length - header_length < 4U) {
            return false;
        }
        extension_length = (size_t)read_be16(bytes + header_length + 2U) * 4U;
        if (extension_length > length - header_length - 4U) {
            return false;
        }
        header_length += 4U + extension_length;
    }
    if ((bytes[0] & 0x20U) != 0U) {
        uint8_t padding_length = bytes[length - 1U];
        if (padding_length == 0U || padding_length > length - header_length) {
            return false;
        }
    }
    payload_type = (uint8_t)(bytes[1] & 0x7fU);
    marker = (bytes[1] & 0x80U) != 0U;
    return sn_decode_result_fits(snprintf(output, output_capacity,
        "RTP v2 pt=%u marker=%u seq=%u timestamp=%u ssrc=%08x csrc=%u payload=%zu",
        payload_type, marker ? 1U : 0U, read_be16(bytes + 2U),
        read_be32(bytes + 4U), read_be32(bytes + 8U), csrc_count,
        length - header_length), output_capacity);
}