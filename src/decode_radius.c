#include "protocol_decode_internal.h"

#include <stdio.h>

#define RADIUS_HEADER_LENGTH 20U

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static const char *code_name(uint8_t code)
{
    switch (code) {
    case 1U: return "Access-Request";
    case 2U: return "Access-Accept";
    case 3U: return "Access-Reject";
    case 4U: return "Accounting-Request";
    case 5U: return "Accounting-Response";
    case 11U: return "Access-Challenge";
    case 12U: return "Status-Server";
    case 13U: return "Status-Client";
    default: return "other";
    }
}

bool sn_decode_radius(const uint8_t *bytes,
                      size_t length,
                      char *output,
                      size_t output_capacity)
{
    uint16_t packet_length;
    size_t cursor = RADIUS_HEADER_LENGTH;
    size_t attribute_count = 0U;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < RADIUS_HEADER_LENGTH) {
        return false;
    }
    packet_length = read_be16(bytes + 2U);
    if (packet_length < RADIUS_HEADER_LENGTH || packet_length > length) {
        return false;
    }
    while (cursor < packet_length) {
        size_t attribute_length;
        if (packet_length - cursor < 2U) {
            return false;
        }
        attribute_length = bytes[cursor + 1U];
        if (attribute_length < 2U || attribute_length > packet_length - cursor) {
            return false;
        }
        ++attribute_count;
        cursor += attribute_length;
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
        "RADIUS %s id=%u bytes=%u attributes=%zu",
        code_name(bytes[0]), bytes[1], packet_length, attribute_count), output_capacity);
}