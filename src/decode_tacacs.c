#include "protocol_decode_internal.h"

#include <stdio.h>

#define TACACS_HEADER_LENGTH 12U

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static const char *packet_type_name(uint8_t packet_type)
{
    switch (packet_type) {
    case 1U: return "authentication";
    case 2U: return "authorization";
    case 3U: return "accounting";
    default: return NULL;
    }
}

bool sn_decode_tacacs(const uint8_t *bytes,
                      size_t length,
                      char *output,
                      size_t output_capacity)
{
    const char *name;
    uint32_t body_length;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < TACACS_HEADER_LENGTH ||
        (bytes[0] & 0xf0U) != 0xc0U || bytes[2] == 0U) {
        return false;
    }
    name = packet_type_name(bytes[1]);
    body_length = read_be32(bytes + 8U);
    if (name == NULL || body_length > length - TACACS_HEADER_LENGTH) {
        return false;
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
        "TACACS+ %s version=0x%02x seq=%u flags=0x%02x body-bytes=%u",
        name, bytes[0], bytes[2], bytes[3], body_length), output_capacity);
}