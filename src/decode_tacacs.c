#include "decode_placeholder_internal.h"

bool sn_decode_tacacs(const uint8_t *bytes, size_t length, char *output, size_t output_capacity)
{
    return sn_decode_placeholder(bytes, length, output, output_capacity);
}