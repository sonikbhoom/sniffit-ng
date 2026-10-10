#include "protocol_decode_internal.h"

#include <stdio.h>

bool sn_decode_syslog(const uint8_t *bytes,
                      size_t length,
                      char *output,
                      size_t output_capacity)
{
    size_t cursor = 1U;
    unsigned int priority = 0U;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < 4U || bytes[0] != '<') {
        return false;
    }
    while (cursor < length && bytes[cursor] >= '0' && bytes[cursor] <= '9' &&
           cursor <= 3U) {
        priority = priority * 10U + (unsigned int)(bytes[cursor] - '0');
        ++cursor;
    }
    if (cursor == 1U || cursor > 4U || cursor >= length ||
        bytes[cursor] != '>' || priority > 191U) {
        return false;
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
        "Syslog PRI=%u facility=%u severity=%u message-bytes=%zu",
        priority, priority / 8U, priority % 8U, length - cursor - 1U), output_capacity);
}