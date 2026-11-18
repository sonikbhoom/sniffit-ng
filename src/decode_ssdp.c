#include "protocol_decode_internal.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

static bool read_line(const uint8_t **cursor, const uint8_t *end, size_t *length)
{
    const uint8_t *newline = memchr(*cursor, '\n', (size_t)(end - *cursor));

    if (newline == NULL || newline == *cursor || newline[-1] != '\r') {
        return false;
    }
    *length = (size_t)(newline - *cursor) - 1U;
    for (size_t index = 0U; index < *length; ++index) {
        uint8_t byte = (*cursor)[index];
        if (byte != '\t' && (byte < 0x20U || byte > 0x7eU)) {
            return false;
        }
    }
    *cursor = newline + 1U;
    return true;
}

bool sn_decode_ssdp(const uint8_t *bytes, size_t length, char *output, size_t capacity)
{
    static const char search[] = "M-SEARCH * HTTP/1.1";
    static const char notify[] = "NOTIFY * HTTP/1.1";
    static const char reply[] = "HTTP/1.1 200";
    const uint8_t *cursor = bytes;
    const uint8_t *end;
    const uint8_t *target = NULL;
    size_t target_length = 0U;
    size_t line_length;
    const char *kind;
    const char *field = "ST";

    if (bytes == NULL || length == 0U || length > 8192U || output == NULL || capacity == 0U) {
        return false;
    }
    end = bytes + length;
    if (!read_line(&cursor, end, &line_length)) {
        return false;
    }
    if (line_length == sizeof(search) - 1U && memcmp(bytes, search, line_length) == 0) {
        kind = "M-SEARCH";
    } else if (line_length == sizeof(notify) - 1U && memcmp(bytes, notify, line_length) == 0) {
        kind = "NOTIFY";
        field = "NT";
    } else if (line_length >= sizeof(reply) - 1U && memcmp(bytes, reply, sizeof(reply) - 1U) == 0 &&
               (line_length == sizeof(reply) - 1U || bytes[sizeof(reply) - 1U] == ' ')) {
        kind = "200 OK";
    } else {
        return false;
    }

    while (cursor < end) {
        const uint8_t *line = cursor;
        const uint8_t *colon;

        if (!read_line(&cursor, end, &line_length)) {
            return false;
        }
        if (line_length == 0U) {
            if (target == NULL || cursor != end) {
                return false;
            }
            return sn_decode_result_fits(snprintf(output, capacity, "SSDP %s %s=%.*s",
                kind, field, (int)target_length, (const char *)target), capacity);
        }
        colon = memchr(line, ':', line_length);
        if (colon == NULL || colon == line || line[0] == ' ' || line[0] == '\t') {
            return false;
        }
        if (colon - line == 2 && strncasecmp((const char *)line, field, 2U) == 0) {
            const uint8_t *value = colon + 1U;
            const uint8_t *value_end = line + line_length;

            while (value < value_end && (*value == ' ' || *value == '\t')) {
                ++value;
            }
            while (value_end > value && (value_end[-1] == ' ' || value_end[-1] == '\t')) {
                --value_end;
            }
            if (target != NULL || value == value_end || (size_t)(value_end - value) > 160U) {
                return false;
            }
            for (const uint8_t *byte = value; byte < value_end; ++byte) {
                if (*byte < 0x21U) {
                    return false;
                }
            }
            target = value;
            target_length = (size_t)(value_end - value);
        }
    }
    return false;
}