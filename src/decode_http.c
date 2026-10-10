#include "protocol_decode_internal.h"
#include "sniffit_ng/http_decode_extension.h"

#include <stdio.h>
#include <string.h>

#define HTTP_LINE_SCAN_LIMIT 4096U
#define HTTP_HOST_CAPACITY 128U
#define HTTP_HEADER_VALUE_CAPACITY 64U

static bool is_token_character(uint8_t byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
           (byte >= 'a' && byte <= 'z') ||
           (byte >= '0' && byte <= '9') ||
           byte == '!' || byte == '#' || byte == '$' || byte == '%' ||
           byte == '&' || byte == '\'' || byte == '*' || byte == '+' ||
           byte == '-' || byte == '.' || byte == '^' || byte == '_' ||
           byte == '`' || byte == '|' || byte == '~';
}

static bool ascii_equal_case(const uint8_t *bytes, size_t length, const char *text)
{
    size_t text_length = strlen(text);

    if (length != text_length) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        uint8_t byte = bytes[index];
        if (byte >= 'A' && byte <= 'Z') {
            byte = (uint8_t)(byte - 'A' + 'a');
        }
        if (byte != (uint8_t)text[index]) {
            return false;
        }
    }
    return true;
}

static bool find_line_end(const uint8_t *bytes,
                          size_t length,
                          size_t start,
                          size_t *end)
{
    for (size_t index = start; index + 1U < length; ++index) {
        if (bytes[index] == '\r' && bytes[index + 1U] == '\n') {
            *end = index;
            return true;
        }
        if (bytes[index] == '\n' || bytes[index] == '\0') {
            return false;
        }
    }
    return false;
}

static const char *method_name(const uint8_t *bytes, size_t length)
{
    static const char *const methods[] = {
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS",
        "TRACE", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
        "MOVE", "LOCK", "UNLOCK"
    };

    for (size_t index = 0U; index < sizeof(methods) / sizeof(methods[0]); ++index) {
        if (length == strlen(methods[index]) &&
            memcmp(bytes, methods[index], length) == 0) {
            return methods[index];
        }
    }
    return "OTHER";
}

static bool valid_host_character(uint8_t byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
           (byte >= 'a' && byte <= 'z') ||
           (byte >= '0' && byte <= '9') ||
           byte == '.' || byte == '-' || byte == ':' ||
           byte == '[' || byte == ']';
}

static bool valid_header_value_character(uint8_t byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
           (byte >= 'a' && byte <= 'z') ||
           (byte >= '0' && byte <= '9') ||
           byte == ' ' || byte == '.' || byte == '_' || byte == '-' ||
           byte == '/' || byte == '+' || byte == ';' || byte == '=' ||
           byte == ',' || byte == '(' || byte == ')';
}

static void copy_header_value(const uint8_t *bytes,
                              size_t value_start,
                              size_t end,
                              char value[HTTP_HEADER_VALUE_CAPACITY])
{
    size_t value_length = end - value_start;

    while (value_length > 0U &&
           (bytes[value_start + value_length - 1U] == ' ' ||
            bytes[value_start + value_length - 1U] == '\t')) {
        --value_length;
    }
    if (value_length == 0U || value_length >= HTTP_HEADER_VALUE_CAPACITY) {
        return;
    }
    for (size_t index = 0U; index < value_length; ++index) {
        if (!valid_header_value_character(bytes[value_start + index])) {
            return;
        }
        value[index] = (char)bytes[value_start + index];
    }
    value[value_length] = '\0';
}

static void find_host(const uint8_t *bytes,
                      size_t length,
                      size_t cursor,
                      char host[HTTP_HOST_CAPACITY])
{
    size_t scan_length = length < HTTP_LINE_SCAN_LIMIT ? length : HTTP_LINE_SCAN_LIMIT;

    host[0] = '\0';
    while (cursor < scan_length) {
        size_t end;
        size_t colon;

        if (!find_line_end(bytes, scan_length, cursor, &end) || end == cursor) {
            return;
        }
        for (colon = cursor; colon < end && bytes[colon] != ':'; ++colon) {
        }
        if (colon < end && ascii_equal_case(bytes + cursor, colon - cursor, "host")) {
            size_t value_start = colon + 1U;
            size_t value_length;

            while (value_start < end &&
                   (bytes[value_start] == ' ' || bytes[value_start] == '\t')) {
                ++value_start;
            }
            value_length = end - value_start;
            while (value_length > 0U &&
                   (bytes[value_start + value_length - 1U] == ' ' ||
                    bytes[value_start + value_length - 1U] == '\t')) {
                --value_length;
            }
            if (value_length == 0U || value_length >= HTTP_HOST_CAPACITY) {
                return;
            }
            for (size_t index = 0U; index < value_length; ++index) {
                if (!valid_host_character(bytes[value_start + index])) {
                    return;
                }
                host[index] = (char)bytes[value_start + index];
            }
            host[value_length] = '\0';
            return;
        }
        cursor = end + 2U;
    }
}

static void find_response_metadata(const uint8_t *bytes,
                                   size_t length,
                                   size_t cursor,
                                   char server[HTTP_HEADER_VALUE_CAPACITY],
                                   char content_type[HTTP_HEADER_VALUE_CAPACITY],
                                   char content_length[16])
{
    size_t scan_length = length < HTTP_LINE_SCAN_LIMIT ? length : HTTP_LINE_SCAN_LIMIT;

    server[0] = '\0';
    content_type[0] = '\0';
    content_length[0] = '\0';
    while (cursor < scan_length) {
        size_t end;
        size_t colon;

        if (!find_line_end(bytes, scan_length, cursor, &end)) {
            return;
        }
        if (end == cursor) {
            return;
        }
        for (colon = cursor; colon < end && bytes[colon] != ':'; ++colon) {
        }
        if (colon == end) {
            return;
        }
        size_t value_start = colon + 1U;
        while (value_start < end &&
               (bytes[value_start] == ' ' || bytes[value_start] == '\t')) {
            ++value_start;
        }
        if (ascii_equal_case(bytes + cursor, colon - cursor, "server")) {
            copy_header_value(bytes, value_start, end, server);
        } else if (ascii_equal_case(bytes + cursor, colon - cursor, "content-type")) {
            copy_header_value(bytes, value_start, end, content_type);
        } else if (ascii_equal_case(bytes + cursor, colon - cursor, "content-length")) {
            size_t value_length = end - value_start;
            if (value_length > 0U && value_length < 16U) {
                bool digits_only = true;
                for (size_t index = 0U; index < value_length; ++index) {
                    if (bytes[value_start + index] < '0' || bytes[value_start + index] > '9') {
                        digits_only = false;
                        break;
                    }
                }
                if (digits_only) {
                    (void)memcpy(content_length, bytes + value_start, value_length);
                    content_length[value_length] = '\0';
                }
            }
        }
        cursor = end + 2U;
    }
}

static bool output_fits(int formatted_length, char *output, size_t output_capacity)
{
    if (!sn_decode_result_fits(formatted_length, output_capacity)) {
        output[0] = '\0';
        return false;
    }
    return true;
}

static bool append_custom_metadata(const uint8_t *bytes,
                                   size_t length,
                                   char *output,
                                   size_t output_capacity)
{
    char extension[SN_HTTP_EXTENSION_OUTPUT_CAPACITY] = {0};
    size_t extension_length = 0U;
    size_t output_length;
    int formatted_length;

    if (!sn_http_decode_extension(bytes, length, extension, sizeof(extension))) {
        return true;
    }
    while (extension_length < sizeof(extension) && extension[extension_length] != '\0') {
        uint8_t character = (uint8_t)extension[extension_length];
        if (character < 0x20U || character > 0x7eU) {
            extension[extension_length] = '.';
        }
        ++extension_length;
    }
    if (extension_length == 0U || extension_length == sizeof(extension)) {
        return true;
    }
    output_length = strlen(output);
    if (output_length >= output_capacity) {
        output[0] = '\0';
        return false;
    }
    formatted_length = snprintf(output + output_length,
                                output_capacity - output_length,
                                " custom=%s", extension);
    if (!sn_decode_result_fits(formatted_length, output_capacity - output_length)) {
        output[output_length] = '\0';
    }
    return true;
}

bool sn_decode_http(const uint8_t *bytes,
                    size_t length,
                    char *output,
                    size_t output_capacity)
{
    size_t first_line_end;
    size_t first_space = 0U;
    size_t second_space;
    char host[HTTP_HOST_CAPACITY];
    char server[HTTP_HEADER_VALUE_CAPACITY];
    char content_type[HTTP_HEADER_VALUE_CAPACITY];
    char content_length[16];
    size_t base_length;
    int formatted_length;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < 14U ||
        !find_line_end(bytes, length, 0U, &first_line_end)) {
        return false;
    }

    if (first_line_end >= 12U && bytes[8] == ' ' &&
        (memcmp(bytes, "HTTP/1.0", 8U) == 0 || memcmp(bytes, "HTTP/1.1", 8U) == 0)) {
        size_t status_start = 9U;
        size_t status_end = status_start + 3U;

        if (status_end > first_line_end ||
            (status_end < first_line_end && bytes[status_end] != ' ') ||
            bytes[status_start] < '1' || bytes[status_start] > '5' ||
            bytes[status_start + 1U] < '0' || bytes[status_start + 1U] > '9' ||
            bytes[status_start + 2U] < '0' || bytes[status_start + 2U] > '9') {
            return false;
        }
        formatted_length = snprintf(output, output_capacity,
                                    "HTTP response version=%.8s status=%u%u%u",
                                    bytes, (unsigned int)(bytes[status_start] - '0'),
                                    (unsigned int)(bytes[status_start + 1U] - '0'),
                                    (unsigned int)(bytes[status_start + 2U] - '0'));
        if (!output_fits(formatted_length, output, output_capacity)) {
            return false;
        }
        base_length = strlen(output);
        find_response_metadata(bytes, length, first_line_end + 2U,
                               server, content_type, content_length);
        if (server[0] != '\0' && content_type[0] != '\0' && content_length[0] != '\0') {
            formatted_length = snprintf(output + strlen(output),
                                        output_capacity - strlen(output),
                                        " server=%s type=%s bytes=%s",
                                        server, content_type, content_length);
        } else if (server[0] != '\0' && content_type[0] != '\0') {
            formatted_length = snprintf(output + strlen(output),
                                        output_capacity - strlen(output),
                                        " server=%s type=%s", server, content_type);
        } else if (server[0] != '\0' && content_length[0] != '\0') {
            formatted_length = snprintf(output + strlen(output),
                                        output_capacity - strlen(output),
                                        " server=%s bytes=%s", server, content_length);
        } else if (content_type[0] != '\0' && content_length[0] != '\0') {
            formatted_length = snprintf(output + strlen(output),
                                        output_capacity - strlen(output),
                                        " type=%s bytes=%s", content_type, content_length);
        } else if (server[0] != '\0') {
            formatted_length = snprintf(output + strlen(output),
                                        output_capacity - strlen(output),
                                        " server=%s", server);
        } else if (content_type[0] != '\0') {
            formatted_length = snprintf(output + strlen(output),
                                        output_capacity - strlen(output),
                                        " type=%s", content_type);
        } else if (content_length[0] != '\0') {
            formatted_length = snprintf(output + strlen(output),
                                        output_capacity - strlen(output),
                                        " bytes=%s", content_length);
        } else {
            return append_custom_metadata(bytes, length, output, output_capacity);
        }
        if (!sn_decode_result_fits(formatted_length, output_capacity - base_length)) {
            output[0] = '\0';
            return false;
        }
        return append_custom_metadata(bytes, length, output, output_capacity);
    }

    while (first_space < first_line_end && bytes[first_space] != ' ') {
        if (!is_token_character(bytes[first_space])) {
            return false;
        }
        ++first_space;
    }
    if (first_space == 0U || first_space >= first_line_end) {
        return false;
    }
    second_space = first_space + 1U;
    while (second_space < first_line_end && bytes[second_space] != ' ') {
        if (bytes[second_space] < 0x21U || bytes[second_space] > 0x7eU) {
            return false;
        }
        ++second_space;
    }
    if (second_space >= first_line_end || second_space == first_space + 1U) {
        return false;
    }

    if (second_space + 9U != first_line_end ||
        memcmp(bytes + second_space + 1U, "HTTP/1.", 7U) != 0 ||
        (bytes[second_space + 8U] != '0' && bytes[second_space + 8U] != '1')) {
        return false;
    }
    find_host(bytes, length, first_line_end + 2U, host);
    if (host[0] != '\0') {
        formatted_length = snprintf(output, output_capacity,
                                    "HTTP request method=%s version=%.*s host=%s",
                                    method_name(bytes, first_space),
                                    (int)(first_line_end - second_space - 1U),
                                    bytes + second_space + 1U, host);
    } else {
        formatted_length = snprintf(output, output_capacity,
                                    "HTTP request method=%s version=%.*s",
                                    method_name(bytes, first_space),
                                    (int)(first_line_end - second_space - 1U),
                                    bytes + second_space + 1U);
    }
    return output_fits(formatted_length, output, output_capacity) &&
           append_custom_metadata(bytes, length, output, output_capacity);
}
