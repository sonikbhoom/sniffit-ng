#include "sniffit_ng/icmp_payload_view.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

size_t sn_icmp_format_payload_row(const uint8_t *payload,
                                  size_t payload_length,
                                  char *hex_output,
                                  size_t hex_capacity,
                                  char *ascii_output,
                                  size_t ascii_capacity)
{
    static const char hex_digits[] = "0123456789abcdef";
    size_t row_length = payload_length;

    if (row_length > SN_ICMP_DISPLAY_ROW_BYTES) {
        row_length = SN_ICMP_DISPLAY_ROW_BYTES;
    }
    if ((row_length > 0U && payload == NULL) || hex_output == NULL || ascii_output == NULL ||
        hex_capacity < row_length * 3U || ascii_capacity < row_length + 1U) {
        if (hex_output != NULL && hex_capacity > 0U) {
            hex_output[0] = '\0';
        }
        if (ascii_output != NULL && ascii_capacity > 0U) {
            ascii_output[0] = '\0';
        }
        return 0U;
    }

    for (size_t index = 0U; index < row_length; ++index) {
        uint8_t byte = payload[index];
        size_t hex_offset = index * 3U;

        hex_output[hex_offset] = hex_digits[byte >> 4];
        hex_output[hex_offset + 1U] = hex_digits[byte & 0x0fU];
        hex_output[hex_offset + 2U] = index + 1U == row_length ? '\0' : ' ';
        ascii_output[index] = isprint((unsigned char)byte) ? (char)byte : '.';
    }
    hex_output[row_length == 0U ? 0U : row_length * 3U - 1U] = '\0';
    ascii_output[row_length] = '\0';
    return row_length;
}

size_t sn_icmp_format_payload_display_row(size_t row_offset,
                                          const uint8_t *payload,
                                          size_t payload_length,
                                          char *line_output,
                                          size_t line_capacity)
{
    char ascii[SN_ICMP_DISPLAY_ASCII_CAPACITY];
    size_t row_length = payload_length;
    size_t output_length = 0U;

    if (row_length > SN_ICMP_DISPLAY_ROW_BYTES) {
        row_length = SN_ICMP_DISPLAY_ROW_BYTES;
    }
    if (line_output == NULL || line_capacity == 0U ||
        (row_length > 0U && payload == NULL) ||
        row_offset > SIZE_MAX - row_length) {
        if (line_output != NULL && line_capacity > 0U) {
            line_output[0] = '\0';
        }
        return 0U;
    }
    if (sn_icmp_format_payload_row(payload, row_length, line_output,
                                   line_capacity, ascii, sizeof(ascii)) != row_length) {
        line_output[0] = '\0';
        return 0U;
    }

    output_length = 0U;
    for (size_t group_index = 0U;
         group_index < SN_ICMP_DISPLAY_GROUPS_PER_ROW; ++group_index) {
        char group_hex[SN_ICMP_DISPLAY_GROUP_BYTES * 3U];
        char group_ascii[SN_ICMP_DISPLAY_GROUP_BYTES + 1U];
        size_t group_start = group_index * SN_ICMP_DISPLAY_GROUP_BYTES;
        size_t group_cell_width = group_index == 0U ? 16U : 17U;
        size_t group_length;
        int written;

        if (group_start >= row_length) {
            if (group_cell_width >= line_capacity - output_length) {
                line_output[0] = '\0';
                return 0U;
            }
            memset(line_output + output_length, ' ', group_cell_width);
            output_length += group_cell_width;
            continue;
        }
        group_length = row_length - group_start;
        if (group_length > SN_ICMP_DISPLAY_GROUP_BYTES) {
            group_length = SN_ICMP_DISPLAY_GROUP_BYTES;
        }
        if (sn_icmp_format_payload_row(payload + group_start, group_length,
                                       group_hex, sizeof(group_hex), group_ascii,
                                       sizeof(group_ascii)) != group_length) {
            line_output[0] = '\0';
            return 0U;
        }
        written = snprintf(line_output + output_length,
                           line_capacity - output_length,
                           group_index == 0U ? "%03zu  %-11s" :
                                               " %03zu  %-11s",
                           row_offset + group_start, group_hex);
        if (written < 0 || (size_t)written >= line_capacity - output_length) {
            line_output[0] = '\0';
            return 0U;
        }
        output_length += (size_t)written;
    }

    int written = snprintf(line_output + output_length,
                           line_capacity - output_length, " |%s|", ascii);
    if (written < 0 || (size_t)written >= line_capacity - output_length) {
        line_output[0] = '\0';
        return 0U;
    }
    return row_length;
}
