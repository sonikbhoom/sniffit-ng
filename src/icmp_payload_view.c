#include "sniffit_ng/icmp_payload_view.h"

#include <ctype.h>
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
