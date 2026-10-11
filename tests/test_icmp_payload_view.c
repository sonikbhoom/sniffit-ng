#include "sniffit_ng/icmp_payload_view.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_binary_payload_formats_as_hex_and_safe_ascii(void)
{
    const uint8_t payload[] = {'p', 'i', 'n', 'g', 0U, 0xffU, 'A'};
    char hex[SN_ICMP_DISPLAY_HEX_CAPACITY];
    char ascii[SN_ICMP_DISPLAY_ASCII_CAPACITY];

    assert(sn_icmp_format_payload_row(payload, sizeof(payload),
                                      hex, sizeof(hex), ascii, sizeof(ascii)) == sizeof(payload));
    assert(strcmp(hex, "70 69 6e 67 00 ff 41") == 0);
    assert(strcmp(ascii, "ping..A") == 0);
}

static void test_rows_are_capped_at_twelve_bytes(void)
{
    uint8_t payload[SN_ICMP_DISPLAY_ROW_BYTES + 4U];
    char hex[SN_ICMP_DISPLAY_HEX_CAPACITY];
    char ascii[SN_ICMP_DISPLAY_ASCII_CAPACITY];

    for (size_t index = 0U; index < sizeof(payload); ++index) {
        payload[index] = (uint8_t)('a' + index);
    }
    assert(sn_icmp_format_payload_row(payload, sizeof(payload),
                                      hex, sizeof(hex), ascii, sizeof(ascii)) ==
           SN_ICMP_DISPLAY_ROW_BYTES);
    assert(strlen(ascii) == SN_ICMP_DISPLAY_ROW_BYTES);
    assert(strlen(hex) == SN_ICMP_DISPLAY_ROW_BYTES * 3U - 1U);
}

static void test_display_row_combines_three_groups_and_ascii(void)
{
    const uint8_t payload[] = {
        0x78U, 0xb2U, 0xcbU, 0x6aU,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x41U, 0x42U, 0x43U, 0x44U
    };
    char line[SN_ICMP_DISPLAY_LINE_CAPACITY];

    assert(sn_icmp_format_payload_display_row(0U, payload, sizeof(payload),
                                              line, sizeof(line)) == sizeof(payload));
    assert(strcmp(line,
                  "000  78 b2 cb 6a 004  00 00 00 00 008  41 42 43 44 |x..j....ABCD|") == 0);
}

static void test_partial_display_row_uses_decimal_offset(void)
{
    const uint8_t payload[] = {'A', 'B'};
    const uint8_t full_row[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L'
    };
    char line[SN_ICMP_DISPLAY_LINE_CAPACITY];
    char full_line[SN_ICMP_DISPLAY_LINE_CAPACITY];
    char late_line[SN_ICMP_DISPLAY_LINE_CAPACITY];

    assert(sn_icmp_format_payload_display_row(12U, payload, sizeof(payload),
                                              line, sizeof(line)) == sizeof(payload));
    assert(strncmp(line, "012  41 42", 10U) == 0);
    assert(strstr(line, "|AB|") != NULL);
    assert(sn_icmp_format_payload_display_row(24U, full_row, sizeof(full_row),
                                              full_line, sizeof(full_line)) ==
           sizeof(full_row));
    assert(strncmp(full_line, "024  ", 5U) == 0);
    assert(sn_icmp_format_payload_display_row(104U, full_row, sizeof(full_row),
                                              late_line, sizeof(late_line)) ==
           sizeof(full_row));
    assert(strncmp(late_line, "104  ", 5U) == 0);
    assert(strchr(line, '|') - line == strchr(full_line, '|') - full_line);
    assert(strchr(line, '|') - line == strchr(late_line, '|') - late_line);
}

static void test_invalid_arguments_fail_without_writing_past_buffers(void)
{
    char hex[2] = {'x', 'x'};
    char ascii[2] = {'x', 'x'};

    assert(sn_icmp_format_payload_row(NULL, 1U, hex, sizeof(hex),
                                      ascii, sizeof(ascii)) == 0U);
    assert(hex[0] == '\0');
    assert(ascii[0] == '\0');
}

int main(void)
{
    test_binary_payload_formats_as_hex_and_safe_ascii();
    test_rows_are_capped_at_twelve_bytes();
    test_display_row_combines_three_groups_and_ascii();
    test_partial_display_row_uses_decimal_offset();
    test_invalid_arguments_fail_without_writing_past_buffers();
    puts("ICMP payload view tests passed");
    return 0;
}
