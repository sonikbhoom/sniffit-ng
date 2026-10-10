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

static void test_rows_are_capped_at_sixteen_bytes(void)
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
    test_rows_are_capped_at_sixteen_bytes();
    test_invalid_arguments_fail_without_writing_past_buffers();
    puts("ICMP payload view tests passed");
    return 0;
}
