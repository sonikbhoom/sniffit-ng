#ifndef SNIFFIT_NG_ICMP_PAYLOAD_VIEW_H
#define SNIFFIT_NG_ICMP_PAYLOAD_VIEW_H

#include <stddef.h>
#include <stdint.h>

#define SN_ICMP_DISPLAY_GROUP_BYTES 4U
#define SN_ICMP_DISPLAY_GROUPS_PER_ROW 3U
#define SN_ICMP_DISPLAY_ROW_BYTES \
    (SN_ICMP_DISPLAY_GROUP_BYTES * SN_ICMP_DISPLAY_GROUPS_PER_ROW)
#define SN_ICMP_DISPLAY_HEX_CAPACITY (SN_ICMP_DISPLAY_ROW_BYTES * 3U)
#define SN_ICMP_DISPLAY_ASCII_CAPACITY (SN_ICMP_DISPLAY_ROW_BYTES + 1U)
#define SN_ICMP_DISPLAY_LINE_CAPACITY 80U

size_t sn_icmp_format_payload_row(const uint8_t *payload,
                                  size_t payload_length,
                                  char *hex_output,
                                  size_t hex_capacity,
                                  char *ascii_output,
                                  size_t ascii_capacity);

size_t sn_icmp_format_payload_display_row(size_t row_offset,
                                          const uint8_t *payload,
                                          size_t payload_length,
                                          char *line_output,
                                          size_t line_capacity);

#endif
