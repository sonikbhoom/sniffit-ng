#ifndef SNIFFIT_NG_PROTOCOL_DECODE_H
#define SNIFFIT_NG_PROTOCOL_DECODE_H

#include "sniffit_ng/packet.h"

#include <stdbool.h>
#include <stddef.h>

#define SN_PACKET_DECODE_TEXT_CAPACITY 192U
#define SN_FLOW_DECODE_HISTORY_CAPACITY 16U

struct sn_packet_decode_record {
    char text[SN_PACKET_DECODE_TEXT_CAPACITY];
};

bool sn_protocol_decode(const struct sn_packet_view *packet,
                        char *output,
                        size_t output_capacity);

#endif