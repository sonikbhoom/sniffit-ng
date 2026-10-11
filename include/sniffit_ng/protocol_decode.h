#ifndef SNIFFIT_NG_PROTOCOL_DECODE_H
#define SNIFFIT_NG_PROTOCOL_DECODE_H

#include "sniffit_ng/packet.h"
#include "sniffit_ng/decoder_modes.h"

#include <stdbool.h>
#include <stddef.h>

#define SN_PACKET_DECODE_TEXT_CAPACITY 256U
#define SN_FLOW_DECODE_HISTORY_CAPACITY 16U

struct sn_packet_decode_record {
    char text[SN_PACKET_DECODE_TEXT_CAPACITY];
};

bool sn_protocol_decode(const struct sn_packet_view *packet,
                        char *output,
                        size_t output_capacity);

bool sn_protocol_decode_with_extension(const struct sn_packet_view *packet,
                                       char *output,
                                       size_t output_capacity,
                                       bool tainted_extensions);

bool sn_protocol_decode_with_options(const struct sn_packet_view *packet,
                                     char *output,
                                     size_t output_capacity,
                                     bool show_raw_flows,
                                     bool tainted_extensions);

bool sn_protocol_decode_with_modes(
    const struct sn_packet_view *packet,
    char *output,
    size_t output_capacity,
    bool show_raw_flows,
    bool tainted_extensions,
    const enum sn_decoder_mode modes[SN_DECODER_MODULE_COUNT]);

const char *sn_protocol_security_advisory(const struct sn_packet_view *packet);

#endif