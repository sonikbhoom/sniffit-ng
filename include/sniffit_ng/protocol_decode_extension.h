#ifndef SNIFFIT_NG_PROTOCOL_DECODE_EXTENSION_H
#define SNIFFIT_NG_PROTOCOL_DECODE_EXTENSION_H

#include "sniffit_ng/packet.h"

#include <stdbool.h>
#include <stddef.h>

/*
 * Called synchronously only when the operator enables tainted_extensions.
 * Packet spans are valid only until return and must not be retained.
 * Compiled-in code is trusted executable code and is not sandboxed. Successful
 * output must be NUL-terminated within capacity.
 */
bool sn_protocol_decode_extension(const struct sn_packet_view *packet,
                                  char *output,
                                  size_t output_capacity);

#endif