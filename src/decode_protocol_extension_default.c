#include "sniffit_ng/protocol_decode_extension.h"

bool sn_protocol_decode_extension(const struct sn_packet_view *packet,
                                  char *output,
                                  size_t output_capacity)
{
    (void)packet;
    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    return false;
}