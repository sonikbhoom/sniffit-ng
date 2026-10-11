#ifndef SNIFFIT_NG_PACKET_INSPECT_H
#define SNIFFIT_NG_PACKET_INSPECT_H

#include "sniffit_ng/capture.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

bool sn_packet_inspect(FILE *output,
                       const struct sn_capture_packet *packet,
                       size_t packet_number);

#endif