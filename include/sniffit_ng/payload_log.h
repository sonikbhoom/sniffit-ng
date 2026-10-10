#ifndef SNIFFIT_NG_PAYLOAD_LOG_H
#define SNIFFIT_NG_PAYLOAD_LOG_H

#include "sniffit_ng/capture.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define SN_PAYLOAD_ACK_PHRASE "I ACKNOWLEDGE THE PRIVACY AND AUTHORIZATION RISKS"

struct sn_payload_log;

bool sn_capture_recording_confirm(FILE *input, FILE *output);

struct sn_payload_log *sn_payload_log_open(
    const char *path,
    char *error_buffer,
    size_t error_buffer_size);

bool sn_payload_log_write_packet(
    struct sn_payload_log *log,
    const struct sn_capture_packet *packet);

bool sn_payload_log_close(struct sn_payload_log *log);

#endif
