#ifndef SNIFFIT_NG_CONFIG_H
#define SNIFFIT_NG_CONFIG_H

#include "sniffit_ng/decoder_modes.h"

#include <stdbool.h>
#include <stddef.h>

#define SN_CONFIG_PAYLOAD_ACK_COMMENT \
    "## User has acknowledged to behave ethically and inspect only authorized traffic."

struct sn_app_config {
    bool inspect_payloads;
    bool payload_display_acknowledged;
    bool resolve_external_addr;
    bool show_raw_flows;
    bool tainted_extensions;
    enum sn_decoder_mode decoder_modes[SN_DECODER_MODULE_COUNT];
};

void sn_config_init(struct sn_app_config *config);

bool sn_config_load_file(const char *path,
                         struct sn_app_config *config,
                         char *error_buffer,
                         size_t error_buffer_size);

bool sn_config_validate_payload_inspection(
    const struct sn_app_config *config,
    char *error_buffer,
    size_t error_buffer_size);

#endif
