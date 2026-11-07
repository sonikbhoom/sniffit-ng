#ifndef SNIFFIT_NG_ARP_CONFIG_H
#define SNIFFIT_NG_ARP_CONFIG_H

#include "sniffit_ng/arp_rotation.h"

#define SN_ARP_LOG_DIRECTORY_CAPACITY 512U

struct sn_arp_config {
    char log_directory[SN_ARP_LOG_DIRECTORY_CAPACITY];
    struct sn_arp_rotation_config rotation;
};

void sn_arp_config_init(struct sn_arp_config *config);
bool sn_arp_config_load(const char *path, struct sn_arp_config *config,
                        char *error_buffer, size_t error_capacity);

#endif