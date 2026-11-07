#ifndef SNIFFIT_NG_ARP_ROTATION_H
#define SNIFFIT_NG_ARP_ROTATION_H

#include "sniffit_ng/capture.h"

#include <time.h>

struct sn_arp_rotation_config {
    bool packet_logging;
    bool address_logging;
    uint64_t packet_segment_bytes;
    uint64_t address_segment_bytes;
    bool rotate_daily;
    uint64_t idle_seconds;
    uint64_t maximum_age_seconds;
    uint64_t maximum_total_bytes;
    bool delete_old_segments;
};

struct sn_arp_rotation;

void sn_arp_rotation_config_init(struct sn_arp_rotation_config *config);
struct sn_arp_rotation *sn_arp_rotation_open(const char *directory,
                                             const struct sn_arp_rotation_config *config,
                                             char *error_buffer, size_t error_capacity);
bool sn_arp_rotation_write(struct sn_arp_rotation *rotation,
                           const struct sn_capture_packet *packet, time_t now);
uint64_t sn_arp_rotation_deleted(const struct sn_arp_rotation *rotation);
bool sn_arp_rotation_close(struct sn_arp_rotation *rotation);

#endif