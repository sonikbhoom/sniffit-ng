#ifndef SNIFFIT_NG_ARP_REPLAY_H
#define SNIFFIT_NG_ARP_REPLAY_H

#include "sniffit_ng/arp_config.h"
#include "sniffit_ng/arp_state.h"

struct sn_arp_replay_stats {
    struct sn_arp_state state;
    uint64_t non_arp;
    uint64_t unclassified;
    uint64_t deleted_segments;
};

bool sn_arp_replay_file(const char *path, const struct sn_arp_config *config,
                        struct sn_arp_replay_stats *stats,
                        char *error_buffer, size_t error_capacity);

#endif