#ifndef SNIFFIT_NG_ARP_REPLAY_H
#define SNIFFIT_NG_ARP_REPLAY_H

#include "sniffit_ng/arp_config.h"
#include "sniffit_ng/arp_state.h"

#include <signal.h>

struct sn_arp_replay_stats {
    struct sn_arp_state state;
    uint64_t non_arp;
    uint64_t unclassified;
    uint64_t deleted_segments;
    struct sn_arp_analysis *analysis;
};

struct sn_arp_capture_session;

struct sn_arp_capture_session *sn_arp_capture_session_open(
    const struct sn_arp_config *config, char *error_buffer, size_t error_capacity);
bool sn_arp_capture_session_process(struct sn_arp_capture_session *session,
                                    const struct sn_capture_packet *packet, time_t now,
                                    char *error_buffer, size_t error_capacity);
struct sn_arp_replay_stats *sn_arp_capture_session_stats(
    struct sn_arp_capture_session *session);
bool sn_arp_capture_session_finish(struct sn_arp_capture_session *session,
                                   char *error_buffer, size_t error_capacity);
void sn_arp_capture_session_release(struct sn_arp_capture_session *session);

/* May leave stats->analysis allocated even on failure; always call the release function. */
bool sn_arp_capture_process(struct sn_capture *capture,
                            const struct sn_arp_config *config,
                            struct sn_arp_replay_stats *stats,
                            const volatile sig_atomic_t *stop_requested,
                            char *error_buffer, size_t error_capacity);
bool sn_arp_replay_file(const char *path, const struct sn_arp_config *config,
                        struct sn_arp_replay_stats *stats,
                        char *error_buffer, size_t error_capacity);
void sn_arp_replay_stats_release(struct sn_arp_replay_stats *stats);

#endif