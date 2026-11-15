#ifndef SNIFFIT_NG_ARP_ANALYSIS_H
#define SNIFFIT_NG_ARP_ANALYSIS_H

#include "sniffit_ng/arp_state.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define SN_ARP_HOST_CAPACITY 256U
#define SN_ARP_MAC_CAPACITY 4U
#define SN_ARP_TRACKED_TARGETS 64U
#define SN_ARP_WINDOW_TARGET_CAPACITY 512U
#define SN_ARP_BASELINE_CAPACITY 16U
#define SN_ARP_RATE_WINDOW_SECONDS 60

enum sn_arp_alert {
    SN_ARP_ALERT_TALKATIVE = 1U,
    SN_ARP_ALERT_RANGE_POLLER = 2U,
    SN_ARP_ALERT_SWEEP = 4U,
    SN_ARP_ALERT_OFF_LINK = 8U,
    SN_ARP_ALERT_MAC_CHANGE = 16U
};

#define SN_ARP_ALERT_KIND_COUNT 5U

/* A threshold of 0 disables that detector. */
struct sn_arp_analysis_config {
    bool local_known;
    uint8_t local_network[4];
    uint8_t local_prefix;
    uint64_t talkative_requests_per_minute;
    uint64_t sweep_targets;
    uint64_t sweep_window_seconds;
    uint64_t range_poll_repeat;
    uint64_t range_poll_min_targets;
    uint64_t off_link_min_requests;
    uint8_t baseline_ips[SN_ARP_BASELINE_CAPACITY][4];
    size_t baseline_count;
};

struct sn_arp_target_count {
    uint8_t ip[4];
    uint64_t count;
};

struct sn_arp_host {
    bool active;
    bool baseline;
    uint8_t ip[4];
    uint8_t last_mac[6];
    uint8_t macs[SN_ARP_MAC_CAPACITY][6];
    size_t mac_count;
    uint64_t mac_changes;
    int64_t first_seen;
    int64_t last_seen;
    uint64_t requests;
    uint64_t replies;
    uint64_t off_link_requests;
    struct sn_arp_target_count targets[SN_ARP_TRACKED_TARGETS];
    size_t target_count;
    int64_t rate_window_start;
    uint64_t rate_window_requests;
    uint64_t peak_requests_per_minute;
    int64_t sweep_window_start;
    uint32_t sweep_targets[SN_ARP_WINDOW_TARGET_CAPACITY];
    size_t sweep_count;
    bool sweep_window_flagged;
    uint64_t peak_sweep_targets;
    uint64_t sweeps_detected;
    unsigned int alerts;
    int64_t first_alert[SN_ARP_ALERT_KIND_COUNT];
};

/* About 0.9 MB: allocate on the heap, never on the stack. */
struct sn_arp_analysis {
    struct sn_arp_analysis_config config;
    struct sn_arp_host hosts[SN_ARP_HOST_CAPACITY];
    uint64_t observed;
    uint64_t probes;
    uint64_t evictions;
};

void sn_arp_analysis_config_init(struct sn_arp_analysis_config *config);
void sn_arp_analysis_init(struct sn_arp_analysis *analysis,
                          const struct sn_arp_analysis_config *config);
void sn_arp_analysis_observe(struct sn_arp_analysis *analysis,
                             const struct sn_arp_observation *observation);
size_t sn_arp_analysis_host_count(const struct sn_arp_analysis *analysis);

/* Hosts with unsuppressed alerts first, then baseline alerts, then by requests. */
size_t sn_arp_analysis_sorted(const struct sn_arp_analysis *analysis,
                              const struct sn_arp_host **hosts,
                              size_t capacity);

/* Writes names such as "talkative,sweep"; returns false if truncated. */
bool sn_arp_alerts_text(unsigned int alerts, char *output, size_t capacity);

#endif
