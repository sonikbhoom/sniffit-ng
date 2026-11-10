#include "sniffit_ng/arp_analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct {
    unsigned int flag;
    const char *name;
} alert_names[SN_ARP_ALERT_KIND_COUNT] = {
    {SN_ARP_ALERT_TALKATIVE, "talkative"},
    {SN_ARP_ALERT_RANGE_POLLER, "range-poller"},
    {SN_ARP_ALERT_SWEEP, "sweep"},
    {SN_ARP_ALERT_OFF_LINK, "off-link"},
    {SN_ARP_ALERT_MAC_CHANGE, "mac-change"}
};

static void increment(uint64_t *value)
{
    if (*value < UINT64_MAX) {
        ++*value;
    }
}

static uint32_t ip_value(const uint8_t ip[4])
{
    return ((uint32_t)ip[0] << 24U) | ((uint32_t)ip[1] << 16U) |
           ((uint32_t)ip[2] << 8U) | (uint32_t)ip[3];
}

static bool ip_is_zero(const uint8_t ip[4])
{
    return ip[0] == 0U && ip[1] == 0U && ip[2] == 0U && ip[3] == 0U;
}

static bool in_local_network(const struct sn_arp_analysis_config *config, const uint8_t ip[4])
{
    uint32_t mask = config->local_prefix == 0U ? 0U : UINT32_MAX << (32U - config->local_prefix);

    return (ip_value(ip) & mask) == (ip_value(config->local_network) & mask);
}

void sn_arp_analysis_config_init(struct sn_arp_analysis_config *config)
{
    if (config != NULL) {
        *config = (struct sn_arp_analysis_config){
            .talkative_requests_per_minute = 60U,
            .sweep_targets = 100U,
            .sweep_window_seconds = 60U,
            .range_poll_repeat = 200U,
            .range_poll_min_targets = 3U,
            .off_link_min_requests = 3U
        };
    }
}

void sn_arp_analysis_init(struct sn_arp_analysis *analysis,
                          const struct sn_arp_analysis_config *config)
{
    if (analysis == NULL) {
        return;
    }
    memset(analysis, 0, sizeof(*analysis));
    if (config == NULL) {
        sn_arp_analysis_config_init(&analysis->config);
    } else {
        analysis->config = *config;
    }
    if (analysis->config.sweep_targets > SN_ARP_WINDOW_TARGET_CAPACITY) {
        analysis->config.sweep_targets = SN_ARP_WINDOW_TARGET_CAPACITY;
    }
    if (analysis->config.sweep_window_seconds == 0U) {
        analysis->config.sweep_window_seconds = 1U;
    }
    if (analysis->config.baseline_count > SN_ARP_BASELINE_CAPACITY) {
        analysis->config.baseline_count = SN_ARP_BASELINE_CAPACITY;
    }
    if (analysis->config.local_prefix > 32U) {
        analysis->config.local_known = false;
    }
}

static bool is_baseline(const struct sn_arp_analysis_config *config, const uint8_t ip[4])
{
    for (size_t index = 0U; index < config->baseline_count; ++index) {
        if (memcmp(config->baseline_ips[index], ip, 4U) == 0) {
            return true;
        }
    }
    return false;
}

static struct sn_arp_host *find_or_create(struct sn_arp_analysis *analysis,
                                          const uint8_t ip[4], int64_t timestamp)
{
    struct sn_arp_host *empty = NULL;
    struct sn_arp_host *oldest = NULL;

    for (size_t index = 0U; index < SN_ARP_HOST_CAPACITY; ++index) {
        struct sn_arp_host *host = &analysis->hosts[index];

        if (!host->active) {
            if (empty == NULL) {
                empty = host;
            }
            continue;
        }
        if (memcmp(host->ip, ip, 4U) == 0) {
            return host;
        }
        if (oldest == NULL || host->last_seen < oldest->last_seen) {
            oldest = host;
        }
    }
    if (empty == NULL) {
        empty = oldest;
        increment(&analysis->evictions);
    }
    memset(empty, 0, sizeof(*empty));
    empty->active = true;
    empty->baseline = is_baseline(&analysis->config, ip);
    memcpy(empty->ip, ip, 4U);
    empty->first_seen = timestamp;
    empty->last_seen = timestamp;
    return empty;
}

static void raise_alert(struct sn_arp_host *host, unsigned int flag, int64_t timestamp)
{
    if ((host->alerts & flag) != 0U) {
        return;
    }
    host->alerts |= flag;
    for (size_t index = 0U; index < SN_ARP_ALERT_KIND_COUNT; ++index) {
        if (alert_names[index].flag == flag) {
            host->first_alert[index] = timestamp;
        }
    }
}

static void track_mac(struct sn_arp_host *host, const uint8_t mac[6], int64_t timestamp)
{
    for (size_t index = 0U; index < host->mac_count; ++index) {
        if (memcmp(host->macs[index], mac, 6U) == 0) {
            return;
        }
    }
    if (host->mac_count < SN_ARP_MAC_CAPACITY) {
        memcpy(host->macs[host->mac_count], mac, 6U);
        ++host->mac_count;
    }
    if (host->requests + host->replies > 0U || host->mac_count > 1U) {
        increment(&host->mac_changes);
        raise_alert(host, SN_ARP_ALERT_MAC_CHANGE, timestamp);
    }
}

/* Space-saving heavy-hitter count: a burst of one-off targets cannot hide a repeated one. */
static void count_target(struct sn_arp_host *host, const uint8_t target[4])
{
    struct sn_arp_target_count *smallest = &host->targets[0];

    for (size_t index = 0U; index < host->target_count; ++index) {
        if (memcmp(host->targets[index].ip, target, 4U) == 0) {
            increment(&host->targets[index].count);
            return;
        }
        if (host->targets[index].count < smallest->count) {
            smallest = &host->targets[index];
        }
    }
    if (host->target_count < SN_ARP_TRACKED_TARGETS) {
        memcpy(host->targets[host->target_count].ip, target, 4U);
        host->targets[host->target_count].count = 1U;
        ++host->target_count;
        return;
    }
    memcpy(smallest->ip, target, 4U);
    increment(&smallest->count);
}

static void note_window_target(struct sn_arp_host *host, uint32_t target)
{
    for (size_t index = 0U; index < host->sweep_count; ++index) {
        if (host->sweep_targets[index] == target) {
            return;
        }
    }
    if (host->sweep_count < SN_ARP_WINDOW_TARGET_CAPACITY) {
        host->sweep_targets[host->sweep_count++] = target;
    }
}

static void analyze_request(struct sn_arp_analysis *analysis, struct sn_arp_host *host,
                            const uint8_t target[4], int64_t timestamp)
{
    const struct sn_arp_analysis_config *config = &analysis->config;

    increment(&host->requests);

    if (host->rate_window_requests == 0U || timestamp < host->rate_window_start ||
        timestamp - host->rate_window_start >= SN_ARP_RATE_WINDOW_SECONDS) {
        host->rate_window_start = timestamp;
        host->rate_window_requests = 0U;
    }
    increment(&host->rate_window_requests);
    if (host->rate_window_requests > host->peak_requests_per_minute) {
        host->peak_requests_per_minute = host->rate_window_requests;
    }
    if (config->talkative_requests_per_minute > 0U &&
        host->peak_requests_per_minute >= config->talkative_requests_per_minute) {
        raise_alert(host, SN_ARP_ALERT_TALKATIVE, timestamp);
    }

    count_target(host, target);
    if (config->range_poll_min_targets > 0U && config->range_poll_repeat > 0U) {
        uint64_t repeated = 0U;

        for (size_t index = 0U; index < host->target_count; ++index) {
            if (host->targets[index].count >= config->range_poll_repeat) {
                ++repeated;
            }
        }
        if (repeated >= config->range_poll_min_targets) {
            raise_alert(host, SN_ARP_ALERT_RANGE_POLLER, timestamp);
        }
    }

    if (host->sweep_count == 0U || timestamp < host->sweep_window_start ||
        (uint64_t)(timestamp - host->sweep_window_start) >= config->sweep_window_seconds) {
        host->sweep_window_start = timestamp;
        host->sweep_count = 0U;
        host->sweep_window_flagged = false;
    }
    note_window_target(host, ip_value(target));
    if (host->sweep_count > host->peak_sweep_targets) {
        host->peak_sweep_targets = host->sweep_count;
    }
    if (config->sweep_targets > 0U && host->sweep_count >= config->sweep_targets &&
        !host->sweep_window_flagged) {
        host->sweep_window_flagged = true;
        increment(&host->sweeps_detected);
        raise_alert(host, SN_ARP_ALERT_SWEEP, timestamp);
    }

    if (config->local_known && !ip_is_zero(target) && !in_local_network(config, target)) {
        increment(&host->off_link_requests);
        if (config->off_link_min_requests > 0U &&
            host->off_link_requests >= config->off_link_min_requests) {
            raise_alert(host, SN_ARP_ALERT_OFF_LINK, timestamp);
        }
    }
}

void sn_arp_analysis_observe(struct sn_arp_analysis *analysis,
                             const struct sn_arp_observation *observation)
{
    const struct sn_arp_packet *packet;
    struct sn_arp_host *host;
    int64_t timestamp;

    if (analysis == NULL || observation == NULL) {
        return;
    }
    packet = &observation->packet;
    increment(&analysis->observed);
    if (ip_is_zero(packet->sender_ipv4)) {
        increment(&analysis->probes);
        return;
    }
    timestamp = (int64_t)observation->timestamp.tv_sec;
    host = find_or_create(analysis, packet->sender_ipv4, timestamp);
    host->last_seen = timestamp;
    track_mac(host, packet->sender_mac, timestamp);
    if (packet->operation == 2U) {
        increment(&host->replies);
        return;
    }
    analyze_request(analysis, host, packet->target_ipv4, timestamp);
}

size_t sn_arp_analysis_host_count(const struct sn_arp_analysis *analysis)
{
    size_t count = 0U;

    if (analysis != NULL) {
        for (size_t index = 0U; index < SN_ARP_HOST_CAPACITY; ++index) {
            if (analysis->hosts[index].active) {
                ++count;
            }
        }
    }
    return count;
}

static int compare_hosts(const void *left_pointer, const void *right_pointer)
{
    const struct sn_arp_host *left = *(const struct sn_arp_host *const *)left_pointer;
    const struct sn_arp_host *right = *(const struct sn_arp_host *const *)right_pointer;
    int left_rank = left->alerts != 0U ? (left->baseline ? 1 : 0) : 2;
    int right_rank = right->alerts != 0U ? (right->baseline ? 1 : 0) : 2;

    if (left_rank != right_rank) {
        return left_rank < right_rank ? -1 : 1;
    }
    if (left->requests != right->requests) {
        return left->requests > right->requests ? -1 : 1;
    }
    return memcmp(left->ip, right->ip, 4U);
}

size_t sn_arp_analysis_sorted(const struct sn_arp_analysis *analysis,
                              const struct sn_arp_host **hosts,
                              size_t capacity)
{
    size_t count = 0U;

    if (analysis == NULL || hosts == NULL) {
        return 0U;
    }
    for (size_t index = 0U; index < SN_ARP_HOST_CAPACITY && count < capacity; ++index) {
        if (analysis->hosts[index].active) {
            hosts[count++] = &analysis->hosts[index];
        }
    }
    qsort(hosts, count, sizeof(hosts[0]), compare_hosts);
    return count;
}

bool sn_arp_alerts_text(unsigned int alerts, char *output, size_t capacity)
{
    size_t used = 0U;

    if (output == NULL || capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    for (size_t index = 0U; index < SN_ARP_ALERT_KIND_COUNT; ++index) {
        int written;

        if ((alerts & alert_names[index].flag) == 0U) {
            continue;
        }
        written = snprintf(output + used, capacity - used, "%s%s",
                           used > 0U ? "," : "", alert_names[index].name);
        if (written < 0 || (size_t)written >= capacity - used) {
            output[used] = '\0';
            return false;
        }
        used += (size_t)written;
    }
    return true;
}
