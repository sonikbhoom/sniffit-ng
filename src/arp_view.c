#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/arp_view.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void format_time(int64_t seconds, char *output, size_t capacity)
{
    time_t value = (time_t)seconds;
    struct tm utc;

    if (seconds < 0 || gmtime_r(&value, &utc) == NULL) {
        (void)snprintf(output, capacity, "--:--:--Z");
        return;
    }
    (void)snprintf(output, capacity, "%02d:%02d:%02dZ", utc.tm_hour, utc.tm_min, utc.tm_sec);
}

static void format_date_time(int64_t seconds, char *output, size_t capacity)
{
    time_t value = (time_t)seconds;
    struct tm utc;

    if (seconds < 0 || gmtime_r(&value, &utc) == NULL ||
        strftime(output, capacity, "%Y-%m-%d %H:%M:%SZ", &utc) == 0U) {
        (void)snprintf(output, capacity, "unknown");
    }
}

static void format_ip(const uint8_t ip[4], char *output, size_t capacity)
{
    (void)snprintf(output, capacity, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static void format_mac(const uint8_t mac[6], char *output, size_t capacity)
{
    (void)snprintf(output, capacity, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void sn_arp_view_header(char *output, size_t capacity)
{
    if (output != NULL && capacity > 0U) {
        (void)snprintf(output, capacity, "  %-15s %-17s %9s %8s %7s %9s  %s", "HOST IP",
                       "QUERIER MAC", "REQUESTS", "REPLIES", "PEAK/M", "SWEEPTGT", "ALERTS");
    }
}

void sn_arp_view_host_row(const struct sn_arp_host *host, char *output, size_t capacity)
{
    char address[16];
    char mac[18] = "--";
    char alerts[64];
    char marker = ' ';

    if (output == NULL || capacity == 0U) {
        return;
    }
    output[0] = '\0';
    if (host == NULL) {
        return;
    }
    format_ip(host->ip, address, sizeof(address));
    if (host->mac_count > 0U) {
        format_mac(host->last_mac, mac, sizeof(mac));
    }
    (void)sn_arp_alerts_text(host->alerts, alerts, sizeof(alerts));
    if (host->alerts != 0U) {
        marker = host->baseline ? '~' : '!';
    }
    (void)snprintf(output, capacity,
                   "%c %-15s %-17s %9" PRIu64 " %8" PRIu64 " %7" PRIu64 " %9" PRIu64 "  %s",
                   marker, address, mac, host->requests, host->replies,
                   host->peak_requests_per_minute, host->peak_sweep_targets, alerts);
}

void sn_arp_view_observation(const struct sn_arp_observation *observation,
                             char *output, size_t capacity)
{
    char when[16];
    char sender[16];
    char target[16];
    char mac[18];

    if (output == NULL || capacity == 0U) {
        return;
    }
    output[0] = '\0';
    if (observation == NULL) {
        return;
    }
    format_time((int64_t)observation->timestamp.tv_sec, when, sizeof(when));
    format_ip(observation->packet.sender_ipv4, sender, sizeof(sender));
    format_ip(observation->packet.target_ipv4, target, sizeof(target));
    if (observation->packet.operation == 1U) {
        (void)snprintf(output, capacity, "%s %s%s", when, "who-has ", target);
        {
            size_t used = strlen(output);

            if (used < capacity) {
                (void)snprintf(output + used, capacity - used, " tell %s", sender);
            }
        }
        return;
    }
    format_mac(observation->packet.sender_mac, mac, sizeof(mac));
    (void)snprintf(output, capacity, "%s %s is-at %s", when, sender, mac);
}

size_t sn_arp_view_host_packets(const struct sn_arp_state *state, const uint8_t ip[4],
                                const struct sn_arp_observation **observations,
                                size_t capacity)
{
    size_t found = 0U;

    if (state == NULL || ip == NULL || observations == NULL) {
        return 0U;
    }
    for (size_t index = state->history_count; index > 0U && found < capacity; --index) {
        const struct sn_arp_observation *observation = sn_arp_state_at(state, index - 1U);

        if (observation != NULL && (memcmp(observation->packet.sender_ipv4, ip, 4U) == 0 ||
                                    memcmp(observation->packet.target_ipv4, ip, 4U) == 0)) {
            observations[found++] = observation;
        }
    }
    return found;
}

static const char *alert_explanation(unsigned int flag)
{
    switch (flag) {
    case SN_ARP_ALERT_TALKATIVE:
        return "talkative: many requests per minute";
    case SN_ARP_ALERT_RANGE_POLLER:
        return "range-poller: same few targets asked repeatedly";
    case SN_ARP_ALERT_SWEEP:
        return "sweep: many distinct targets in a short window";
    case SN_ARP_ALERT_OFF_LINK:
        return "off-link: asks for addresses outside local_network";
    default:
        return "mac-change: IP seen with more than one MAC";
    }
}

size_t sn_arp_view_detail(const struct sn_arp_host *host,
                          char lines[][SN_ARP_VIEW_LINE], size_t max_lines)
{
    size_t count = 0U;
    char first[24];
    char last[24];

    if (host == NULL || lines == NULL) {
        return 0U;
    }
    format_date_time(host->first_seen, first, sizeof(first));
    format_date_time(host->last_seen, last, sizeof(last));
    if (count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE, "seen %s to %s", first, last);
    }
    if (count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE, "requests %" PRIu64 "  replies %" PRIu64,
                       host->requests, host->replies);
    }
    if (count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE,
                       "peak %" PRIu64 " requests/min, %" PRIu64 " distinct targets/min",
                       host->peak_requests_per_minute, host->peak_sweep_targets);
    }
    if (count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE,
                       "MACs %zu (changes %" PRIu64 ")  off-link %" PRIu64 "  sweeps %" PRIu64,
                       host->mac_count, host->mac_changes, host->off_link_requests,
                       host->sweeps_detected);
    }
    {
        const struct sn_arp_target_count *best[3] = {NULL, NULL, NULL};

        for (size_t rank = 0U; rank < 3U; ++rank) {
            for (size_t index = 0U; index < host->target_count; ++index) {
                const struct sn_arp_target_count *candidate = &host->targets[index];
                bool taken = false;

                for (size_t other = 0U; other < rank; ++other) {
                    taken = taken || best[other] == candidate;
                }
                if (!taken && (best[rank] == NULL || candidate->count > best[rank]->count)) {
                    best[rank] = candidate;
                }
            }
        }
        for (size_t rank = 0U; rank < 3U && best[rank] != NULL && count < max_lines; ++rank) {
            char target[16];

            format_ip(best[rank]->ip, target, sizeof(target));
            (void)snprintf(lines[count++], SN_ARP_VIEW_LINE, "asked %" PRIu64 "x  %s",
                           best[rank]->count, target);
        }
    }
    for (size_t index = 0U; index < SN_ARP_ALERT_KIND_COUNT && count < max_lines; ++index) {
        unsigned int flag = 1U << index;

        if ((host->alerts & flag) != 0U) {
            (void)snprintf(lines[count++], SN_ARP_VIEW_LINE, "%s", alert_explanation(flag));
        }
    }
    if (host->baseline && count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE,
                       "baseline: listed in baseline_ips, so its alerts are ranked last");
    }
    return count;
}

struct sn_arp_view_layout sn_arp_view_layout(int lines, int columns, bool show_stats)
{
    struct sn_arp_view_layout layout = {0};
    int reserved = show_stats ? 15 : 5;

    layout.too_small = columns < SN_ARP_VIEW_MIN_COLUMNS || lines < SN_ARP_VIEW_MIN_ROWS;
    layout.first_row = 3;
    layout.visible_rows = lines > reserved ? lines - reserved : 1;
    layout.stats_row = lines - 11;
    layout.panel_x = columns * 2 / 5;
    layout.panel_width = columns - layout.panel_x;
    return layout;
}

size_t sn_arp_view_clamp_scroll(size_t item_count, size_t visible, size_t scroll)
{
    size_t maximum = item_count > visible ? item_count - visible : 0U;

    return scroll < maximum ? scroll : maximum;
}

size_t sn_arp_view_stats(const struct sn_arp_analysis *analysis,
                         const struct sn_arp_view_totals *totals,
                         char lines[][SN_ARP_VIEW_LINE], size_t max_lines)
{
    uint64_t requests = 0U;
    uint64_t replies = 0U;
    size_t hosts = 0U;
    size_t alerting = 0U;
    size_t baseline_alerting = 0U;
    size_t by_alert[SN_ARP_ALERT_KIND_COUNT] = {0};
    size_t count = 0U;

    if (analysis == NULL || totals == NULL || lines == NULL) {
        return 0U;
    }
    for (size_t index = 0U; index < SN_ARP_HOST_CAPACITY; ++index) {
        const struct sn_arp_host *host = &analysis->hosts[index];

        if (!host->active) {
            continue;
        }
        ++hosts;
        requests += host->requests;
        replies += host->replies;
        if (host->alerts != 0U) {
            if (host->baseline) {
                ++baseline_alerting;
            } else {
                ++alerting;
            }
            for (size_t kind = 0U; kind < SN_ARP_ALERT_KIND_COUNT; ++kind) {
                by_alert[kind] += (host->alerts & (1U << kind)) != 0U ? 1U : 0U;
            }
        }
    }
    if (count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE,
                       "Packets: ARP %" PRIu64 "  decoded %" PRIu64 "  requests %" PRIu64
                       "  replies %" PRIu64 "  probes %" PRIu64,
                       totals->arp_packets, totals->decoded, requests, replies, analysis->probes);
    }
    if (count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE,
                       "Other: non-ARP frames %" PRIu64 "  unclassified %" PRIu64
                       "  Truncated: %" PRIu64 "  Malformed: %" PRIu64 "  Unsupported: %" PRIu64,
                       totals->non_arp, totals->unclassified, totals->truncated,
                       totals->malformed, totals->unsupported);
    }
    if (count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE,
                       "Hosts: %zu  alerting %zu  baseline alerts %zu  evicted %" PRIu64,
                       hosts, alerting, baseline_alerting, analysis->evictions);
    }
    if (count < max_lines) {
        (void)snprintf(lines[count++], SN_ARP_VIEW_LINE,
                       "Alerts: talkative %zu  range-poller %zu  sweep %zu  off-link %zu"
                       "  mac-change %zu",
                       by_alert[0], by_alert[1], by_alert[2], by_alert[3], by_alert[4]);
    }
    return count;
}
