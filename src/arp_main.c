#include "sniffit_ng/arp_replay.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sniffit_ng/arp_ui.h"

#define USAGE "Usage: arpwatch-ng-tui --read-pcap FILE --config FILE [--hosts | --tui]"

static void print_hosts(const struct sn_arp_analysis *analysis)
{
    const struct sn_arp_host *hosts[SN_ARP_HOST_CAPACITY];
    size_t count = sn_arp_analysis_sorted(analysis, hosts, SN_ARP_HOST_CAPACITY);

    printf("%-15s %9s %8s %7s %9s %s\n", "HOST", "REQUESTS", "REPLIES", "PEAK/M",
           "SWEEPTGT", "ALERTS");
    for (size_t index = 0U; index < count; ++index) {
        const struct sn_arp_host *host = hosts[index];
        char address[16];
        char alerts[64];

        (void)snprintf(address, sizeof(address), "%u.%u.%u.%u", host->ip[0], host->ip[1],
                       host->ip[2], host->ip[3]);
        (void)sn_arp_alerts_text(host->alerts, alerts, sizeof(alerts));
        printf("%-15s %9" PRIu64 " %8" PRIu64 " %7" PRIu64 " %9" PRIu64 " %s%s\n", address,
               host->requests, host->replies, host->peak_requests_per_minute,
               host->peak_sweep_targets, alerts, host->baseline ? " (baseline)" : "");
    }
    printf("Hosts=%zu probes=%" PRIu64 " evictions=%" PRIu64 "\n", count, analysis->probes,
           analysis->evictions);
}

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *config_path = NULL;
    bool show_hosts = false;
    bool use_tui = false;
    struct sn_arp_config config;
    struct sn_arp_replay_stats stats;
    char error[256] = {0};
    bool replayed;

    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--help") == 0) {
            puts(USAGE);
            return 0;
        }
        if (strcmp(argv[index], "--read-pcap") == 0 && index + 1 < argc && pcap_path == NULL) {
            pcap_path = argv[++index];
        } else if (strcmp(argv[index], "--config") == 0 && index + 1 < argc && config_path == NULL) {
            config_path = argv[++index];
        } else if (strcmp(argv[index], "--hosts") == 0 && !show_hosts) {
            show_hosts = true;
        } else if (strcmp(argv[index], "--tui") == 0 && !use_tui) {
            use_tui = true;
        } else {
            fprintf(stderr, "invalid argument: %s\n", argv[index]);
            return 2;
        }
    }
    if (pcap_path == NULL || config_path == NULL || (show_hosts && use_tui)) {
        fputs(USAGE "\n", stderr);
        return 2;
    }
    if (use_tui && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
        fputs("--tui needs an interactive terminal\n", stderr);
        return 2;
    }
    if (!sn_arp_config_load(config_path, &config, error, sizeof(error))) {
        fprintf(stderr, "ARP configuration failed: %s\n", error);
        return 1;
    }
    replayed = sn_arp_replay_file(pcap_path, &config, &stats, error, sizeof(error));
    if (!replayed) {
        fprintf(stderr, "ARP replay failed: %s\n", error);
        sn_arp_replay_stats_release(&stats);
        return 1;
    }
    if (use_tui) {
        struct sn_arp_view_totals totals = {
            .source = pcap_path,
            .arp_packets = stats.state.captured,
            .decoded = stats.state.decoded,
            .truncated = stats.state.truncated,
            .malformed = stats.state.malformed,
            .unsupported = stats.state.unsupported,
            .non_arp = stats.non_arp,
            .unclassified = stats.unclassified
        };
        int result = sn_arp_ui_run(stats.analysis, &stats.state, &totals);

        sn_arp_replay_stats_release(&stats);
        return result;
    }
    printf("ARP packets=%" PRIu64 " decoded=%" PRIu64 " truncated=%" PRIu64
           " malformed=%" PRIu64 " unsupported=%" PRIu64 "\n",
           stats.state.captured, stats.state.decoded, stats.state.truncated,
           stats.state.malformed, stats.state.unsupported);
    printf("Non-ARP skipped=%" PRIu64 " unclassified link headers=%" PRIu64
           " deleted segments=%" PRIu64 "\n",
           stats.non_arp, stats.unclassified, stats.deleted_segments);
    printf("Packet logging=%s address logging=%s\n",
           config.rotation.packet_logging ? "on" : "off",
           config.rotation.address_logging ? "on" : "off");
    if (show_hosts) {
        print_hosts(stats.analysis);
    }
    sn_arp_replay_stats_release(&stats);
    return 0;
}