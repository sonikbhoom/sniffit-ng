#include "sniffit_ng/arp_replay.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *config_path = NULL;
    struct sn_arp_config config;
    struct sn_arp_replay_stats stats;
    char error[256] = {0};

    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--help") == 0) {
            puts("Usage: arpwatch-ng-tui --read-pcap FILE --config FILE");
            return 0;
        }
        if (strcmp(argv[index], "--read-pcap") == 0 && index + 1 < argc && pcap_path == NULL) {
            pcap_path = argv[++index];
        } else if (strcmp(argv[index], "--config") == 0 && index + 1 < argc && config_path == NULL) {
            config_path = argv[++index];
        } else {
            fprintf(stderr, "invalid argument: %s\n", argv[index]);
            return 2;
        }
    }
    if (pcap_path == NULL || config_path == NULL) {
        fputs("Usage: arpwatch-ng-tui --read-pcap FILE --config FILE\n", stderr);
        return 2;
    }
    if (!sn_arp_config_load(config_path, &config, error, sizeof(error)) ||
        !sn_arp_replay_file(pcap_path, &config, &stats, error, sizeof(error))) {
        fprintf(stderr, "ARP replay failed: %s\n", error);
        return 1;
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
    return 0;
}