#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/arp_replay.h"
#include "sniffit_ng/capture.h"
#include "sniffit_ng/privilege.h"
#include "sniffit_ng/network_info.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sniffit_ng/arp_ui.h"

#define USAGE "Usage: arpwatch-ng-tui (--read-pcap FILE | --interface DEVICE) --config FILE [--hosts | --tui]"
#define LIVE_CAPTURE_BATCH_CAPACITY 64U

static volatile sig_atomic_t stop_requested;

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

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static bool install_stop_handlers(char *error, size_t error_capacity)
{
    struct sigaction action = {0};

    action.sa_handler = request_stop;
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        (void)snprintf(error, error_capacity, "cannot install stop handlers");
        return false;
    }
    return true;
}

static void close_setup_capture(struct sn_capture *capture)
{
    char error[256] = {0};

    if (!sn_drop_privileges_to_real_user(error, sizeof(error))) {
        fprintf(stderr, "arpwatch-ng-tui: privilege drop after setup failure: %s\n", error);
    }
    sn_capture_close(capture);
}

struct live_ui_context {
    struct sn_capture *capture;
    struct sn_arp_capture_session *session;
    struct sn_arp_replay_stats *stats;
    struct sn_arp_view_totals *totals;
};

static void update_live_totals(struct live_ui_context *context)
{
    context->totals->arp_packets = context->stats->state.captured;
    context->totals->decoded = context->stats->state.decoded;
    context->totals->truncated = context->stats->state.truncated;
    context->totals->malformed = context->stats->state.malformed;
    context->totals->unsupported = context->stats->state.unsupported;
    context->totals->non_arp = context->stats->non_arp;
    context->totals->unclassified = context->stats->unclassified;
}

static enum sn_arp_ui_poll_result poll_live_ui(void *opaque, char *error_buffer,
                                               size_t error_capacity)
{
    struct live_ui_context *context = opaque;
    bool updated = false;

    if (stop_requested != 0) {
        return SN_ARP_UI_POLL_STOPPED;
    }
    for (size_t index = 0U; index < LIVE_CAPTURE_BATCH_CAPACITY; ++index) {
        struct sn_capture_packet packet;
        enum sn_capture_result result = sn_capture_next(context->capture, &packet,
                                                        error_buffer, error_capacity);

        if (result == SN_CAPTURE_TIMEOUT) {
            update_live_totals(context);
            return updated ? SN_ARP_UI_POLL_UPDATED : SN_ARP_UI_POLL_IDLE;
        }
        if (result == SN_CAPTURE_EOF) {
            update_live_totals(context);
            return SN_ARP_UI_POLL_STOPPED;
        }
        if (result != SN_CAPTURE_PACKET) {
            return SN_ARP_UI_POLL_FAILED;
        }
        time_t now = time(NULL);
        if (now == (time_t)-1) {
            (void)snprintf(error_buffer, error_capacity,
                           "cannot read wall clock for ARP logging");
            return SN_ARP_UI_POLL_FAILED;
        }
        if (!sn_arp_capture_session_process(context->session, &packet, now,
                                            error_buffer, error_capacity)) {
            return SN_ARP_UI_POLL_FAILED;
        }
        updated = true;
    }
    update_live_totals(context);
    return SN_ARP_UI_POLL_UPDATED;
}

static int run_live_capture(const char *device, const struct sn_arp_config *config,
                            bool show_hosts, bool use_tui)
{
    char error[256] = {0};
    struct sn_capture *capture;
    struct sn_arp_replay_stats stats = {0};
    struct sn_capture_stats capture_stats = {0};
    struct sn_arp_capture_session *session = NULL;
    enum sn_packet_link_type link_type;
    const char *filter;
    bool processed;
    bool have_capture_stats;

    if (!sn_enable_capture_capability(error, sizeof(error))) {
        fprintf(stderr, "arpwatch-ng-tui: cannot enable live capture: %s\n", error);
        return 1;
    }
    capture = sn_capture_open_live(device, 65535, false, 100,
                                   error, sizeof(error));
    if (capture == NULL) {
        fprintf(stderr, "arpwatch-ng-tui: cannot open interface %s: %s\n", device, error);
        close_setup_capture(NULL);
        return 1;
    }
    if (!sn_capture_set_nonblocking(capture, error, sizeof(error))) {
        fprintf(stderr, "arpwatch-ng-tui: cannot configure live capture: %s\n", error);
        close_setup_capture(capture);
        return 1;
    }
    if (!sn_capture_get_link_type(capture, &link_type)) {
        fprintf(stderr, "arpwatch-ng-tui: cannot determine capture link type\n");
        close_setup_capture(capture);
        return 1;
    }
    filter = sn_arp_bpf_filter_expression(link_type);
    if (filter == NULL || !sn_capture_set_filter(capture, filter, error, sizeof(error))) {
        fprintf(stderr, "arpwatch-ng-tui: cannot install ARP capture filter: %s\n",
                error[0] != '\0' ? error : "unsupported link type");
        close_setup_capture(capture);
        return 1;
    }
    if (!sn_drop_privileges_to_real_user(error, sizeof(error))) {
        fprintf(stderr, "arpwatch-ng-tui: refusing to process packets with elevated privileges: %s\n",
                error);
        sn_capture_close(capture);
        return 1;
    }
    stop_requested = 0;
    if (!install_stop_handlers(error, sizeof(error))) {
        fprintf(stderr, "arpwatch-ng-tui: %s\n", error);
        sn_capture_close(capture);
        return 1;
    }
    fprintf(stderr, "arpwatch-ng-tui: monitoring ARP on %s without promiscuous mode; "
                    "press Ctrl-C to stop\n", device);
    if (use_tui) {
        struct sn_arp_view_totals totals = {.source = device};
        struct live_ui_context ui_context;
        struct sn_network_info network_info;
        uint8_t local_ipv4[4];

        sn_network_info_init(&network_info, device);
        if (sn_network_info_find_local_ipv4(&network_info) &&
            inet_pton(AF_INET, network_info.local_ipv4, local_ipv4) == 1) {
            memcpy(totals.local_ipv4, local_ipv4, sizeof(totals.local_ipv4));
            totals.local_ipv4_known = true;
        }

        session = sn_arp_capture_session_open(config, error, sizeof(error));
        if (session == NULL) {
            fprintf(stderr, "arpwatch-ng-tui: cannot initialize live ARP processing: %s\n",
                    error);
            sn_capture_close(capture);
            return 1;
        }
        ui_context = (struct live_ui_context){
            .capture = capture,
            .session = session,
            .stats = sn_arp_capture_session_stats(session),
            .totals = &totals
        };
        processed = sn_arp_ui_run_live(ui_context.stats, &totals,
                                       poll_live_ui, &ui_context,
                                       error, sizeof(error)) == 0;
        stop_requested = 1;
        if (!sn_arp_capture_session_finish(session, error, sizeof(error))) {
            processed = false;
        }
        stats = *sn_arp_capture_session_stats(session);
        sn_arp_capture_session_stats(session)->analysis = NULL;
        sn_arp_capture_session_release(session);
    } else {
        processed = sn_arp_capture_process(capture, config, &stats, &stop_requested,
                                           error, sizeof(error));
    }
    if (!processed) {
        fprintf(stderr, "arpwatch-ng-tui: live capture failed: %s\n", error);
    }
    have_capture_stats = sn_capture_get_stats(capture, &capture_stats,
                                              error, sizeof(error));
    printf("ARP packets=%" PRIu64 " decoded=%" PRIu64 " truncated=%" PRIu64
           " malformed=%" PRIu64 " unsupported=%" PRIu64 "\n",
           stats.state.captured, stats.state.decoded, stats.state.truncated,
           stats.state.malformed, stats.state.unsupported);
    printf("Non-ARP skipped=%" PRIu64 " unclassified link headers=%" PRIu64
           " deleted segments=%" PRIu64 "\n",
           stats.non_arp, stats.unclassified, stats.deleted_segments);
    if (have_capture_stats) {
        printf("Capture counters: received=%" PRIu64 " dropped=%" PRIu64
               " interface-dropped=%" PRIu64 "\n",
               capture_stats.received, capture_stats.dropped,
               capture_stats.interface_dropped);
    } else {
        fprintf(stderr, "arpwatch-ng-tui: capture-loss counters unavailable: %s\n", error);
    }
    printf("Packet logging=%s address logging=%s\n",
           config->rotation.packet_logging ? "on" : "off",
           config->rotation.address_logging ? "on" : "off");
    if (show_hosts && stats.analysis != NULL) {
        print_hosts(stats.analysis);
    }
    sn_arp_replay_stats_release(&stats);
    sn_capture_close(capture);
    return processed ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *interface_name = NULL;
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
        } else if (strcmp(argv[index], "--interface") == 0 &&
                   index + 1 < argc && interface_name == NULL) {
            interface_name = argv[++index];
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
    if ((pcap_path == NULL) == (interface_name == NULL) || config_path == NULL ||
        (show_hosts && use_tui)) {
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
    if (interface_name != NULL) {
        return run_live_capture(interface_name, &config, show_hosts, use_tui);
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