#include "sniffit_ng/capture.h"
#include "sniffit_ng/config.h"
#include "sniffit_ng/monitor.h"
#include "sniffit_ng/pcap_writer.h"
#include "sniffit_ng/payload_log.h"
#include "sniffit_ng/privilege.h"
#include "sniffit_ng/ui.h"

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SN_CONFIG_PATH_CAPACITY 4096U

static void print_usage(FILE *stream, const char *program)
{
    fprintf(stream, "Usage: %s --read-pcap FILE [--config FILE] [--inspect-payloads]\n", program);
    fprintf(stream, "       %s --interface DEVICE [--promiscuous] [--config FILE] [--inspect-payloads]\n", program);
    fprintf(stream, "       %s [--read-pcap FILE|--interface DEVICE] --write-pcap FILE\n", program);
    fprintf(stream, "       %s [--read-pcap FILE|--interface DEVICE] --payload-logging [--payload-log FILE]\n", program);
    fprintf(stream, "       %s --help | --version\n", program);
}

static bool load_application_config(const char *requested_path,
                                    struct sn_app_config *config,
                                    char *error,
                                    size_t error_capacity)
{
    char default_path[SN_CONFIG_PATH_CAPACITY];
    const char *config_path = requested_path;
    const char *base;

    sn_config_init(config);
    if (config_path == NULL) {
        base = getenv("XDG_CONFIG_HOME");
        if (base != NULL && base[0] != '\0') {
            if (snprintf(default_path, sizeof(default_path),
                         "%s/sniffit-ng/config", base) >= (int)sizeof(default_path)) {
                (void)snprintf(error, error_capacity, "default config path is too long");
                return false;
            }
        } else {
            base = getenv("HOME");
            if (base == NULL || base[0] == '\0') {
                return true;
            }
            if (snprintf(default_path, sizeof(default_path),
                         "%s/.config/sniffit-ng/config", base) >= (int)sizeof(default_path)) {
                (void)snprintf(error, error_capacity, "default config path is too long");
                return false;
            }
        }
        config_path = default_path;
        if (access(config_path, F_OK) != 0) {
            if (errno == ENOENT) {
                return true;
            }
            (void)snprintf(error, error_capacity, "cannot access default config: %s",
                           strerror(errno));
            return false;
        }
    }
    return sn_config_load_file(config_path, config, error, error_capacity);
}

struct live_context {
    struct sn_capture *capture;
    struct sn_monitor *monitor;
    struct sn_payload_log *payload_log;
    struct sn_pcap_writer *pcap_writer;
    char error[256];
};

static void drain_monitor_events(struct sn_monitor *monitor)
{
    struct sn_monitor_event event;

    while (sn_monitor_next_event(monitor, &event)) {
    }
}

static enum sn_ui_poll_result poll_live_capture(void *context,
                                                const char **status)
{
    struct live_context *live = context;
    bool updated = false;

    if (status != NULL) {
        *status = NULL;
    }

    for (unsigned int index = 0U; index < 64U; ++index) {
        struct sn_capture_packet packet;
        enum sn_capture_result result = sn_capture_next(
            live->capture, &packet, live->error, sizeof(live->error));

        if (result == SN_CAPTURE_TIMEOUT) {
            return updated ? SN_UI_POLL_UPDATED : SN_UI_POLL_IDLE;
        }
        if (result != SN_CAPTURE_PACKET) {
            char message[sizeof(live->error)];
            (void)snprintf(message, sizeof(message), "Capture stopped: %.200s",
                           live->error[0] != '\0' ? live->error : "unknown libpcap error");
            (void)snprintf(live->error, sizeof(live->error), "%s", message);
            if (status != NULL) {
                *status = live->error;
            }
            return SN_UI_POLL_STOPPED;
        }

        (void)sn_monitor_process(live->monitor, &packet);
        updated = true;
        if (live->payload_log != NULL &&
            !sn_payload_log_write_packet(live->payload_log, &packet)) {
            (void)snprintf(live->error, sizeof(live->error),
                           "Capture stopped: payload log write failed");
            if (status != NULL) {
                *status = live->error;
            }
            return SN_UI_POLL_STOPPED;
        }
        if (live->pcap_writer != NULL &&
            !sn_pcap_writer_write(live->pcap_writer, &packet)) {
            (void)snprintf(live->error, sizeof(live->error),
                           "Capture stopped: pcap write failed");
            if (status != NULL) {
                *status = live->error;
            }
            return SN_UI_POLL_STOPPED;
        }
    }
    return updated ? SN_UI_POLL_UPDATED : SN_UI_POLL_IDLE;
}

static bool acknowledge_capture_recording(void)
{
    FILE *terminal = fopen("/dev/tty", "r+");
    bool accepted;

    if (terminal == NULL || !isatty(fileno(terminal))) {
        if (terminal != NULL) {
            fclose(terminal);
        }
        fprintf(stderr, "sniffit-ng: capture recording requires an interactive terminal for acknowledgment\n");
        return false;
    }
    accepted = sn_capture_recording_confirm(terminal, terminal);
    fclose(terminal);
    return accepted;
}

static int replay_pcap(const char *path,
                       bool payload_logging_enabled,
                       bool pcap_recording_enabled,
                       bool payload_inspection_enabled,
                       const char *payload_log_path,
                       const char *pcap_output_path)
{
    char error[256] = {0};
    struct sn_capture_packet packet;
    struct sn_capture *capture;
    struct sn_payload_log *payload_log = NULL;
    struct sn_pcap_writer *pcap_writer = NULL;
    struct sn_monitor monitor;
    enum sn_packet_link_type link_type;
    enum sn_capture_result result;
    int status = 0;

    capture = sn_capture_open_offline(path, error, sizeof(error));
    if (capture == NULL) {
        fprintf(stderr, "sniffit-ng: %s\n", error);
        return 1;
    }

    if (pcap_recording_enabled) {
        if (!sn_capture_get_link_type(capture, &link_type)) {
            fprintf(stderr, "sniffit-ng: cannot determine capture link type\n");
            sn_capture_close(capture);
            return 1;
        }
        pcap_writer = sn_pcap_writer_open(pcap_output_path, link_type,
                                          error, sizeof(error));
        if (pcap_writer == NULL) {
            fprintf(stderr, "sniffit-ng: cannot open pcap recording: %s\n", error);
            sn_capture_close(capture);
            return 1;
        }
    }

    if (payload_logging_enabled) {
        payload_log = sn_payload_log_open(payload_log_path, error, sizeof(error));
        if (payload_log == NULL) {
            fprintf(stderr, "sniffit-ng: cannot open payload log: %s\n", error);
            (void)sn_pcap_writer_close(pcap_writer);
            sn_capture_close(capture);
            return 1;
        }
    }

    sn_monitor_init(&monitor, SN_FLOW_DEFAULT_IDLE_TIMEOUT_NS);
    sn_monitor_set_payload_inspection(&monitor, payload_inspection_enabled);
    while ((result = sn_capture_next(capture, &packet, error, sizeof(error))) != SN_CAPTURE_EOF) {
        if (result == SN_CAPTURE_TIMEOUT) {
            continue;
        }
        if (result == SN_CAPTURE_ERROR) {
            fprintf(stderr, "sniffit-ng: capture read failed: %s\n", error);
            status = 1;
            break;
        }
        (void)sn_monitor_process(&monitor, &packet);
        drain_monitor_events(&monitor);
        if (payload_log != NULL && !sn_payload_log_write_packet(payload_log, &packet)) {
            fprintf(stderr, "sniffit-ng: failed writing payload log\n");
            status = 1;
            break;
        }
        if (pcap_writer != NULL && !sn_pcap_writer_write(pcap_writer, &packet)) {
            fprintf(stderr, "sniffit-ng: failed writing pcap recording\n");
            status = 1;
            break;
        }
    }

    sn_capture_close(capture);
    if (!sn_pcap_writer_close(pcap_writer)) {
        fprintf(stderr, "sniffit-ng: failed closing pcap recording\n");
        status = 1;
    }
    if (!sn_payload_log_close(payload_log)) {
        fprintf(stderr, "sniffit-ng: failed closing payload log\n");
        status = 1;
    }
    if (status != 0) {
        return status;
    }
    return sn_ui_run(&monitor, NULL,
                     payload_logging_enabled || pcap_recording_enabled,
                     payload_inspection_enabled,
                     NULL, NULL);
}

static int run_live_capture(const char *device,
                            bool promiscuous,
                            bool payload_logging_enabled,
                            bool payload_inspection_enabled,
                            bool resolve_external_addr,
                            const char *payload_log_path,
                            const char *pcap_output_path)
{
    char error[256] = {0};
    struct sn_capture *capture;
    struct sn_payload_log *payload_log = NULL;
    struct sn_pcap_writer *pcap_writer = NULL;
    struct sn_monitor monitor;
    struct sn_network_info network_info;
    struct live_context live;
    enum sn_packet_link_type link_type;
    int ui_result;

    if (!sn_enable_capture_capability(error, sizeof(error))) {
        fprintf(stderr, "sniffit-ng: cannot enable live capture: %s\n", error);
        return 1;
    }
    capture = sn_capture_open_live(device, 65535, promiscuous, 100,
                                   error, sizeof(error));
    if (capture == NULL) {
        fprintf(stderr, "sniffit-ng: cannot open interface %s: %s\n", device, error);
        (void)sn_drop_privileges_to_real_user(error, sizeof(error));
        return 1;
    }
    if (!sn_capture_set_nonblocking(capture, error, sizeof(error))) {
        fprintf(stderr, "sniffit-ng: cannot configure live capture: %s\n", error);
        sn_capture_close(capture);
        (void)sn_drop_privileges_to_real_user(error, sizeof(error));
        return 1;
    }
    if (!sn_capture_get_link_type(capture, &link_type)) {
        fprintf(stderr, "sniffit-ng: cannot determine capture link type\n");
        sn_capture_close(capture);
        (void)sn_drop_privileges_to_real_user(error, sizeof(error));
        return 1;
    }
    if (!sn_drop_privileges_to_real_user(error, sizeof(error))) {
        fprintf(stderr, "sniffit-ng: refusing to process packets with elevated privileges: %s\n",
                error);
        sn_capture_close(capture);
        return 1;
    }
    sn_network_info_init(&network_info, device);
    (void)sn_network_info_find_local_ipv4(&network_info);
    if (resolve_external_addr &&
        sn_ipv4_is_rfc1918(network_info.local_ipv4) &&
        !sn_network_info_resolve_external_ipv4(&network_info)) {
        fprintf(stderr, "sniffit-ng: external IPv4 lookup failed; continuing with local address only\n");
    }
    if (payload_logging_enabled) {
        payload_log = sn_payload_log_open(payload_log_path, error, sizeof(error));
        if (payload_log == NULL) {
            fprintf(stderr, "sniffit-ng: cannot open payload log after privilege drop: %s\n",
                    error);
            sn_capture_close(capture);
            return 1;
        }
    }
    if (pcap_output_path != NULL) {
        pcap_writer = sn_pcap_writer_open(pcap_output_path, link_type,
                                          error, sizeof(error));
        if (pcap_writer == NULL) {
            fprintf(stderr, "sniffit-ng: cannot open pcap recording after privilege drop: %s\n",
                    error);
            (void)sn_payload_log_close(payload_log);
            sn_capture_close(capture);
            return 1;
        }
    }

    sn_monitor_init(&monitor, SN_FLOW_DEFAULT_IDLE_TIMEOUT_NS);
    sn_monitor_set_payload_inspection(&monitor, payload_inspection_enabled);
    live.capture = capture;
    live.monitor = &monitor;
    live.payload_log = payload_log;
    live.pcap_writer = pcap_writer;
    live.error[0] = '\0';
    ui_result = sn_ui_run(&monitor, &network_info,
                          payload_logging_enabled || pcap_writer != NULL,
                          payload_inspection_enabled,
                          poll_live_capture, &live);

    sn_capture_close(capture);
    if (!sn_pcap_writer_close(pcap_writer)) {
        fprintf(stderr, "sniffit-ng: failed closing pcap recording\n");
        (void)sn_payload_log_close(payload_log);
        return 1;
    }
    if (!sn_payload_log_close(payload_log)) {
        fprintf(stderr, "sniffit-ng: failed closing payload log\n");
        return 1;
    }
    return live.error[0] == '\0' ? ui_result : 1;
}

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *pcap_output_path = NULL;
    const char *interface_name = NULL;
    const char *payload_log_path = NULL;
    const char *config_path = NULL;
    bool payload_logging_enabled = false;
    bool payload_inspection_requested = false;
    bool payload_inspection_enabled;
    bool promiscuous = false;
    struct sn_app_config config;
    char config_error[256] = {0};

    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--help") == 0 && argc == 2) {
            print_usage(stdout, argv[0]);
            return 0;
        }
        if (strcmp(argv[index], "--version") == 0 && argc == 2) {
            puts("Sniffit NG 0.1.0");
            return 0;
        }
        if (strcmp(argv[index], "--read-pcap") == 0 && index + 1 < argc && pcap_path == NULL) {
            pcap_path = argv[++index];
        } else if (strcmp(argv[index], "--interface") == 0 &&
                   index + 1 < argc && interface_name == NULL) {
            interface_name = argv[++index];
        } else if (strcmp(argv[index], "--promiscuous") == 0) {
            promiscuous = true;
        } else if (strcmp(argv[index], "--payload-logging") == 0) {
            payload_logging_enabled = true;
        } else if (strcmp(argv[index], "--write-pcap") == 0 && index + 1 < argc &&
                   pcap_output_path == NULL) {
            pcap_output_path = argv[++index];
        } else if (strcmp(argv[index], "--inspect-payloads") == 0) {
            payload_inspection_requested = true;
        } else if (strcmp(argv[index], "--config") == 0 && index + 1 < argc &&
                   config_path == NULL) {
            config_path = argv[++index];
        } else if (strcmp(argv[index], "--payload-log") == 0 && index + 1 < argc &&
                   payload_log_path == NULL) {
            payload_log_path = argv[++index];
        } else {
            print_usage(stderr, argv[0]);
            return 2;
        }
    }

    if ((pcap_path == NULL) == (interface_name == NULL) ||
        (promiscuous && interface_name == NULL) ||
        (payload_log_path != NULL && !payload_logging_enabled)) {
        print_usage(stderr, argv[0]);
        return 2;
    }
    if (!load_application_config(config_path, &config,
                                 config_error, sizeof(config_error))) {
        fprintf(stderr, "sniffit-ng: invalid configuration: %s\n", config_error);
        return 2;
    }
    payload_inspection_enabled = config.inspect_payloads || payload_inspection_requested;
    if (payload_inspection_enabled && !config.payload_display_acknowledged) {
        fprintf(stderr,
                "sniffit-ng: payload display requires this exact active config comment:\n%s\n",
                SN_CONFIG_PAYLOAD_ACK_COMMENT);
        return 2;
    }
    if (payload_inspection_enabled) {
        fprintf(stderr,
                "sniffit-ng: ICMP payload display enabled; inspect only authorized traffic and handle sensitive data ethically\n");
    }
    if ((payload_logging_enabled || pcap_output_path != NULL) &&
        !acknowledge_capture_recording()) {
        fprintf(stderr, "sniffit-ng: capture recording was not acknowledged; refusing to continue\n");
        return 1;
    }
    if (payload_logging_enabled && payload_log_path == NULL) {
        payload_log_path = "sniffit-ng-payload.log";
    }

    if (pcap_path != NULL) {
        return replay_pcap(pcap_path, payload_logging_enabled,
                           pcap_output_path != NULL,
                           payload_inspection_enabled, payload_log_path,
                           pcap_output_path);
    }
    return run_live_capture(interface_name, promiscuous,
                            payload_logging_enabled, payload_inspection_enabled,
                            config.resolve_external_addr,
                            payload_log_path, pcap_output_path);
}
