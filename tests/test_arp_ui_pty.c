#include "sniffit_ng/capture.h"
#include "sniffit_ng/arp_ui.h"
#include "test_temp.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define SWEEP_TARGETS 120U

/* xterm-256color key sequences in application-keypad mode (from terminfo). */
#define KEY_PGUP "\033[5~"
#define KEY_PGDN "\033[6~"
#define KEY_HOME_APP "\033OH"
#define KEY_END_APP "\033OF"
#define KEY_UP_APP "\033OA"
#define KEY_DOWN_APP "\033OB"
#define CTRL_L "\014"

static void make_arp(uint8_t *frame, uint8_t operation, uint8_t sender_host, uint8_t target_host)
{
    memset(frame, 0, 42U);
    frame[12] = 0x08U;
    frame[13] = 0x06U;
    frame[15] = 1U;
    frame[16] = 0x08U;
    frame[18] = 6U;
    frame[19] = 4U;
    frame[21] = operation;
    frame[22] = 0x02U;
    frame[27] = sender_host;
    frame[28] = 192U;
    frame[29] = 168U;
    frame[30] = 1U;
    frame[31] = sender_host;
    frame[38] = 192U;
    frame[39] = 168U;
    frame[40] = 1U;
    frame[41] = target_host;
}

static void dump(pcap_dumper_t *dumper, const uint8_t *frame, long seconds)
{
    struct pcap_pkthdr header = {0};

    header.ts.tv_sec = seconds;
    header.caplen = 42U;
    header.len = 42U;
    pcap_dump((u_char *)dumper, &header, frame);
}

static void write_text(const char *path, const char *text)
{
    FILE *stream = fopen(path, "w");

    assert(stream != NULL && fputs(text, stream) >= 0 && fclose(stream) == 0);
}

static void send_keys(int fd, const char *keys)
{
    size_t length = strlen(keys);

    assert(write(fd, keys, length) == (ssize_t)length);
}

/* Reads until the terminal output has been quiet for a moment. */
static void drain(int fd, char *output, size_t capacity, size_t *length, int quiet_ms)
{
    struct pollfd descriptor = {.fd = fd, .events = POLLIN};

    while (*length + 1U < capacity && poll(&descriptor, 1U, quiet_ms) > 0) {
        ssize_t bytes_read = read(fd, output + *length, capacity - *length - 1U);

        if (bytes_read <= 0) {
            break;
        }
        *length += (size_t)bytes_read;
    }
    output[*length] = '\0';
}

/* Sends keys, then Ctrl-L so ncurses repaints the whole screen, and returns that screen. */
static void screen_after(int fd, const char *keys, char *output, size_t capacity, size_t *length)
{
    *length = 0U;
    drain(fd, output, capacity, length, 100);
    *length = 0U;
    output[0] = '\0';
    if (keys != NULL) {
        send_keys(fd, keys);
    }
    send_keys(fd, CTRL_L);
    drain(fd, output, capacity, length, 400);
}

static void screen_after_keys(int fd, const char *keys, char *output, size_t capacity,
                              size_t *length)
{
    *length = 0U;
    output[0] = '\0';
    send_keys(fd, keys);
    drain(fd, output, capacity, length, 400);
}

struct live_ui_test_context {
    struct sn_arp_capture_session *session;
    struct sn_arp_view_totals *totals;
    int trigger_fd;
};

static enum sn_arp_ui_poll_result inject_live_arp(void *opaque, char *error_buffer,
                                                   size_t error_capacity)
{
    struct live_ui_test_context *context = opaque;
    uint8_t frame[42];
    char trigger;
    struct sn_capture_packet packet = {0};

    if (read(context->trigger_fd, &trigger, sizeof(trigger)) != (ssize_t)sizeof(trigger)) {
        return SN_ARP_UI_POLL_IDLE;
    }
    if (trigger == '2') {
        sn_arp_capture_session_stats(context->session)->analysis->config
            .talkative_requests_per_minute = 1U;
        make_arp(frame, 1U, 20U, 30U);
    } else {
        make_arp(frame, 1U, 9U, 30U);
        if (trigger == '3') {
            frame[27] = 0x55U;
        }
    }
    packet.data = frame;
    packet.captured_length = sizeof(frame);
    packet.wire_length = sizeof(frame);
    packet.link_type = SN_PACKET_LINK_ETHERNET;
    packet.timestamp.tv_sec = time(NULL);
    if (!sn_arp_capture_session_process(context->session, &packet,
                                        packet.timestamp.tv_sec,
                                        error_buffer, error_capacity)) {
        return SN_ARP_UI_POLL_FAILED;
    }
    {
        const struct sn_arp_replay_stats *stats =
            sn_arp_capture_session_stats(context->session);

        context->totals->arp_packets = stats->state.captured;
        context->totals->decoded = stats->state.decoded;
    }
    return SN_ARP_UI_POLL_UPDATED;
}

static void test_live_view_updates(void)
{
    struct winsize terminal_size = {.ws_row = 24, .ws_col = 100};
    char output[32768] = "";
    size_t output_length = 0U;
    int trigger_pipe[2];
    int master_fd;
    int status;
    pid_t child;

    assert(pipe(trigger_pipe) == 0);
    assert(fcntl(trigger_pipe[0], F_SETFL, O_NONBLOCK) == 0);
    child = forkpty(&master_fd, NULL, NULL, &terminal_size);
    assert(child >= 0);
    if (child == 0) {
        struct sn_arp_config config;
        struct sn_arp_capture_session *session;
        struct sn_arp_replay_stats *stats;
        struct sn_arp_view_totals totals = {.source = "test-interface"};
        const uint8_t local_ipv4[4] = {192U, 168U, 1U, 9U};
        struct live_ui_test_context context;
        char error[256] = {0};
        int result;

        (void)close(trigger_pipe[1]);
        (void)setenv("TERM", "xterm-256color", 1);
        sn_arp_config_init(&config);
        config.rotation.packet_logging = false;
        config.rotation.address_logging = false;
        memcpy(totals.local_ipv4, local_ipv4, sizeof(local_ipv4));
        totals.local_ipv4_known = true;
        session = sn_arp_capture_session_open(&config, error, sizeof(error));
        assert(session != NULL);
        stats = sn_arp_capture_session_stats(session);
        context = (struct live_ui_test_context){
            .session = session,
            .totals = &totals,
            .trigger_fd = trigger_pipe[0]
        };
        result = sn_arp_ui_run_live(stats, &totals, inject_live_arp, &context,
                                    error, sizeof(error));
        assert(sn_arp_capture_session_finish(session, error, sizeof(error)));
        assert(stats->state.decoded == 3U);
        stats->analysis = NULL;
        sn_arp_capture_session_release(session);
        _exit(result);
    }

    assert(close(trigger_pipe[0]) == 0);
    screen_after(master_fd, NULL, output, sizeof(output), &output_length);
    assert(strstr(output, "HOST") != NULL && strstr(output, "test-interface") != NULL);
    assert(strstr(output, "192.168.1.9") == NULL);
    assert(write(trigger_pipe[1], "1", 1U) == 1);
    screen_after_keys(master_fd, "", output, sizeof(output), &output_length);
    assert(strstr(output, "192.168.1.9") != NULL);
    assert(strstr(output, "02:00:00:00:00:09") != NULL);
    assert(strstr(output, "\033[32m") != NULL);
    screen_after(master_fd, "n", output, sizeof(output), &output_length);
    assert(strstr(output, "Packets: ARP 1") != NULL);
    assert(write(trigger_pipe[1], "2", 1U) == 1);
    screen_after_keys(master_fd, "", output, sizeof(output), &output_length);
    assert(strstr(output, "talkative") != NULL && strstr(output, "192.168.1.20") != NULL);
    assert(strstr(output, "\033[36m") != NULL);
    assert(write(trigger_pipe[1], "3", 1U) == 1);
    screen_after_keys(master_fd, "", output, sizeof(output), &output_length);
    assert(strstr(output, "mac-change") != NULL);
    assert(strstr(output, "02:00:00:00:00:55") != NULL);
    if (strstr(output, "\033[38;5;131m") == NULL) {
        (void)fprintf(stderr, "missing muted red SGR, captured %zu bytes:\n%s\n",
                      output_length, output);
    }
    assert(strstr(output, "\033[38;5;131m") != NULL);
    send_keys(master_fd, "q");
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(close(trigger_pipe[1]) == 0 && close(master_fd) == 0);
}

int main(void)
{
    char pcap_path[4096];
    char config_path[4096];
    uint8_t frame[42];
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 256);
    pcap_dumper_t *dumper;
    struct winsize size = {.ws_row = 24, .ws_col = 100};
    char output[131072] = "";
    char pages[sizeof(KEY_PGDN) * 20U] = "";
    size_t length = 0U;
    int master_fd;
    int status;
    pid_t child;
    int pcap_fd;
    int config_fd;

    assert(sn_test_temp_template(pcap_path, sizeof(pcap_path), "a"));
    assert(sn_test_temp_template(config_path, sizeof(config_path), "b"));
    pcap_fd = mkstemp(pcap_path);
    config_fd = mkstemp(config_path);
    assert(pcap_fd >= 0 && close(pcap_fd) == 0 && config_fd >= 0 && close(config_fd) == 0);
    assert(dead != NULL);
    dumper = pcap_dump_open(dead, pcap_path);
    assert(dumper != NULL);
    /* The oldest packet of the swept host is a reply, so "is-at" only shows when its
     * timeline is scrolled to the end. */
    make_arp(frame, 2U, 9U, 30U);
    dump(dumper, frame, 999L);
    for (unsigned int target = 1U; target <= SWEEP_TARGETS; ++target) {
        make_arp(frame, 1U, 9U, (uint8_t)target);
        dump(dumper, frame, 1000L);
    }
    make_arp(frame, 1U, 20U, 5U);
    dump(dumper, frame, 1001L);
    make_arp(frame, 2U, 5U, 20U);
    dump(dumper, frame, 1002L);
    assert(pcap_dump_flush(dumper) == 0);
    pcap_dump_close(dumper);
    pcap_close(dead);
    write_text(config_path,
               "packet_logging = false\naddress_logging = false\nlocal_network = 192.168.1.0/24\n");
    for (int page = 0; page < 20; ++page) {
        strcat(pages, KEY_PGDN);
    }

    child = forkpty(&master_fd, NULL, NULL, &size);
    assert(child >= 0);
    if (child == 0) {
        (void)setenv("TERM", "xterm-256color", 1);
        execl(ARP_CLI_PATH, ARP_CLI_PATH, "--read-pcap", pcap_path, "--config", config_path,
              "--tui", (char *)NULL);
        _exit(127);
    }

    /* Main view: swept host first, no panel, statistics hidden. */
    screen_after(master_fd, NULL, output, sizeof(output), &length);
    assert(strstr(output, "HOST") != NULL && strstr(output, "alerting 1") != NULL);
    assert(strstr(output, "192.168.1.9") != NULL && strstr(output, "sweep") != NULL);
    assert(strstr(output, "n stats") != NULL);
    assert(strstr(output, "who-has") == NULL && strstr(output, "Packets: ARP") == NULL);

    /* Ordinary page navigation must not clear the terminal between screen updates. */
    screen_after_keys(master_fd, KEY_PGDN, output, sizeof(output), &length);
    assert(strstr(output, "\033[2J") == NULL);
    screen_after_keys(master_fd, KEY_PGUP, output, sizeof(output), &length);
    assert(strstr(output, "\033[2J") == NULL);

    /* Statistics toggle at the bottom of the main view, like sniffit-ng. */
    screen_after(master_fd, "n", output, sizeof(output), &length);
    assert(strstr(output, "Packets: ARP 123") != NULL && strstr(output, "Alerts: talkative") != NULL);
    screen_after(master_fd, "n", output, sizeof(output), &length);
    assert(strstr(output, "Packets: ARP") == NULL);

    /* Enter overlays the detail panel; the oldest reply is below the first page. */
    screen_after(master_fd, "\n", output, sizeof(output), &length);
    assert(strstr(output, "ARP host 192.168.1.9") != NULL);
    assert(strstr(output, "(newest first) 1-") != NULL && strstr(output, "/121") != NULL);
    assert(strstr(output, "who-has") != NULL && strstr(output, "sweep: many distinct targets") != NULL);
    assert(strstr(output, "PgUp/PgDn scroll") != NULL);
    assert(strstr(output, "is-at") == NULL);

    /* Timeline paging refreshes the overlay without a terminal-wide clear. */
    screen_after_keys(master_fd, KEY_PGDN, output, sizeof(output), &length);
    assert(strstr(output, "\033[2J") == NULL);
    screen_after_keys(master_fd, KEY_HOME_APP, output, sizeof(output), &length);
    assert(strstr(output, "\033[2J") == NULL);

    /* PgDn scrolls the timeline to its end instead of closing the panel. */
    screen_after(master_fd, pages, output, sizeof(output), &length);
    assert(strstr(output, "ARP host 192.168.1.9") != NULL);
    assert(strstr(output, "-121/121") != NULL && strstr(output, "is-at") != NULL);

    /* PgUp moves back a page: the oldest reply scrolls out of view. */
    screen_after(master_fd, KEY_PGUP, output, sizeof(output), &length);
    assert(strstr(output, "/121") != NULL && strstr(output, "-121/121") == NULL);
    assert(strstr(output, "is-at") == NULL);

    /* Home returns to the newest packets and End goes back to the oldest. */
    screen_after(master_fd, KEY_HOME_APP, output, sizeof(output), &length);
    assert(strstr(output, "(newest first) 1-") != NULL && strstr(output, "is-at") == NULL);
    screen_after(master_fd, KEY_END_APP, output, sizeof(output), &length);
    assert(strstr(output, "-121/121") != NULL && strstr(output, "is-at") != NULL);

    /* The arrow keys still choose the host and reset the scroll; they do not scroll. */
    screen_after(master_fd, KEY_DOWN_APP, output, sizeof(output), &length);
    assert(strstr(output, "ARP host 192.168.1.20") != NULL && strstr(output, "is-at") != NULL);
    assert(strstr(output, "/121") == NULL);
    screen_after(master_fd, KEY_UP_APP, output, sizeof(output), &length);
    assert(strstr(output, "ARP host 192.168.1.9") != NULL);
    assert(strstr(output, "(newest first) 1-") != NULL && strstr(output, "is-at") == NULL);
    screen_after(master_fd, "j", output, sizeof(output), &length);
    assert(strstr(output, "ARP host 192.168.1.20") != NULL);
    screen_after(master_fd, "k", output, sizeof(output), &length);
    assert(strstr(output, "ARP host 192.168.1.9") != NULL);

    /* n toggles statistics while the panel is open; any other key closes the panel. */
    screen_after(master_fd, "n", output, sizeof(output), &length);
    assert(strstr(output, "ARP host 192.168.1.9") != NULL && strstr(output, "Packets: ARP") != NULL);
    screen_after(master_fd, "x", output, sizeof(output), &length);
    assert(strstr(output, "ARP host") == NULL && strstr(output, "HOST") != NULL);

    send_keys(master_fd, "q");
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(close(master_fd) == 0);
    assert(unlink(pcap_path) == 0 && unlink(config_path) == 0);
    test_live_view_updates();
    puts("arp ui pty tests passed");
    return 0;
}
