#include "sniffit_ng/ui.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void seed_flows(struct sn_monitor *monitor)
{
    struct sn_flow *first = &monitor->flows.entries[0];
    struct sn_flow *second = &monitor->flows.entries[1];

    first->active = true;
    first->protocol = 6U;
    first->endpoints[0].ipv4[0] = 152U;
    first->endpoints[0].ipv4[1] = 2U;
    first->endpoints[0].ipv4[2] = 23U;
    first->endpoints[0].ipv4[3] = 104U;
    first->endpoints[0].port = 40000U;
    first->endpoints[1].ipv4[0] = 192U;
    first->endpoints[1].ipv4[1] = 168U;
    first->endpoints[1].ipv4[2] = 1U;
    first->endpoints[1].ipv4[3] = 7U;
    first->endpoints[1].port = 22U;
    first->packets[0] = 1U;

    second->active = true;
    second->protocol = 17U;
    second->endpoints[0].ipv4[0] = 192U;
    second->endpoints[0].ipv4[1] = 168U;
    second->endpoints[0].ipv4[2] = 1U;
    second->endpoints[0].ipv4[3] = 7U;
    second->endpoints[0].port = 40001U;
    second->endpoints[1].ipv4[0] = 192U;
    second->endpoints[1].ipv4[1] = 0U;
    second->endpoints[1].ipv4[2] = 2U;
    second->endpoints[1].ipv4[3] = 1U;
    second->endpoints[1].port = 53U;
    second->packets[0] = 1U;
}

struct ui_poll_context {
    struct sn_monitor *monitor;
    int trigger_fd;
    bool injected;
};

static enum sn_ui_poll_result inject_new_flow(void *opaque, const char **status)
{
    struct ui_poll_context *context = opaque;
    struct sn_flow *selected = &context->monitor->flows.entries[0];
    struct sn_flow *new_flow = &context->monitor->flows.entries[2];
    char trigger;

    (void)status;
    if (context->injected || read(context->trigger_fd, &trigger, 1U) != 1) {
        return SN_UI_POLL_IDLE;
    }

    context->injected = true;
    selected->packets[0] = 2U;
    *new_flow = (struct sn_flow){0};
    new_flow->active = true;
    new_flow->protocol = 6U;
    new_flow->endpoints[0].ipv4[0] = 10U;
    new_flow->endpoints[0].ipv4[3] = 1U;
    new_flow->endpoints[0].port = 1234U;
    new_flow->endpoints[1].ipv4[0] = 10U;
    new_flow->endpoints[1].ipv4[3] = 2U;
    new_flow->endpoints[1].port = 443U;
    context->monitor->events[0] = (struct sn_monitor_event){
        .kind = SN_MONITOR_FLOW_UPDATED,
        .flow = *selected
    };
    context->monitor->events[1] = (struct sn_monitor_event){
        .kind = SN_MONITOR_FLOW_CREATED,
        .flow = *new_flow
    };
    context->monitor->event_head = 0U;
    context->monitor->event_count = 2U;
    return SN_UI_POLL_UPDATED;
}

static bool read_until(int fd, char *output, size_t capacity, size_t *length,
                       const char *text, int timeout_ms)
{
    struct pollfd descriptor = {.fd = fd, .events = POLLIN};

    if (strstr(output, text) != NULL) {
        return true;
    }
    while (*length + 1U < capacity) {
        ssize_t bytes_read;
        int ready = poll(&descriptor, 1U, timeout_ms);

        if (ready <= 0) {
            return false;
        }
        bytes_read = read(fd, output + *length, capacity - *length - 1U);
        if (bytes_read <= 0) {
            return false;
        }
        *length += (size_t)bytes_read;
        output[*length] = '\0';
        if (strstr(output, text) != NULL) {
            return true;
        }
    }
    return false;
}

static size_t count_occurrences(const char *text, const char *needle)
{
    size_t count = 0U;
    size_t needle_length = strlen(needle);

    while ((text = strstr(text, needle)) != NULL) {
        ++count;
        text += needle_length;
    }
    return count;
}

int main(void)
{
    struct winsize terminal_size = {0};
    int trigger_pipe[2];
    int master_fd;
    pid_t child;
    int child_status;
    char output[16384] = {0};
    size_t output_length = 0U;
    bool details_opened;
    bool new_flow_visible_while_open;
    bool selected_counters_updated;
    bool details_followed_highlight;
    bool source_filter_applied;
    bool source_filter_cleared;

    terminal_size.ws_row = 30U;
    terminal_size.ws_col = 120U;
    assert(pipe(trigger_pipe) == 0);
    assert(fcntl(trigger_pipe[0], F_SETFL, O_NONBLOCK) == 0);
    child = forkpty(&master_fd, NULL, NULL, &terminal_size);
    assert(child >= 0);
    if (child == 0) {
        struct sn_monitor monitor;
        struct sn_network_info network_info = {
            .interface_name = "ppp0",
            .local_ipv4 = "192.168.1.7",
            .external_ipv4 = "203.0.113.7"
        };
        struct ui_poll_context poll_context;

        (void)close(trigger_pipe[1]);
        (void)setenv("TERM", "xterm-256color", 1);
        sn_monitor_init(&monitor, UINT64_MAX);
        seed_flows(&monitor);
        poll_context = (struct ui_poll_context){
            .monitor = &monitor,
            .trigger_fd = trigger_pipe[0]
        };
        _exit(sn_ui_run(&monitor, &network_info, false, false,
                inject_new_flow, &poll_context));
    }

    (void)close(trigger_pipe[0]);
    assert(read_until(master_fd, output, sizeof(output), &output_length,
                      "ppp0 ", 1000));
    assert(read_until(master_fd, output, sizeof(output), &output_length,
                      "192.168.1.7", 1000));
    assert(strstr(output, "external 203.0.113.7") != NULL);
    assert(read_until(master_fd, output, sizeof(output), &output_length,
                      "q quit", 1000));
    assert(count_occurrences(output, "\033[38;5;65m") == 2U);
    assert(strstr(output, "\033[38;5;131m") == NULL);
    assert(strstr(output, "DIRECTION") == NULL);
    assert(strstr(output, "IN?") == NULL);
    assert(strstr(output, "t priority") == NULL);

    output[0] = '\0';
    output_length = 0U;
    assert(write(master_fd, "1", 1U) == 1);
    assert(read_until(master_fd, output, sizeof(output), &output_length,
                      "host (IPv4 or all):", 1000));
    assert(!read_until(master_fd, output, sizeof(output), &output_length,
                       "__filter_input_probe__", 100));
    assert(write(master_fd, "192.168.1.7\n", sizeof("192.168.1.7\n") - 1U) ==
           (ssize_t)(sizeof("192.168.1.7\n") - 1U));
    source_filter_applied = read_until(master_fd, output, sizeof(output),
                                       &output_length, "192.168.1.7:All/0", 1000);
    assert(source_filter_applied);

    output[0] = '\0';
    output_length = 0U;
    assert(write(master_fd, "1", 1U) == 1);
    assert(read_until(master_fd, output, sizeof(output), &output_length,
                      "host (IPv4 or all):", 1000));
    assert(write(master_fd, "all\n", sizeof("all\n") - 1U) ==
           (ssize_t)(sizeof("all\n") - 1U));
    source_filter_cleared = read_until(master_fd, output, sizeof(output),
                                       &output_length, "All:All/0", 1000);
    assert(source_filter_cleared);

    output[0] = '\0';
    output_length = 0U;
    assert(write(master_fd, "\n", 1U) == 1);
    details_opened = read_until(master_fd, output, sizeof(output), &output_length,
                                "TCP flow", 1000);
    if (details_opened) {
        assert(write(trigger_pipe[1], "x", 1U) == 1);
    }
    new_flow_visible_while_open = read_until(master_fd, output, sizeof(output),
                                             &output_length, "10.0.0.1", 1000);
    selected_counters_updated = read_until(master_fd, output, sizeof(output),
                                           &output_length,
                                           "Packets A>B/B>A: 2/0", 1000);
    assert(write(master_fd, "\033OB", 3U) == 3);
    details_followed_highlight =
        read_until(master_fd, output, sizeof(output), &output_length,
                   "A 10.0.0.1:1234", 1000);
    assert(write(master_fd, "qq", 2U) == 2);
    assert(waitpid(child, &child_status, 0) == child);
    assert(WIFEXITED(child_status));
    assert(WEXITSTATUS(child_status) == 0);
    assert(close(master_fd) == 0);
    assert(close(trigger_pipe[1]) == 0);
    assert(details_opened);
    assert(new_flow_visible_while_open);
    assert(selected_counters_updated);
    assert(details_followed_highlight);
    puts("curses pty interaction test passed");
    return 0;
}
