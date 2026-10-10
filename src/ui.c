#include "sniffit_ng/ui.h"
#include "sniffit_ng/icmp_payload_view.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <curses.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

struct ui_filter {
    bool source_ip_enabled;
    bool destination_ip_enabled;
    bool source_port_enabled;
    bool destination_port_enabled;
    uint8_t source_ip[4];
    uint8_t destination_ip[4];
    uint16_t source_port;
    uint16_t destination_port;
};

struct ui_detail_context {
    struct sn_monitor *monitor;
    const struct ui_filter *filter;
    const struct sn_flow **flows;
    size_t flow_count;
    size_t *selected;
    size_t *scroll_start;
    bool show_stats;
    bool payload_logging_active;
    bool payload_inspection_active;
    bool *capture_polling;
    const char **capture_status;
    const struct sn_monitor_rates *rates;
};

static bool endpoint_matches(const struct sn_flow_endpoint *endpoint,
                             bool ip_enabled,
                             const uint8_t ip[4],
                             bool port_enabled,
                             uint16_t port)
{
    return (!ip_enabled || memcmp(endpoint->ipv4, ip, 4U) == 0) &&
           (!port_enabled || endpoint->port == port);
}

static bool flow_matches(const struct sn_flow *flow, const struct ui_filter *filter)
{
    for (size_t source = 0U; source < 2U; ++source) {
        size_t destination = 1U - source;
        if (endpoint_matches(&flow->endpoints[source],
                             filter->source_ip_enabled, filter->source_ip,
                             filter->source_port_enabled, filter->source_port) &&
            endpoint_matches(&flow->endpoints[destination],
                             filter->destination_ip_enabled, filter->destination_ip,
                             filter->destination_port_enabled, filter->destination_port)) {
            return true;
        }
    }
    return false;
}

static size_t collect_flows(struct sn_monitor *monitor,
                            const struct ui_filter *filter,
                            const struct sn_flow **flows)
{
    size_t count = 0U;

    for (size_t index = 0U; index < SN_FLOW_TABLE_CAPACITY; ++index) {
        const struct sn_flow *flow = &monitor->flows.entries[index];
        if (flow->active && flow_matches(flow, filter)) {
            flows[count++] = flow;
        }
    }
    sn_ui_sort_flows(flows, count);
    return count;
}

static const char *protocol_name(uint8_t protocol)
{
    switch (protocol) {
    case 6U:
        return "TCP";
    case 17U:
        return "UDP";
    case 1U:
        return "ICMP";
    default:
        return "IP";
    }
}

static uint64_t monotonic_time_ns(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) {
        return 0U;
    }
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void draw_filter_line(const struct ui_filter *filter)
{
    char source[INET_ADDRSTRLEN] = "All";
    char destination[INET_ADDRSTRLEN] = "All";

    if (filter->source_ip_enabled) {
        (void)inet_ntop(AF_INET, filter->source_ip, source, sizeof(source));
    }
    if (filter->destination_ip_enabled) {
        (void)inet_ntop(AF_INET, filter->destination_ip, destination, sizeof(destination));
    }
    mvprintw(LINES - 2, 0, "Source: %.15s:%s%u  Destination: %.15s:%s%u",
             source,
             filter->source_port_enabled ? "" : "All/",
             filter->source_port_enabled ? filter->source_port : 0U,
             destination,
             filter->destination_port_enabled ? "" : "All/",
             filter->destination_port_enabled ? filter->destination_port : 0U);
    clrtoeol();
}

static void draw_screen(struct sn_monitor *monitor,
                        const struct ui_filter *filter,
                        const struct sn_flow **flows,
                        size_t flow_count,
                        size_t selected,
                        size_t scroll_start,
                        bool show_stats,
                        bool payload_logging_active,
                        bool payload_inspection_active,
                        const char *capture_status,
                        const struct sn_monitor_rates *rates)
{
    size_t visible_rows;

    erase();
    if (COLS < 80 || LINES < 18) {
        mvaddstr(0, 0, "Sniffit NG needs a terminal at least 80 columns by 18 rows.");
        mvaddstr(2, 0, "Resize the terminal, or press q to quit.");
        refresh();
        return;
    }

    attron(A_BOLD);
    mvprintw(0, 0, "Sniffit NG | Ethernet / IPv4 monitor%s%s",
             payload_logging_active ? " | PAYLOAD LOGGING ACTIVE" : "",
             payload_inspection_active ? " | ICMP PAYLOAD DISPLAY ENABLED" : "");
    attroff(A_BOLD);
    mvprintw(1, 0, "PROTO  ENDPOINT A                         ENDPOINT B                         PACKETS A>B/B>A");
    mvhline(2, 0, ACS_HLINE, COLS);

    visible_rows = (size_t)(LINES - (show_stats ? 14 : 5));
    if (scroll_start > flow_count) {
        scroll_start = flow_count;
    }
    if (visible_rows > flow_count - scroll_start) {
        visible_rows = flow_count - scroll_start;
    }
    for (size_t row = 0U; row < visible_rows; ++row) {
        char endpoint_a[INET_ADDRSTRLEN] = "?";
        char endpoint_b[INET_ADDRSTRLEN] = "?";
        size_t flow_index = scroll_start + row;
        const struct sn_flow *flow = flows[flow_index];

        (void)inet_ntop(AF_INET, flow->endpoints[0].ipv4,
                        endpoint_a, sizeof(endpoint_a));
        (void)inet_ntop(AF_INET, flow->endpoints[1].ipv4,
                        endpoint_b, sizeof(endpoint_b));
        if (flow_index == selected) {
            attron(A_REVERSE);
        }
        mvprintw((int)row + 3, 0, "%-5s %-15s:%-5u -> %-15s:%-5u %8llu/%-8llu",
                 protocol_name(flow->protocol), endpoint_a,
                 flow->endpoints[0].port, endpoint_b,
                 flow->endpoints[1].port,
                 (unsigned long long)flow->packets[0],
                 (unsigned long long)flow->packets[1]);
        clrtoeol();
        if (flow_index == selected) {
            attroff(A_REVERSE);
        }
    }
    if (visible_rows == 0U) {
        mvaddstr(3, 0, flow_count == 0U ? "No flows in this capture." :
                                          "No flows match the current masks.");
    }

    if (show_stats) {
        int stats_row = LINES - 11;
        mvhline(stats_row - 1, 0, ACS_HLINE, COLS);
        if (rates != NULL) {
            mvprintw(stats_row, 0, "Packets/sec: IP %llu  TCP %llu  UDP %llu  ICMP %llu",
                     (unsigned long long)rates->ipv4_packets_per_second,
                     (unsigned long long)rates->tcp_packets_per_second,
                     (unsigned long long)rates->udp_packets_per_second,
                     (unsigned long long)rates->icmp_packets_per_second);
            mvprintw(stats_row + 1, 0, "Bytes/sec: TCP %llu  UDP %llu",
                     (unsigned long long)rates->tcp_bytes_per_second,
                     (unsigned long long)rates->udp_bytes_per_second);
        } else {
            mvprintw(stats_row, 0, "Packet totals: IP %llu  TCP %llu  UDP %llu  ICMP %llu",
                     (unsigned long long)monitor->stats.ipv4_packets,
                     (unsigned long long)monitor->stats.tcp_packets,
                     (unsigned long long)monitor->stats.udp_packets,
                     (unsigned long long)monitor->stats.icmp_packets);
            mvprintw(stats_row + 1, 0, "Byte totals: TCP %llu  UDP %llu",
                     (unsigned long long)monitor->stats.tcp_bytes,
                     (unsigned long long)monitor->stats.udp_bytes);
        }
        mvprintw(stats_row + 2, 0, "Truncated: %llu  Malformed: %llu  Unsupported: %llu  Dropped UI events: %llu",
                 (unsigned long long)monitor->stats.truncated_packets,
                 (unsigned long long)monitor->stats.malformed_packets,
                 (unsigned long long)monitor->stats.unsupported_packets,
                 (unsigned long long)monitor->stats.dropped_events);
    }

    draw_filter_line(filter);
    attron(A_REVERSE);
    if (capture_status != NULL) {
        mvaddnstr(LINES - 1, 0, capture_status, COLS - 1);
    } else {
        mvaddstr(LINES - 1, 0, " j/k or arrows: move  1-4: masks  Enter: details  n: stats  r: reset  q: quit ");
    }
    clrtoeol();
    attroff(A_REVERSE);
    refresh();
}

static bool read_line(const char *prompt, char *buffer, size_t capacity)
{
    size_t maximum;

    if (capacity < 2U || capacity > (size_t)INT32_MAX) {
        return false;
    }
    maximum = capacity - 1U;
    echo();
    curs_set(1);
    move(LINES - 2, 0);
    clrtoeol();
    mvaddstr(LINES - 2, 0, prompt);
    refresh();
    int result = getnstr(buffer, (int)maximum);
    noecho();
    curs_set(0);
    return result != ERR;
}

static void set_ip_filter(const char *prompt, bool *enabled, uint8_t address[4])
{
    char input[64] = {0};

    if (!read_line(prompt, input, sizeof(input))) {
        return;
    }
    if (strcasecmp(input, "all") == 0 || input[0] == '\0') {
        *enabled = false;
    } else if (inet_pton(AF_INET, input, address) == 1) {
        *enabled = true;
    }
}

static void set_port_filter(const char *prompt, bool *enabled, uint16_t *port)
{
    char input[32] = {0};
    char *end = NULL;
    unsigned long value;

    if (!read_line(prompt, input, sizeof(input))) {
        return;
    }
    if (input[0] == '\0') {
        return;
    }
    value = strtoul(input, &end, 10);
    if (end == input || *end != '\0' || value > UINT16_MAX) {
        return;
    }
    *port = (uint16_t)value;
    *enabled = value != 0UL;
}

static bool same_flow_identity(const struct sn_flow *left, const struct sn_flow *right)
{
    return left->protocol == right->protocol &&
           memcmp(left->endpoints[0].ipv4, right->endpoints[0].ipv4, 4U) == 0 &&
           left->endpoints[0].port == right->endpoints[0].port &&
           memcmp(left->endpoints[1].ipv4, right->endpoints[1].ipv4, 4U) == 0 &&
           left->endpoints[1].port == right->endpoints[1].port;
}

static void discard_monitor_events(struct sn_monitor *monitor)
{
    struct sn_monitor_event event;

    while (sn_monitor_next_event(monitor, &event)) {
    }
}

static void append_icmp_sample(WINDOW *history,
                               const struct sn_icmp_echo_sample *sample)
{
    const char *type_name = sample->type == 8U ? "request" : "reply";
    const char *direction = sample->direction == 0U ? "A>B" : "B>A";

    (void)wprintw(history, "ICMP Echo %s %s id=%u seq=%u (%zu bytes)\n",
                  type_name, direction, sample->identifier, sample->sequence,
                  sample->payload_length);
    if (sample->payload_length == 0U) {
        (void)waddstr(history, "  (empty payload)\n");
    }
    for (size_t offset = 0U; offset < sample->payload_length; offset += 4U) {
        char hex[SN_ICMP_DISPLAY_HEX_CAPACITY];
        char ascii[SN_ICMP_DISPLAY_ASCII_CAPACITY];
        size_t chunk_length = sample->payload_length - offset;

        if (chunk_length > 4U) {
            chunk_length = 4U;
        }
        if (sn_icmp_format_payload_row(sample->payload + offset, chunk_length,
                                       hex, sizeof(hex), ascii, sizeof(ascii)) == 0U) {
            break;
        }
        (void)wprintw(history, "  %04zu  %-11s |%s|\n", offset, hex, ascii);
    }
    (void)waddch(history, '\n');
}

static void refresh_detail_panel(WINDOW *panel, WINDOW *history, int panel_x)
{
    int history_height = LINES - 11;
    int latest_line = getcury(history);
    int top_line = latest_line >= history_height ?
        latest_line - history_height + 1 : 0;

    (void)wnoutrefresh(panel);
    (void)prefresh(history, top_line, 0, 8, panel_x + 2, LINES - 4, COLS - 3);
}

static void append_matching_events(struct sn_monitor *monitor,
                                   const struct sn_flow *identity,
                                   WINDOW *panel,
                                   WINDOW *history,
                                   bool payload_inspection_active,
                                   size_t *seen_count,
                                   size_t *seen_next,
                                   int panel_x)
{
    struct sn_monitor_event event;
    bool changed = false;

    while (sn_monitor_next_event(monitor, &event)) {
        const struct sn_flow *updated = &event.flow;

        if (!same_flow_identity(updated, identity)) {
            continue;
        }
        (void)mvwprintw(panel, 5, 2, "Packets A>B/B>A: %llu/%llu",
                        (unsigned long long)updated->packets[0],
                        (unsigned long long)updated->packets[1]);
        (void)mvwprintw(panel, 6, 2, "Bytes A>B/B>A: %llu/%llu",
                        (unsigned long long)updated->bytes[0],
                        (unsigned long long)updated->bytes[1]);

        if (payload_inspection_active &&
            (updated->icmp_history_count != *seen_count ||
             updated->icmp_history_next != *seen_next)) {
            const struct sn_icmp_echo_sample *sample =
                sn_flow_icmp_history_at(updated, updated->icmp_history_count - 1U);
            if (sample != NULL) {
                append_icmp_sample(history, sample);
                *seen_count = updated->icmp_history_count;
                *seen_next = updated->icmp_history_next;
                changed = true;
            }
        }
    }
    if (changed) {
        refresh_detail_panel(panel, history, panel_x);
    } else {
        (void)wnoutrefresh(panel);
        (void)doupdate();
    }
}

static void draw_detail_contents(struct ui_detail_context *context,
                                 const struct sn_flow *flow,
                                 WINDOW *panel,
                                 WINDOW *history,
                                 int panel_x,
                                 size_t *seen_count,
                                 size_t *seen_next,
                                 bool load_history)
{
    const char *service_a = sn_ui_port_service_name(flow->protocol,
                                                    flow->endpoints[0].port);
    const char *service_b = sn_ui_port_service_name(flow->protocol,
                                                    flow->endpoints[1].port);

    if (load_history) {
        (void)werase(history);
        *seen_count = flow->icmp_history_count;
        *seen_next = flow->icmp_history_next;
    }
    (void)werase(panel);
    (void)box(panel, 0, 0);
    (void)mvwprintw(panel, 1, 2, "%s flow", protocol_name(flow->protocol));
    (void)mvwprintw(panel, 2, 2, "A %u.%u.%u.%u:%u",
                    flow->endpoints[0].ipv4[0], flow->endpoints[0].ipv4[1],
                    flow->endpoints[0].ipv4[2], flow->endpoints[0].ipv4[3],
                    flow->endpoints[0].port);
    (void)mvwprintw(panel, 3, 2, "B %u.%u.%u.%u:%u",
                    flow->endpoints[1].ipv4[0], flow->endpoints[1].ipv4[1],
                    flow->endpoints[1].ipv4[2], flow->endpoints[1].ipv4[3],
                    flow->endpoints[1].port);
    (void)mvwprintw(panel, 4, 2, "Services A/B: %s / %s",
                    service_a != NULL ? service_a : "unknown",
                    service_b != NULL ? service_b : "unknown");
    (void)mvwprintw(panel, 5, 2, "Packets A>B/B>A: %llu/%llu",
                    (unsigned long long)flow->packets[0],
                    (unsigned long long)flow->packets[1]);
    (void)mvwprintw(panel, 6, 2, "Bytes A>B/B>A: %llu/%llu",
                    (unsigned long long)flow->bytes[0],
                    (unsigned long long)flow->bytes[1]);
    (void)mvwprintw(panel, LINES - 2, 2, "Traffic: %s", protocol_name(flow->protocol));

    if (!load_history) {
        return;
    }
    if (flow->protocol == 1U && context->payload_inspection_active) {
        for (size_t index = 0U; index < flow->icmp_history_count; ++index) {
            const struct sn_icmp_echo_sample *sample =
                sn_flow_icmp_history_at(flow, index);
            if (sample != NULL) {
                append_icmp_sample(history, sample);
            }
        }
        if (flow->icmp_history_count == 0U) {
            (void)waddstr(history, "Waiting for ICMP Echo packets...\n");
        }
    } else if (flow->protocol == 1U) {
        (void)waddstr(history,
                       "ICMP payload inspection is disabled.\n"
                       "Enable --inspect-payloads and add the acknowledged config comment.\n"
                       "No payload bytes are retained.\n");
    } else {
        (void)waddstr(history, "Per-packet payload inspection is not enabled for this protocol.\n");
    }
    refresh_detail_panel(panel, history, panel_x);
}

static void redraw_detail_background(struct ui_detail_context *context)
{
    size_t visible_rows = LINES > (context->show_stats ? 14 : 5) ?
        (size_t)(LINES - (context->show_stats ? 14 : 5)) : 1U;

    context->flow_count = collect_flows(context->monitor, context->filter,
                                        context->flows);
    if (context->flow_count == 0U) {
        return;
    }
    if (*context->selected >= context->flow_count) {
        *context->selected = context->flow_count - 1U;
    }
    *context->scroll_start = sn_ui_window_start(context->flow_count,
                                                 *context->selected,
                                                 visible_rows,
                                                 *context->scroll_start);
}

static void draw_detail_background(struct ui_detail_context *context)
{
    draw_screen(context->monitor, context->filter, context->flows,
                context->flow_count, *context->selected, *context->scroll_start,
                context->show_stats, context->payload_logging_active,
                context->payload_inspection_active, *context->capture_status,
                context->rates);
}

static void show_details(struct ui_detail_context *context,
                         sn_ui_poll_callback poll_capture,
                         void *poll_context)
{
    struct sn_flow identity = *context->flows[*context->selected];
    int panel_x = COLS * 2 / 5;
    int panel_width = COLS - panel_x;
    int history_width = panel_width - 4;
    size_t seen_count = 0U;
    size_t seen_next = 0U;
    WINDOW *panel = newwin(LINES, panel_width, 0, panel_x);
    WINDOW *history = newpad(8192, history_width);
    int key;

    if (panel == NULL || history == NULL) {
        if (panel != NULL) {
            delwin(panel);
        }
        if (history != NULL) {
            delwin(history);
        }
        return;
    }
    (void)scrollok(history, true);
    (void)idlok(history, true);
    draw_detail_contents(context, &identity, panel, history, panel_x,
                         &seen_count, &seen_next, true);

    for (;;) {
        key = getch();
        if (key == ERR) {
            if (*context->capture_polling) {
                enum sn_ui_poll_result result = poll_capture(poll_context,
                                                             context->capture_status);
                if (result == SN_UI_POLL_STOPPED) {
                    *context->capture_polling = false;
                } else if (result == SN_UI_POLL_UPDATED) {
                    append_matching_events(context->monitor, &identity, panel, history,
                                           context->payload_inspection_active,
                                           &seen_count, &seen_next, panel_x);
                }
            }
            continue;
        }
        if (key == KEY_RESIZE) {
            (void)resize_term(0, 0);
            panel_x = COLS * 2 / 5;
            panel_width = COLS - panel_x;
            history_width = panel_width - 4;
            (void)wresize(panel, LINES, panel_width);
            (void)mvwin(panel, 0, panel_x);
            (void)wresize(history, 8192, history_width);
            draw_detail_background(context);
            draw_detail_contents(context, &identity, panel, history, panel_x,
                                 &seen_count, &seen_next, false);
            refresh_detail_panel(panel, history, panel_x);
            continue;
        }

        int direction = sn_ui_detail_navigation_direction(key, KEY_UP, KEY_DOWN);
        if (direction != 0) {
            redraw_detail_background(context);
            if (context->flow_count > 0U) {
                size_t next = *context->selected;
                if (direction < 0 && next > 0U) {
                    --next;
                } else if (direction > 0 && next + 1U < context->flow_count) {
                    ++next;
                }
                if (next != *context->selected) {
                    *context->selected = next;
                    size_t visible_rows = LINES > (context->show_stats ? 14 : 5) ?
                        (size_t)(LINES - (context->show_stats ? 14 : 5)) : 1U;
                    *context->scroll_start = sn_ui_window_start(context->flow_count,
                                                                 next, visible_rows,
                                                                 *context->scroll_start);
                    draw_detail_background(context);
                    identity = *context->flows[next];
                    draw_detail_contents(context, &identity, panel, history, panel_x,
                                         &seen_count, &seen_next, true);
                }
            }
            continue;
        }
        if (sn_ui_detail_should_dismiss(key, ERR, KEY_RESIZE)) {
            break;
        }
    }

    delwin(history);
    delwin(panel);
    touchwin(stdscr);
    refresh();
}

static void reset_monitor(struct sn_monitor *monitor)
{
    sn_flow_table_init(&monitor->flows, monitor->flows.idle_timeout_ns);
    monitor->stats = (struct sn_monitor_stats){0};
    monitor->event_head = 0U;
    monitor->event_count = 0U;
}

int sn_ui_run(struct sn_monitor *monitor,
              bool payload_logging_active,
              bool payload_inspection_active,
              sn_ui_poll_callback poll_capture,
              void *poll_context)
{
    struct ui_filter filter = {0};
    const struct sn_flow *flows[SN_FLOW_TABLE_CAPACITY];
    size_t selected = 0U;
    size_t scroll_start = 0U;
    bool show_stats = false;
    bool capture_polling = poll_capture != NULL;
    const char *capture_status = NULL;
    struct sn_monitor_rate_sampler rate_sampler;
    struct sn_monitor_rates rates = {0};
    bool rates_ready = false;
    int key;

    if (monitor == NULL || initscr() == NULL) {
        return 1;
    }
    cbreak();
    noecho();
    keypad(stdscr, true);
    wtimeout(stdscr, capture_polling ? 50 : -1);
    (void)curs_set(0);
    sn_monitor_rate_sampler_init(&rate_sampler);

    for (;;) {
        size_t flow_count = collect_flows(monitor, &filter, flows);

        if (capture_polling) {
            if (sn_monitor_rate_sample(&rate_sampler, &monitor->stats,
                                       monotonic_time_ns(), &rates)) {
                rates_ready = true;
            }
            if (poll_capture(poll_context, &capture_status) == SN_UI_POLL_STOPPED) {
                capture_polling = false;
            }
            discard_monitor_events(monitor);
        }
        flow_count = collect_flows(monitor, &filter, flows);
        if (selected >= flow_count && flow_count > 0U) {
            selected = flow_count - 1U;
        }
        size_t visible_rows = LINES > (show_stats ? 14 : 5) ?
            (size_t)(LINES - (show_stats ? 14 : 5)) : 1U;
        scroll_start = sn_ui_window_start(flow_count, selected,
                                          visible_rows, scroll_start);
        struct ui_detail_context detail_context = {
            .monitor = monitor,
            .filter = &filter,
            .flows = flows,
            .flow_count = flow_count,
            .selected = &selected,
            .scroll_start = &scroll_start,
            .show_stats = show_stats,
            .payload_logging_active = payload_logging_active,
            .payload_inspection_active = payload_inspection_active,
            .capture_polling = &capture_polling,
            .capture_status = &capture_status,
            .rates = rates_ready ? &rates : (capture_polling ? &rates : NULL)
        };
        draw_screen(monitor, &filter, flows, flow_count, selected, scroll_start, show_stats,
                payload_logging_active, payload_inspection_active, capture_status,
                detail_context.rates);
        key = getch();
        if (key == 'q' || key == 'Q') {
            break;
        }
        switch (key) {
        case KEY_DOWN:
        case 'j':
        case 'J':
            if (selected + 1U < flow_count) {
                ++selected;
            }
            break;
        case KEY_UP:
        case 'k':
        case 'K':
            if (selected > 0U) {
                --selected;
            }
            break;
        case 'n':
        case 'N':
            show_stats = !show_stats;
            break;
        case 'r':
        case 'R':
            reset_monitor(monitor);
            sn_monitor_rate_sampler_init(&rate_sampler);
            rates = (struct sn_monitor_rates){0};
            rates_ready = false;
            selected = 0U;
            scroll_start = 0U;
            break;
        case '\n':
        case KEY_ENTER:
            if (flow_count > 0U) {
                show_details(&detail_context, poll_capture, poll_context);
            }
            break;
        case '1':
        case KEY_F(1):
            set_ip_filter("Source host (IPv4 or all): ",
                          &filter.source_ip_enabled, filter.source_ip);
            selected = 0U;
            scroll_start = 0U;
            break;
        case '2':
        case KEY_F(2):
            set_ip_filter("Destination host (IPv4 or all): ",
                          &filter.destination_ip_enabled, filter.destination_ip);
            selected = 0U;
            scroll_start = 0U;
            break;
        case '3':
        case KEY_F(3):
            set_port_filter("Source port (0 for all): ",
                            &filter.source_port_enabled, &filter.source_port);
            selected = 0U;
            scroll_start = 0U;
            break;
        case '4':
        case KEY_F(4):
            set_port_filter("Destination port (0 for all): ",
                            &filter.destination_port_enabled, &filter.destination_port);
            selected = 0U;
            scroll_start = 0U;
            break;
        case KEY_RESIZE:
            (void)resize_term(0, 0);
            break;
        default:
            break;
        }
    }

    endwin();
    return 0;
}
