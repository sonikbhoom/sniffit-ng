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

struct ui_detail_context {
    struct sn_monitor *monitor;
    const struct sn_network_info *network_info;
    const struct sn_ui_flow_filter *filter;
    const struct sn_flow **flows;
    size_t flow_count;
    size_t *selected;
    size_t *scroll_start;
    bool show_stats;
    bool colors_enabled;
    bool recording_active;
    bool payload_inspection_active;
    bool *capture_polling;
    const char **capture_status;
    const struct sn_monitor_rates *rates;
};

enum {
    UI_COLOR_SSH_TELNET = 1,
    UI_COLOR_LOCAL_ADDRESS
};

static bool initialize_ui_colors(void)
{
    short background = COLOR_BLACK;
    short priority_color = COLOR_RED;
    short local_address_color = COLOR_GREEN;

    if (!has_colors() || start_color() == ERR) {
        return false;
    }
    if (COLORS >= 256) {
        priority_color = 131;
        local_address_color = 65;
    }
    if (use_default_colors() != ERR) {
        background = -1;
    }
    return init_pair(UI_COLOR_SSH_TELNET, priority_color, background) != ERR &&
           init_pair(UI_COLOR_LOCAL_ADDRESS, local_address_color, background) != ERR;
}

static size_t collect_flows(struct sn_monitor *monitor,
                            const struct sn_ui_flow_filter *filter,
                            const struct sn_flow **flows)
{
    size_t count = 0U;

    for (size_t index = 0U; index < SN_FLOW_TABLE_CAPACITY; ++index) {
        const struct sn_flow *flow = &monitor->flows.entries[index];
        if (flow->active && sn_ui_flow_matches(flow, filter)) {
            flows[count++] = flow;
        }
    }
    sn_ui_sort_flows_by_priority(flows, count);
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
    case 2U:
        return "IGMP";
    case 112U:
        return "VRRP";
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

static void draw_filter_line(const struct sn_ui_flow_filter *filter)
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

static void draw_title_line(const char *title,
                            size_t local_address_start,
                            size_t local_address_length,
                            bool colors_enabled)
{
    size_t visible_length = COLS > 1 ? (size_t)(COLS - 1) : 0U;

    attron(A_BOLD);
    if (!colors_enabled || local_address_start == SIZE_MAX ||
        local_address_start >= visible_length || local_address_length == 0U) {
        mvaddnstr(0, 0, title, (int)visible_length);
    } else {
        size_t prefix_length = local_address_start;
        size_t address_length = local_address_length;
        size_t suffix_start;

        if (address_length > visible_length - local_address_start) {
            address_length = visible_length - local_address_start;
        }
        if (prefix_length > 0U) {
            mvaddnstr(0, 0, title, (int)prefix_length);
        }
        attroff(A_BOLD);
        attrset(COLOR_PAIR(UI_COLOR_LOCAL_ADDRESS));
        mvaddnstr(0, (int)local_address_start, title + local_address_start,
                  (int)address_length);
        attrset(A_BOLD);
        suffix_start = local_address_start + local_address_length;
        if (suffix_start < visible_length) {
            mvaddnstr(0, (int)suffix_start, title + suffix_start,
                      (int)(visible_length - suffix_start));
        }
    }
    attroff(A_BOLD);
}

static void draw_screen(struct sn_monitor *monitor,
                        const struct sn_network_info *network_info,
                        const struct sn_ui_flow_filter *filter,
                        const struct sn_flow **flows,
                        size_t flow_count,
                        size_t selected,
                        size_t scroll_start,
                        bool show_stats,
                        bool recording_active,
                        bool payload_inspection_active,
                        const char *capture_status,
                        const struct sn_monitor_rates *rates,
                        bool colors_enabled)
{
    char title[256] = "Sniffit NG | Network monitor";
    size_t local_address_start = SIZE_MAX;
    size_t local_address_length = 0U;
    uint8_t local_ipv4[4];
    bool have_local_ipv4 = network_info != NULL &&
        inet_pton(AF_INET, network_info->local_ipv4, local_ipv4) == 1;
    size_t title_length;
    size_t visible_rows;

    erase();
    if (COLS < 80 || LINES < 18) {
        mvaddstr(0, 0, "Sniffit NG needs a terminal at least 80 columns by 18 rows.");
        mvaddstr(2, 0, "Resize the terminal, or press q to quit.");
        refresh();
        return;
    }

    title_length = strlen(title);
    if (network_info != NULL && network_info->interface_name[0] != '\0') {
        if (network_info->local_ipv4[0] != '\0') {
            (void)snprintf(title + title_length, sizeof(title) - title_length,
                           " | %s ", network_info->interface_name);
            local_address_start = strlen(title);
            local_address_length = strlen(network_info->local_ipv4);
            title_length = local_address_start;
            (void)snprintf(title + title_length, sizeof(title) - title_length,
                           "%s", network_info->local_ipv4);
        } else {
            (void)snprintf(title + title_length, sizeof(title) - title_length,
                           " | %s", network_info->interface_name);
        }
        if (network_info->external_ipv4[0] != '\0') {
            title_length = strlen(title);
            (void)snprintf(title + title_length, sizeof(title) - title_length,
                           " (external %s)", network_info->external_ipv4);
        }
    }
    title_length = strlen(title);
    if (recording_active) {
        (void)snprintf(title + title_length, sizeof(title) - title_length,
                       " | RECORDING ACTIVE");
    }
    title_length = strlen(title);
    if (payload_inspection_active) {
        (void)snprintf(title + title_length, sizeof(title) - title_length,
                       " | PAYLOAD DISPLAY ENABLED");
    }
    draw_title_line(title, local_address_start, local_address_length,
                    colors_enabled);
    mvprintw(1, 0, "%-5s %-15s:%-5s -> %-15s:%-5s %s",
             "PROTO", "ENDPOINT A", "PORT", "ENDPOINT B", "PORT",
             "PACKETS A>B/B>A");
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
        bool priority_flow = sn_ui_flow_is_ssh_telnet(flow);
        bool endpoint_a_is_local = have_local_ipv4 &&
            memcmp(flow->endpoints[0].ipv4, local_ipv4, sizeof(local_ipv4)) == 0;
        bool endpoint_b_is_local = have_local_ipv4 &&
            memcmp(flow->endpoints[1].ipv4, local_ipv4, sizeof(local_ipv4)) == 0;
        bool selected_flow = flow_index == selected;
        bool apply_flow_colors = colors_enabled && !selected_flow;
        attr_t row_attributes = selected_flow ? A_REVERSE : A_NORMAL;
        attr_t session_attributes = row_attributes |
            (apply_flow_colors && priority_flow ?
             COLOR_PAIR(UI_COLOR_SSH_TELNET) : 0);

        (void)inet_ntop(AF_INET, flow->endpoints[0].ipv4,
                        endpoint_a, sizeof(endpoint_a));
        (void)inet_ntop(AF_INET, flow->endpoints[1].ipv4,
                        endpoint_b, sizeof(endpoint_b));
        attrset(session_attributes);
        mvprintw((int)row + 3, 0, "%-5s ", protocol_name(flow->protocol));
        attrset(row_attributes | (apply_flow_colors && endpoint_a_is_local ?
                 COLOR_PAIR(UI_COLOR_LOCAL_ADDRESS) :
             (apply_flow_colors && priority_flow ?
                  COLOR_PAIR(UI_COLOR_SSH_TELNET) : 0)));
        printw("%-15s", endpoint_a);
        attrset(session_attributes);
        printw(":%-5u -> ", flow->endpoints[0].port);
        attrset(row_attributes | (apply_flow_colors && endpoint_b_is_local ?
                 COLOR_PAIR(UI_COLOR_LOCAL_ADDRESS) :
             (apply_flow_colors && priority_flow ?
                  COLOR_PAIR(UI_COLOR_SSH_TELNET) : 0)));
        printw("%-15s", endpoint_b);
        attrset(session_attributes);
        printw(":%-5u %8llu/%-8llu",
               flow->endpoints[1].port,
               (unsigned long long)flow->packets[0],
               (unsigned long long)flow->packets[1]);
        attrset(A_NORMAL);
        clrtoeol();
    }
    if (visible_rows == 0U) {
        mvaddstr(3, 0, flow_count == 0U ? "No connections seen yet." :
                                          "No connections match these filters.");
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
            mvprintw(stats_row + 2, 0, "IGMP/sec: %llu  VRRP/sec: %llu",
                     (unsigned long long)rates->igmp_packets_per_second,
                     (unsigned long long)rates->vrrp_packets_per_second);
        } else {
            mvprintw(stats_row, 0, "Packet totals: IP %llu  TCP %llu  UDP %llu  ICMP %llu",
                     (unsigned long long)monitor->stats.ipv4_packets,
                     (unsigned long long)monitor->stats.tcp_packets,
                     (unsigned long long)monitor->stats.udp_packets,
                     (unsigned long long)monitor->stats.icmp_packets);
            mvprintw(stats_row + 1, 0, "Packet totals: IGMP %llu  VRRP %llu",
                     (unsigned long long)monitor->stats.igmp_packets,
                     (unsigned long long)monitor->stats.vrrp_packets);
            mvprintw(stats_row + 2, 0, "Byte totals: TCP %llu  UDP %llu",
                     (unsigned long long)monitor->stats.tcp_bytes,
                     (unsigned long long)monitor->stats.udp_bytes);
        }
        mvprintw(stats_row + 3, 0, "Truncated: %llu  Malformed: %llu  Unsupported: %llu  Dropped UI events: %llu",
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
        mvaddstr(LINES - 1, 0, " j/k move  1-4 filter  Enter details  n stats  r reset  q quit ");
    }
    clrtoeol();
    attroff(A_REVERSE);
    refresh();
}

static bool read_line(const char *prompt, char *buffer, size_t capacity,
                      int input_timeout_ms)
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
    wtimeout(stdscr, -1);
    int result = getnstr(buffer, (int)maximum);
    wtimeout(stdscr, input_timeout_ms);
    noecho();
    curs_set(0);
    return result != ERR;
}

static void set_ip_filter(const char *prompt, bool *enabled, uint8_t address[4],
                          int input_timeout_ms)
{
    char input[64] = {0};

    if (!read_line(prompt, input, sizeof(input), input_timeout_ms)) {
        return;
    }
    if (strcasecmp(input, "all") == 0 || input[0] == '\0') {
        *enabled = false;
    } else if (inet_pton(AF_INET, input, address) == 1) {
        *enabled = true;
    }
}

static void set_port_filter(const char *prompt, bool *enabled, uint16_t *port,
                            int input_timeout_ms)
{
    char input[32] = {0};
    char *end = NULL;
    unsigned long value;

    if (!read_line(prompt, input, sizeof(input), input_timeout_ms)) {
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

    if (sample->payload_truncated) {
        (void)wprintw(history,
                      "ICMP Echo %s %s id=%u seq=%u (%zu of %zu bytes shown; truncated)\n",
                      type_name, direction, sample->identifier, sample->sequence,
                      sample->payload_length, sample->original_payload_length);
    } else {
        (void)wprintw(history, "ICMP Echo %s %s id=%u seq=%u (%zu bytes)\n",
                      type_name, direction, sample->identifier, sample->sequence,
                      sample->payload_length);
    }
    if (sample->payload_length == 0U) {
        (void)waddstr(history, "  (empty payload)\n");
    }
    for (size_t offset = 0U; offset < sample->payload_length;
         offset += SN_ICMP_DISPLAY_ROW_BYTES) {
        char line[SN_ICMP_DISPLAY_LINE_CAPACITY];
        size_t row_length = sample->payload_length - offset;

        if (row_length > SN_ICMP_DISPLAY_ROW_BYTES) {
            row_length = SN_ICMP_DISPLAY_ROW_BYTES;
        }
        if (sn_icmp_format_payload_display_row(offset, sample->payload + offset,
                                              row_length, line, sizeof(line)) == 0U) {
            break;
        }
        (void)wprintw(history, "  %s\n", line);
    }
    (void)waddch(history, '\n');
}

static void append_decode_record(WINDOW *history,
                                 const struct sn_packet_decode_record *record)
{
    if (record != NULL && record->text[0] != '\0') {
        (void)wprintw(history, "%s\n\n", record->text);
    }
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
                                   size_t *seen_decode_count,
                                   size_t *seen_decode_next,
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

        if (updated->decode_history_count > 0U &&
            (updated->decode_history_count != *seen_decode_count ||
             updated->decode_history_next != *seen_decode_next)) {
            const struct sn_packet_decode_record *record =
                sn_flow_decode_history_at(updated, updated->decode_history_count - 1U);
            append_decode_record(history, record);
            *seen_decode_count = updated->decode_history_count;
            *seen_decode_next = updated->decode_history_next;
            changed = true;
        }

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
                                 size_t *seen_decode_count,
                                 size_t *seen_decode_next,
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
        *seen_decode_count = flow->decode_history_count;
        *seen_decode_next = flow->decode_history_next;
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
    for (size_t index = 0U; index < flow->decode_history_count; ++index) {
        append_decode_record(history, sn_flow_decode_history_at(flow, index));
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
    } else if (flow->decode_history_count == 0U) {
        (void)waddstr(history,
                       "No protocol summary is available for this flow.\n"
                       "Payload bytes are hidden.\n");
    }
    refresh_detail_panel(panel, history, panel_x);
}

static void redraw_detail_background(struct ui_detail_context *context,
                                     const struct sn_flow *preferred_flow)
{
    size_t visible_rows = LINES > (context->show_stats ? 14 : 5) ?
        (size_t)(LINES - (context->show_stats ? 14 : 5)) : 1U;

    context->flow_count = collect_flows(context->monitor, context->filter,
                                        context->flows);
    if (context->flow_count == 0U) {
        return;
    }
    if (preferred_flow != NULL) {
        for (size_t index = 0U; index < context->flow_count; ++index) {
            if (same_flow_identity(context->flows[index], preferred_flow)) {
                *context->selected = index;
                break;
            }
        }
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
    draw_screen(context->monitor, context->network_info, context->filter, context->flows,
                context->flow_count, *context->selected, *context->scroll_start,
                context->show_stats, context->recording_active,
                context->payload_inspection_active, *context->capture_status,
                context->rates, context->colors_enabled);
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
    size_t seen_decode_count = 0U;
    size_t seen_decode_next = 0U;
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
                         &seen_count, &seen_next,
                         &seen_decode_count, &seen_decode_next, true);

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
                                           &seen_count, &seen_next,
                                           &seen_decode_count, &seen_decode_next, panel_x);
                    redraw_detail_background(context, &identity);
                    draw_detail_background(context);
                    if (context->flow_count > 0U) {
                        const struct sn_flow *highlighted =
                            context->flows[*context->selected];
                        bool focus_changed = !same_flow_identity(&identity, highlighted);

                        identity = *highlighted;
                        draw_detail_contents(context, &identity, panel, history, panel_x,
                                             &seen_count, &seen_next,
                                             &seen_decode_count, &seen_decode_next,
                                             focus_changed);
                        refresh_detail_panel(panel, history, panel_x);
                    }
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
                                 &seen_count, &seen_next,
                                 &seen_decode_count, &seen_decode_next, false);
            refresh_detail_panel(panel, history, panel_x);
            continue;
        }

        int direction = sn_ui_detail_navigation_direction(key, KEY_UP, KEY_DOWN);
        if (direction != 0) {
            redraw_detail_background(context, &identity);
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
                                         &seen_count, &seen_next,
                                         &seen_decode_count, &seen_decode_next, true);
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
          const struct sn_network_info *network_info,
              bool recording_active,
              bool payload_inspection_active,
              sn_ui_poll_callback poll_capture,
              void *poll_context)
{
    struct sn_ui_flow_filter filter = {0};
    const struct sn_flow *flows[SN_FLOW_TABLE_CAPACITY];
    size_t selected = 0U;
    size_t scroll_start = 0U;
    bool show_stats = false;
    bool capture_polling = poll_capture != NULL;
    const char *capture_status = NULL;
    struct sn_monitor_rate_sampler rate_sampler;
    struct sn_monitor_rates rates = {0};
    bool rates_ready = false;
    bool colors_enabled;
    int key;

    if (monitor == NULL || initscr() == NULL) {
        return 1;
    }
    cbreak();
    noecho();
    keypad(stdscr, true);
    wtimeout(stdscr, capture_polling ? 50 : -1);
    (void)curs_set(0);
    colors_enabled = initialize_ui_colors();
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
            .network_info = network_info,
            .filter = &filter,
            .flows = flows,
            .flow_count = flow_count,
            .selected = &selected,
            .scroll_start = &scroll_start,
            .show_stats = show_stats,
            .colors_enabled = colors_enabled,
            .recording_active = recording_active,
            .payload_inspection_active = payload_inspection_active,
            .capture_polling = &capture_polling,
            .capture_status = &capture_status,
            .rates = rates_ready ? &rates : (capture_polling ? &rates : NULL)
        };
        draw_screen(monitor, network_info, &filter, flows, flow_count, selected, scroll_start,
                show_stats, recording_active, payload_inspection_active,
            capture_status, detail_context.rates, colors_enabled);
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
                          &filter.source_ip_enabled, filter.source_ip,
                          capture_polling ? 50 : -1);
            selected = 0U;
            scroll_start = 0U;
            break;
        case '2':
        case KEY_F(2):
            set_ip_filter("Destination host (IPv4 or all): ",
                          &filter.destination_ip_enabled, filter.destination_ip,
                          capture_polling ? 50 : -1);
            selected = 0U;
            scroll_start = 0U;
            break;
        case '3':
        case KEY_F(3):
            set_port_filter("Source port (0 for all): ",
                            &filter.source_port_enabled, &filter.source_port,
                            capture_polling ? 50 : -1);
            selected = 0U;
            scroll_start = 0U;
            break;
        case '4':
        case KEY_F(4):
            set_port_filter("Destination port (0 for all): ",
                            &filter.destination_port_enabled, &filter.destination_port,
                            capture_polling ? 50 : -1);
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
