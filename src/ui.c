#include "sniffit_ng/ui.h"

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

static void show_details(const struct sn_flow *flow, bool payload_inspection_active)
{
    char endpoint_a[INET_ADDRSTRLEN] = "?";
    char endpoint_b[INET_ADDRSTRLEN] = "?";
    char payload_text[SN_FLOW_ICMP_SAMPLE_CAPACITY + 1U];
    int row = LINES / 2 - 3;

    (void)inet_ntop(AF_INET, flow->endpoints[0].ipv4,
                    endpoint_a, sizeof(endpoint_a));
    (void)inet_ntop(AF_INET, flow->endpoints[1].ipv4,
                    endpoint_b, sizeof(endpoint_b));
    erase();
    box(stdscr, 0, 0);
    mvprintw(row, 3, "%s %s:%u <-> %s:%u", protocol_name(flow->protocol),
             endpoint_a, flow->endpoints[0].port,
             endpoint_b, flow->endpoints[1].port);
    mvprintw(row + 2, 3, "Packets: %llu / %llu",
             (unsigned long long)flow->packets[0],
             (unsigned long long)flow->packets[1]);
    mvprintw(row + 3, 3, "Bytes:   %llu / %llu",
             (unsigned long long)flow->bytes[0],
             (unsigned long long)flow->bytes[1]);
    if (flow->protocol == 1U) {
        if (flow->has_icmp_echo_sample) {
            mvprintw(row + 5, 3, "ICMP Echo %s, id=%u, sequence=%u",
                     flow->icmp_type == 8U ? "request" : "reply",
                     flow->icmp_identifier, flow->icmp_sequence);
            if (payload_inspection_active) {
                for (size_t index = 0U; index < flow->icmp_payload_sample_length; ++index) {
                    unsigned char byte = flow->icmp_payload_sample[index];
                    payload_text[index] = isprint(byte) ? (char)byte : '.';
                }
                payload_text[flow->icmp_payload_sample_length] = '\0';
                mvprintw(row + 6, 3, "Payload sample (%zu bytes):",
                         flow->icmp_payload_sample_length);
                mvaddnstr(row + 7, 3, payload_text,
                          (int)flow->icmp_payload_sample_length);
            }
        } else if (payload_inspection_active) {
            mvaddstr(row + 5, 3, "No ICMP Echo payload sample retained yet.");
        } else {
            mvaddstr(row + 5, 3,
                     "Payload display is off; enable --inspect-payloads with an acknowledged config.");
        }
    }
    mvaddstr(LINES - 2, 3, "Press any key to return");
    refresh();
    (void)getch();
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
            capture_status = poll_capture(poll_context);
            if (capture_status != NULL) {
                capture_polling = false;
            }
        }
        flow_count = collect_flows(monitor, &filter, flows);
        if (selected >= flow_count && flow_count > 0U) {
            selected = flow_count - 1U;
        }
        size_t visible_rows = LINES > (show_stats ? 14 : 5) ?
            (size_t)(LINES - (show_stats ? 14 : 5)) : 1U;
        scroll_start = sn_ui_window_start(flow_count, selected,
                                          visible_rows, scroll_start);
        draw_screen(monitor, &filter, flows, flow_count, selected, scroll_start, show_stats,
                payload_logging_active, payload_inspection_active, capture_status,
                rates_ready ? &rates : (capture_polling ? &rates : NULL));
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
                show_details(flows[selected], payload_inspection_active);
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
