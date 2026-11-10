#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/arp_ui.h"

#include <curses.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define COLOR_ALERT 1
#define COLOR_BASELINE 2
#define PANEL_MIN_TIMELINE_ROWS 3
#define CTRL_L 12

struct view {
    const struct sn_arp_analysis *analysis;
    const struct sn_arp_state *state;
    const struct sn_arp_view_totals *totals;
    const struct sn_arp_host *hosts[SN_ARP_HOST_CAPACITY];
    size_t host_count;
    size_t selected;
    size_t first;
    bool show_stats;
    bool colors;
    size_t panel_scroll;
    size_t panel_page;
    size_t panel_max_scroll;
};

static void put_line(WINDOW *window, int row, int column, int width, const char *text,
                     attr_t attributes)
{
    if (row < 0 || width <= 0) {
        return;
    }
    (void)wattrset(window, attributes);
    (void)mvwaddnstr(window, row, column, text, width);
    (void)wattrset(window, A_NORMAL);
}

static attr_t host_attributes(const struct view *view, const struct sn_arp_host *host)
{
    attr_t attributes = A_NORMAL;

    if (host->alerts != 0U) {
        if (view->colors) {
            attributes = (attr_t)COLOR_PAIR(host->baseline ? COLOR_BASELINE : COLOR_ALERT);
        }
        attributes |= host->baseline ? A_DIM : A_BOLD;
    }
    return attributes;
}

static void keep_selection_visible(struct view *view, int visible_rows)
{
    size_t rows = visible_rows > 0 ? (size_t)visible_rows : 1U;

    if (view->selected < view->first) {
        view->first = view->selected;
    } else if (view->selected >= view->first + rows) {
        view->first = view->selected + 1U - rows;
    }
}

static void draw_background(const struct view *view, const struct sn_arp_view_layout *layout)
{
    char text[SN_ARP_VIEW_LINE];
    char stats[SN_ARP_VIEW_STATS_LINES][SN_ARP_VIEW_LINE];
    size_t alerting = 0U;
    size_t rows;

    (void)werase(stdscr);
    if (layout->too_small) {
        put_line(stdscr, 0, 0, COLS, "Terminal too small: need at least 80x18. Press q to quit.",
                 A_NORMAL);
        (void)wnoutrefresh(stdscr);
        return;
    }
    for (size_t index = 0U; index < view->host_count; ++index) {
        alerting += view->hosts[index]->alerts != 0U && !view->hosts[index]->baseline ? 1U : 0U;
    }
    (void)snprintf(text, sizeof(text), "arpwatch-ng-tui  %s  ARP packets %" PRIu64
                   "  hosts %zu  alerting %zu",
                   view->totals->source != NULL ? view->totals->source : "-",
                   view->totals->arp_packets, view->host_count, alerting);
    put_line(stdscr, 0, 0, COLS, text, A_BOLD);
    sn_arp_view_header(text, sizeof(text));
    put_line(stdscr, 1, 0, COLS, text, A_NORMAL);
    (void)mvwhline(stdscr, 2, 0, ACS_HLINE, COLS);

    rows = (size_t)layout->visible_rows;
    for (size_t row = 0U; row < rows && view->first + row < view->host_count; ++row) {
        const struct sn_arp_host *host = view->hosts[view->first + row];
        attr_t attributes = host_attributes(view, host);

        if (view->first + row == view->selected) {
            attributes |= A_REVERSE;
        }
        sn_arp_view_host_row(host, text, sizeof(text));
        put_line(stdscr, layout->first_row + (int)row, 0, COLS, text, attributes);
    }
    if (view->host_count == 0U) {
        put_line(stdscr, layout->first_row, 0, COLS, "No ARP hosts observed.", A_DIM);
    }
    if (view->show_stats) {
        size_t count = sn_arp_view_stats(view->analysis, view->totals, stats,
                                         SN_ARP_VIEW_STATS_LINES);

        (void)mvwhline(stdscr, layout->stats_row - 1, 0, ACS_HLINE, COLS);
        for (size_t index = 0U; index < count; ++index) {
            put_line(stdscr, layout->stats_row + (int)index, 0, COLS, stats[index], A_NORMAL);
        }
    }
    put_line(stdscr, LINES - 1, 0, COLS,
             " j/k move  Enter details  n stats  g/G ends  q quit  (! alert  ~ baseline) ",
             A_REVERSE);
    (void)wnoutrefresh(stdscr);
}

/* Fixed header (title and facts), then a timeline that PgUp/PgDn/Home/End scroll. */
static void draw_panel(WINDOW *panel, struct view *view, const struct sn_arp_view_layout *layout)
{
    char detail[SN_ARP_VIEW_DETAIL_LINES][SN_ARP_VIEW_LINE];
    const struct sn_arp_observation *packets[SN_ARP_HISTORY_CAPACITY];
    const struct sn_arp_host *host = view->hosts[view->selected];
    char text[SN_ARP_VIEW_LINE];
    int width = layout->panel_width - 4;
    int last_row = LINES - 4;
    int row = 1;
    int budget;
    int area;
    size_t count;
    size_t packet_count;

    (void)werase(panel);
    (void)box(panel, 0, 0);
    (void)snprintf(text, sizeof(text), "ARP host %u.%u.%u.%u%s", host->ip[0], host->ip[1],
                   host->ip[2], host->ip[3], host->baseline ? " | BASELINE" : "");
    put_line(panel, row++, 2, width, text, A_BOLD);

    budget = last_row - row - 1 - PANEL_MIN_TIMELINE_ROWS;
    if (budget < 0) {
        budget = 0;
    }
    count = sn_arp_view_detail(host, detail,
                               (size_t)budget < SN_ARP_VIEW_DETAIL_LINES ? (size_t)budget
                                                                         : SN_ARP_VIEW_DETAIL_LINES);
    for (size_t index = 0U; index < count; ++index) {
        put_line(panel, row++, 2, width, detail[index], A_NORMAL);
    }

    area = last_row - (row + 1) + 1;
    if (area < 1) {
        area = 1;
    }
    packet_count = sn_arp_view_host_packets(view->state, host->ip, packets, SN_ARP_HISTORY_CAPACITY);
    view->panel_scroll = sn_arp_view_clamp_scroll(packet_count, (size_t)area, view->panel_scroll);
    view->panel_page = area > 1 ? (size_t)area - 1U : 1U;
    view->panel_max_scroll = packet_count > (size_t)area ? packet_count - (size_t)area : 0U;
    if (packet_count > (size_t)area) {
        size_t last = view->panel_scroll + (size_t)area;

        (void)snprintf(text, sizeof(text), "Queries and responses (newest first) %zu-%zu/%zu",
                       view->panel_scroll + 1U, last < packet_count ? last : packet_count,
                       packet_count);
    } else {
        (void)snprintf(text, sizeof(text), "Queries and responses (newest first)");
    }
    put_line(panel, row++, 2, width, text, A_BOLD);
    if (packet_count == 0U) {
        put_line(panel, row, 2, width, "No recent packets retained for this host.", A_DIM);
    }
    for (size_t index = view->panel_scroll;
         index < packet_count && row <= last_row; ++index) {
        sn_arp_view_observation(packets[index], text, sizeof(text));
        put_line(panel, row++, 2, width, text, A_NORMAL);
    }
    (void)sn_arp_alerts_text(host->alerts, text, sizeof(text));
    (void)mvwprintw(panel, LINES - 3, 2, "Alerts: %.*s", width > 9 ? width - 8 : 1,
                    text[0] != '\0' ? text : "none");
    put_line(panel, LINES - 2, 2, width, "PgUp/PgDn scroll  j/k host  n stats", A_DIM);
}

static void redraw(struct view *view, WINDOW *panel)
{
    struct sn_arp_view_layout layout = sn_arp_view_layout(LINES, COLS, view->show_stats);

    keep_selection_visible(view, layout.visible_rows);
    draw_background(view, &layout);
    if (panel != NULL && !layout.too_small && view->host_count > 0U) {
        draw_panel(panel, view, &layout);
        (void)wnoutrefresh(panel);
    }
    (void)doupdate();
}

static void move_selection(struct view *view, int direction)
{
    size_t before = view->selected;

    if (direction < 0 && view->selected > 0U) {
        --view->selected;
    } else if (direction > 0 && view->selected + 1U < view->host_count) {
        ++view->selected;
    }
    if (view->selected != before) {
        view->panel_scroll = 0U;
    }
}

/* Arrows and j/k keep choosing the host; PgUp/PgDn/Home/End scroll the panel; other keys close it. */
static void run_panel(struct view *view)
{
    struct sn_arp_view_layout layout = sn_arp_view_layout(LINES, COLS, view->show_stats);
    WINDOW *panel;
    int key;

    if (layout.too_small || view->host_count == 0U) {
        return;
    }
    panel = newwin(LINES, layout.panel_width, 0, layout.panel_x);
    if (panel == NULL) {
        return;
    }
    view->panel_scroll = 0U;
    redraw(view, panel);
    for (;;) {
        key = getch();
        if (key == KEY_RESIZE) {
            (void)resize_term(0, 0);
            layout = sn_arp_view_layout(LINES, COLS, view->show_stats);
            if (layout.too_small) {
                break;
            }
            (void)wresize(panel, LINES, layout.panel_width);
            (void)mvwin(panel, 0, layout.panel_x);
        } else if (key == 'n' || key == 'N') {
            view->show_stats = !view->show_stats;
        } else if (key == KEY_UP || key == 'k' || key == 'K') {
            move_selection(view, -1);
        } else if (key == KEY_DOWN || key == 'j' || key == 'J') {
            move_selection(view, 1);
        } else if (key == KEY_NPAGE) {
            view->panel_scroll += view->panel_page;
        } else if (key == KEY_PPAGE) {
            view->panel_scroll = view->panel_scroll > view->panel_page
                ? view->panel_scroll - view->panel_page : 0U;
        } else if (key == KEY_HOME) {
            view->panel_scroll = 0U;
        } else if (key == KEY_END) {
            view->panel_scroll = view->panel_max_scroll;
        } else if (key == CTRL_L) {
            (void)clearok(curscr, TRUE);
        } else if (key != ERR) {
            break;
        }
        redraw(view, panel);
    }
    (void)delwin(panel);
    (void)touchwin(stdscr);
}

int sn_arp_ui_run(const struct sn_arp_analysis *analysis, const struct sn_arp_state *state,
                  const struct sn_arp_view_totals *totals)
{
    struct view view = {0};
    struct sn_arp_view_totals empty = {0};
    int key;

    if (analysis == NULL || state == NULL) {
        return 1;
    }
    view.analysis = analysis;
    view.state = state;
    view.totals = totals != NULL ? totals : &empty;
    view.host_count = sn_arp_analysis_sorted(analysis, view.hosts, SN_ARP_HOST_CAPACITY);
    if (initscr() == NULL) {
        return 1;
    }
    (void)cbreak();
    (void)noecho();
    (void)keypad(stdscr, TRUE);
    (void)curs_set(0);
    if (has_colors()) {
        (void)start_color();
        (void)use_default_colors();
        (void)init_pair(COLOR_ALERT, COLOR_RED, -1);
        (void)init_pair(COLOR_BASELINE, COLOR_YELLOW, -1);
        view.colors = true;
    }
    for (;;) {
        struct sn_arp_view_layout layout = sn_arp_view_layout(LINES, COLS, view.show_stats);
        size_t page = layout.visible_rows > 1 ? (size_t)layout.visible_rows - 1U : 1U;

        redraw(&view, NULL);
        key = getch();
        if (key == 'q' || key == 'Q' || key == ERR) {
            break;
        }
        if (key == KEY_RESIZE) {
            (void)resize_term(0, 0);
        } else if (key == KEY_UP || key == 'k' || key == 'K') {
            move_selection(&view, -1);
        } else if (key == KEY_DOWN || key == 'j' || key == 'J') {
            move_selection(&view, 1);
        } else if (key == KEY_PPAGE) {
            view.selected = view.selected > page ? view.selected - page : 0U;
        } else if (key == KEY_NPAGE && view.host_count > 0U) {
            view.selected = view.selected + page < view.host_count ? view.selected + page
                                                                    : view.host_count - 1U;
        } else if (key == 'g' || key == KEY_HOME) {
            view.selected = 0U;
        } else if ((key == 'G' || key == KEY_END) && view.host_count > 0U) {
            view.selected = view.host_count - 1U;
        } else if (key == 'n' || key == 'N') {
            view.show_stats = !view.show_stats;
        } else if (key == CTRL_L) {
            (void)clearok(curscr, TRUE);
        } else if (key == '\n' || key == '\r' || key == KEY_ENTER) {
            run_panel(&view);
        }
    }
    (void)endwin();
    return 0;
}
