#ifndef SNIFFIT_NG_ARP_VIEW_H
#define SNIFFIT_NG_ARP_VIEW_H

#include "sniffit_ng/arp_analysis.h"

#define SN_ARP_VIEW_LINE 160U
#define SN_ARP_VIEW_DETAIL_LINES 16U
#define SN_ARP_VIEW_STATS_LINES 4U
#define SN_ARP_VIEW_MIN_COLUMNS 80
#define SN_ARP_VIEW_MIN_ROWS 18

/* Same geometry as sniffit-ng: list rows shrink when statistics show at the bottom, and the
 * detail panel overlays the right 60% of the screen at full height. The statistics block
 * gets one extra row so its divider never covers a host row. */
struct sn_arp_view_layout {
    bool too_small;
    int first_row;
    int visible_rows;
    int stats_row;
    int panel_x;
    int panel_width;
};

struct sn_arp_view_totals {
    const char *source;
    bool local_ipv4_known;
    uint8_t local_ipv4[4];
    uint64_t arp_packets;
    uint64_t decoded;
    uint64_t truncated;
    uint64_t malformed;
    uint64_t unsupported;
    uint64_t non_arp;
    uint64_t unclassified;
};

struct sn_arp_view_layout sn_arp_view_layout(int lines, int columns, bool show_stats);

/* Clamps a scroll offset so the last page is the furthest a list can scroll. */
size_t sn_arp_view_clamp_scroll(size_t item_count, size_t visible, size_t scroll);

/* Fills SN_ARP_VIEW_STATS_LINES lines of totals; returns the number written. */
size_t sn_arp_view_stats(const struct sn_arp_analysis *analysis,
                         const struct sn_arp_view_totals *totals,
                         char lines[][SN_ARP_VIEW_LINE], size_t max_lines);

/* Pure text formatting for the ARP views; no curses dependency. Output is always terminated. */
void sn_arp_view_header(char *output, size_t capacity);

/* A leading '!' marks unsuppressed alerts and '~' alerts on baseline hosts. */
void sn_arp_view_host_row(const struct sn_arp_host *host, char *output, size_t capacity);

/* "HH:MM:SSZ who-has T tell S" or "HH:MM:SSZ S is-at MAC", in UTC; short enough for the panel. */
void sn_arp_view_observation(const struct sn_arp_observation *observation,
                             char *output, size_t capacity);

/* Newest first; includes packets the host sent or was asked about. Returns the count. */
size_t sn_arp_view_host_packets(const struct sn_arp_state *state, const uint8_t ip[4],
                                const struct sn_arp_observation **observations,
                                size_t capacity);

size_t sn_arp_view_detail(const struct sn_arp_host *host,
                          char lines[][SN_ARP_VIEW_LINE], size_t max_lines);

#endif
