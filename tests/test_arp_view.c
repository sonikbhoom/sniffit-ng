#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/arp_view.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct sn_arp_observation make(uint8_t operation, const uint8_t sender[4],
                                      const uint8_t target[4], long seconds)
{
    struct sn_arp_observation observation = {0};

    observation.packet.operation = operation;
    memcpy(observation.packet.sender_ipv4, sender, 4U);
    memcpy(observation.packet.target_ipv4, target, 4U);
    observation.packet.sender_mac[0] = 0x02U;
    observation.packet.sender_mac[5] = 0xabU;
    observation.timestamp.tv_sec = seconds;
    return observation;
}

static void test_row_header_and_markers(void)
{
    struct sn_arp_host host = {.active = true, .ip = {192U, 168U, 1U, 101U}, .requests = 1234U,
                               .replies = 5U, .peak_requests_per_minute = 99U,
                               .peak_sweep_targets = 33U};
    char line[SN_ARP_VIEW_LINE];
    char tiny[8];

    sn_arp_view_header(line, sizeof(line));
    assert(strstr(line, "HOST") != NULL && strstr(line, "REQUESTS") != NULL);
    assert(strstr(line, "SWEEPTGT") != NULL && strstr(line, "ALERTS") != NULL);

    sn_arp_view_host_row(&host, line, sizeof(line));
    /* marker, space, IP padded to 15, then right-aligned columns of width 9, 8, 7 and 9. */
    assert(strcmp(line, "  192.168.1.101" "        " "1234" "        " "5" "      " "99"
                       "        " "33" "  ") == 0);
    host.alerts = SN_ARP_ALERT_TALKATIVE | SN_ARP_ALERT_RANGE_POLLER;
    sn_arp_view_host_row(&host, line, sizeof(line));
    assert(line[0] == '!' && strstr(line, "talkative,range-poller") != NULL);
    host.baseline = true;
    sn_arp_view_host_row(&host, line, sizeof(line));
    assert(line[0] == '~');

    sn_arp_view_host_row(&host, tiny, sizeof(tiny));
    assert(strlen(tiny) < sizeof(tiny));
    sn_arp_view_host_row(NULL, line, sizeof(line));
    assert(line[0] == '\0');
    sn_arp_view_host_row(&host, NULL, 0U);
    sn_arp_view_header(NULL, 0U);
}

static void test_observation_text(void)
{
    const uint8_t sender[4] = {192U, 168U, 1U, 101U};
    const uint8_t target[4] = {192U, 168U, 1U, 201U};
    struct sn_arp_observation request = make(1U, sender, target, 3661L);
    struct sn_arp_observation reply = make(2U, target, sender, 3662L);
    char line[SN_ARP_VIEW_LINE];

    sn_arp_view_observation(&request, line, sizeof(line));
    assert(strcmp(line, "01:01:01Z who-has 192.168.1.201 tell 192.168.1.101") == 0);
    sn_arp_view_observation(&reply, line, sizeof(line));
    assert(strcmp(line, "01:01:02Z 192.168.1.201 is-at 02:00:00:00:00:ab") == 0);
    request.timestamp.tv_sec = -1;
    sn_arp_view_observation(&request, line, sizeof(line));
    assert(strncmp(line, "--:--:--Z", 9U) == 0);
    sn_arp_view_observation(NULL, line, sizeof(line));
    assert(line[0] == '\0');
}

static void test_host_packets_newest_first(void)
{
    struct sn_arp_state *state = calloc(1U, sizeof(*state));
    const uint8_t first[4] = {192U, 168U, 1U, 1U};
    const uint8_t second[4] = {192U, 168U, 1U, 2U};
    const uint8_t third[4] = {192U, 168U, 1U, 3U};
    const struct sn_arp_observation *found[8];
    struct sn_arp_observation observation;
    struct sn_capture_packet packet;
    uint8_t frame[42] = {[12] = 8U, [13] = 6U, [15] = 1U, [16] = 8U, [18] = 6U, [19] = 4U, [21] = 1U};
    const uint8_t *pairs[4][2] = {{first, second}, {second, third}, {third, first}, {second, first}};

    assert(state != NULL);
    sn_arp_state_init(state);
    for (long index = 0; index < 4; ++index) {
        memcpy(frame + 28, pairs[index][0], 4U);
        memcpy(frame + 38, pairs[index][1], 4U);
        packet = (struct sn_capture_packet){.data = frame, .captured_length = sizeof(frame),
                                            .wire_length = sizeof(frame),
                                            .link_type = SN_PACKET_LINK_ETHERNET,
                                            .timestamp = {.tv_sec = 100 + index}};
        assert(sn_arp_state_process(state, &packet) == SN_PACKET_OK);
    }
    assert(sn_arp_view_host_packets(state, first, found, 8U) == 3U);
    assert(found[0]->timestamp.tv_sec == 103L && found[1]->timestamp.tv_sec == 102L);
    assert(found[2]->timestamp.tv_sec == 100L);
    assert(sn_arp_view_host_packets(state, first, found, 2U) == 2U);
    assert(sn_arp_view_host_packets(state, third, found, 8U) == 2U);
    assert(sn_arp_view_host_packets(NULL, first, found, 8U) == 0U);
    (void)observation;
    free(state);
}

static void test_detail_lines(void)
{
    struct sn_arp_host host = {.active = true, .baseline = true, .ip = {192U, 168U, 1U, 101U},
                               .mac_count = 1U, .requests = 50U, .first_seen = 3600,
                               .last_seen = 7200, .peak_requests_per_minute = 9U,
                               .alerts = SN_ARP_ALERT_RANGE_POLLER | SN_ARP_ALERT_OFF_LINK,
                               .target_count = 4U};
    char lines[SN_ARP_VIEW_DETAIL_LINES][SN_ARP_VIEW_LINE];
    size_t count;
    bool saw_most_asked = false;
    bool saw_range = false;
    bool saw_baseline = false;

    for (size_t index = 0U; index < 4U; ++index) {
        host.targets[index].ip[0] = 192U;
        host.targets[index].ip[1] = 168U;
        host.targets[index].ip[2] = 1U;
        host.targets[index].ip[3] = (uint8_t)(210U + index);
        host.targets[index].count = 10U * (index + 1U);
    }
    count = sn_arp_view_detail(&host, lines, SN_ARP_VIEW_DETAIL_LINES);
    assert(count >= 8U && count <= SN_ARP_VIEW_DETAIL_LINES);
    assert(strcmp(lines[0], "seen 1970-01-01 01:00:00Z to 1970-01-01 02:00:00Z") == 0);
    for (size_t index = 0U; index < count; ++index) {
        saw_most_asked = saw_most_asked || strcmp(lines[index], "asked 40x  192.168.1.213") == 0;
        saw_range = saw_range || strstr(lines[index], "range-poller:") != NULL;
        saw_baseline = saw_baseline || strstr(lines[index], "baseline:") != NULL;
        assert(strlen(lines[index]) < SN_ARP_VIEW_LINE);
    }
    assert(saw_most_asked && saw_range && saw_baseline);
    assert(strcmp(lines[4], "asked 40x  192.168.1.213") == 0);
    assert(strcmp(lines[5], "asked 30x  192.168.1.212") == 0);
    assert(strcmp(lines[6], "asked 20x  192.168.1.211") == 0);
    assert(sn_arp_view_detail(&host, lines, 2U) == 2U);
    assert(sn_arp_view_detail(NULL, lines, 2U) == 0U);
    assert(sn_arp_view_detail(&host, NULL, 2U) == 0U);
}

static void test_layout_matches_main_app_geometry(void)
{
    struct sn_arp_view_layout layout = sn_arp_view_layout(24, 100, false);

    /* Detail panel: right 60% (starts at 2/5 of the width), full height. */
    assert(!layout.too_small && layout.first_row == 3 && layout.visible_rows == 19);
    assert(layout.panel_x == 40 && layout.panel_width == 60);
    layout = sn_arp_view_layout(24, 100, true);
    /* Statistics at the bottom: the host list shrinks and the block sits above the footer. */
    assert(layout.visible_rows == 9 && layout.stats_row == 13);
    assert(layout.first_row + layout.visible_rows <= layout.stats_row - 1);
    assert(layout.stats_row + (int)SN_ARP_VIEW_STATS_LINES <= 24 - 1);
    layout = sn_arp_view_layout(18, 80, false);
    assert(!layout.too_small && layout.panel_x == 32 && layout.panel_width == 48);
    assert(sn_arp_view_layout(17, 80, false).too_small);
    assert(sn_arp_view_layout(18, 79, false).too_small);
    layout = sn_arp_view_layout(18, 80, true);
    assert(layout.visible_rows >= 1);
    assert(layout.first_row + layout.visible_rows <= layout.stats_row - 1 + 1);
}

static void test_statistics_lines(void)
{
    struct sn_arp_analysis *analysis = calloc(1U, sizeof(*analysis));
    struct sn_arp_view_totals totals = {.arp_packets = 10U, .decoded = 8U, .truncated = 1U,
                                        .malformed = 2U, .unsupported = 3U, .non_arp = 4U,
                                        .unclassified = 5U};
    char lines[SN_ARP_VIEW_STATS_LINES][SN_ARP_VIEW_LINE];

    assert(analysis != NULL);
    sn_arp_analysis_init(analysis, NULL);
    analysis->hosts[0] = (struct sn_arp_host){.active = true, .requests = 7U, .replies = 2U,
                                              .alerts = SN_ARP_ALERT_SWEEP | SN_ARP_ALERT_TALKATIVE};
    analysis->hosts[1] = (struct sn_arp_host){.active = true, .baseline = true, .requests = 3U,
                                              .alerts = SN_ARP_ALERT_SWEEP};
    analysis->hosts[2] = (struct sn_arp_host){.active = true, .requests = 1U};
    analysis->probes = 6U;
    analysis->evictions = 9U;
    assert(sn_arp_view_stats(analysis, &totals, lines, SN_ARP_VIEW_STATS_LINES) == 4U);
    assert(strcmp(lines[0], "Packets: ARP 10  decoded 8  requests 11  replies 2  probes 6") == 0);
    assert(strcmp(lines[1], "Other: non-ARP frames 4  unclassified 5  Truncated: 1  Malformed: 2  Unsupported: 3") == 0);
    assert(strcmp(lines[2], "Hosts: 3  alerting 1  baseline alerts 1  evicted 9") == 0);
    assert(strstr(lines[3], "talkative 1  range-poller 0  sweep 2  off-link 0  mac-change 0") != NULL);
    assert(sn_arp_view_stats(analysis, &totals, lines, 2U) == 2U);
    assert(sn_arp_view_stats(NULL, &totals, lines, 2U) == 0U);
    assert(sn_arp_view_stats(analysis, NULL, lines, 2U) == 0U);
    free(analysis);
}

static void test_scroll_clamping(void)
{
    assert(sn_arp_view_clamp_scroll(10U, 3U, 0U) == 0U);
    assert(sn_arp_view_clamp_scroll(10U, 3U, 7U) == 7U);
    assert(sn_arp_view_clamp_scroll(10U, 3U, 8U) == 7U);
    assert(sn_arp_view_clamp_scroll(10U, 3U, SIZE_MAX) == 7U);
    assert(sn_arp_view_clamp_scroll(2U, 5U, 3U) == 0U);
    assert(sn_arp_view_clamp_scroll(5U, 5U, 1U) == 0U);
    assert(sn_arp_view_clamp_scroll(0U, 0U, 5U) == 0U);
    assert(sn_arp_view_clamp_scroll(10U, 0U, 4U) == 4U);
}

int main(void)
{
    test_row_header_and_markers();
    test_observation_text();
    test_host_packets_newest_first();
    test_detail_lines();
    test_layout_matches_main_app_geometry();
    test_statistics_lines();
    test_scroll_clamping();
    puts("arp view tests passed");
    return 0;
}
