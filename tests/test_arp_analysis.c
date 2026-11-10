#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/arp_analysis.h"
#include "sniffit_ng/arp_config.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct sn_arp_observation make(uint8_t operation, uint8_t sender_host, uint8_t sender_mac,
                                      const uint8_t target[4], long seconds)
{
    struct sn_arp_observation observation = {0};

    observation.packet.operation = operation;
    observation.packet.sender_ipv4[0] = 192U;
    observation.packet.sender_ipv4[1] = 168U;
    observation.packet.sender_ipv4[2] = 1U;
    observation.packet.sender_ipv4[3] = sender_host;
    observation.packet.sender_mac[5] = sender_mac;
    memcpy(observation.packet.target_ipv4, target, 4U);
    observation.timestamp.tv_sec = seconds;
    return observation;
}

static void local_target(uint8_t out[4], unsigned int host)
{
    out[0] = 192U;
    out[1] = 168U;
    out[2] = 1U;
    out[3] = (uint8_t)host;
}

static struct sn_arp_analysis *fresh(const struct sn_arp_analysis_config *config)
{
    struct sn_arp_analysis *analysis = calloc(1U, sizeof(*analysis));

    assert(analysis != NULL);
    sn_arp_analysis_init(analysis, config);
    return analysis;
}

static const struct sn_arp_host *host_at(const struct sn_arp_analysis *analysis, uint8_t last)
{
    for (size_t index = 0U; index < SN_ARP_HOST_CAPACITY; ++index) {
        if (analysis->hosts[index].active && analysis->hosts[index].ip[3] == last) {
            return &analysis->hosts[index];
        }
    }
    return NULL;
}

static void test_talkative_boundary_and_window(void)
{
    struct sn_arp_analysis_config config;
    struct sn_arp_analysis *analysis;
    struct sn_arp_observation observation;
    uint8_t target[4];

    sn_arp_analysis_config_init(&config);
    config.talkative_requests_per_minute = 5U;
    config.sweep_targets = 0U;
    config.range_poll_min_targets = 0U;
    analysis = fresh(&config);
    local_target(target, 50U);
    for (long second = 0; second < 4; ++second) {
        observation = make(1U, 7U, 1U, target, 100 + second);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 7U)->alerts == 0U);
    observation = make(1U, 7U, 1U, target, 104);
    sn_arp_analysis_observe(analysis, &observation);
    assert((host_at(analysis, 7U)->alerts & SN_ARP_ALERT_TALKATIVE) != 0U);
    assert(host_at(analysis, 7U)->peak_requests_per_minute == 5U);
    free(analysis);

    /* One request every 20 seconds never reaches 5 in a 60-second window. */
    analysis = fresh(&config);
    for (long index = 0; index < 100; ++index) {
        observation = make(1U, 8U, 1U, target, 1000 + index * 20);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 8U)->alerts == 0U);
    assert(host_at(analysis, 8U)->requests == 100U);
    free(analysis);
}

static void test_sweep_boundary_duplicates_and_window(void)
{
    struct sn_arp_analysis_config config;
    struct sn_arp_analysis *analysis;
    struct sn_arp_observation observation;
    uint8_t target[4];

    sn_arp_analysis_config_init(&config);
    config.sweep_targets = 10U;
    config.sweep_window_seconds = 60U;
    config.talkative_requests_per_minute = 0U;
    config.range_poll_min_targets = 0U;
    analysis = fresh(&config);
    for (unsigned int host = 1U; host <= 9U; ++host) {
        local_target(target, host);
        observation = make(1U, 3U, 1U, target, 200);
        sn_arp_analysis_observe(analysis, &observation);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 3U)->alerts == 0U);
    assert(host_at(analysis, 3U)->peak_sweep_targets == 9U);
    local_target(target, 10U);
    observation = make(1U, 3U, 1U, target, 230);
    sn_arp_analysis_observe(analysis, &observation);
    assert((host_at(analysis, 3U)->alerts & SN_ARP_ALERT_SWEEP) != 0U);
    assert(host_at(analysis, 3U)->sweeps_detected == 1U);
    free(analysis);

    /* Targets spread across windows longer than 60 s are not a sweep. */
    analysis = fresh(&config);
    for (unsigned int host = 1U; host <= 30U; ++host) {
        local_target(target, host);
        observation = make(1U, 4U, 1U, target, 500 + (long)host * 61);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 4U)->alerts == 0U);
    free(analysis);

    /* Two separate sweeps are counted separately. */
    analysis = fresh(&config);
    for (long round = 0; round < 2; ++round) {
        for (unsigned int host = 1U; host <= 12U; ++host) {
            local_target(target, host);
            observation = make(1U, 5U, 1U, target, 1000 + round * 1000);
            sn_arp_analysis_observe(analysis, &observation);
        }
    }
    assert(host_at(analysis, 5U)->sweeps_detected == 2U);
    free(analysis);
}

static void test_range_poller_needs_repeats_and_enough_targets(void)
{
    struct sn_arp_analysis_config config;
    struct sn_arp_analysis *analysis;
    struct sn_arp_observation observation;
    uint8_t target[4];

    sn_arp_analysis_config_init(&config);
    config.range_poll_repeat = 5U;
    config.range_poll_min_targets = 3U;
    config.talkative_requests_per_minute = 0U;
    config.sweep_targets = 0U;
    analysis = fresh(&config);
    for (long round = 0; round < 5; ++round) {
        for (unsigned int host = 10U; host < 12U; ++host) {
            local_target(target, host);
            observation = make(1U, 9U, 1U, target, 100 + round * 100);
            sn_arp_analysis_observe(analysis, &observation);
        }
    }
    assert(host_at(analysis, 9U)->alerts == 0U);
    local_target(target, 12U);
    for (long round = 0; round < 4; ++round) {
        observation = make(1U, 9U, 1U, target, 1000 + round);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 9U)->alerts == 0U);
    observation = make(1U, 9U, 1U, target, 2000);
    sn_arp_analysis_observe(analysis, &observation);
    assert((host_at(analysis, 9U)->alerts & SN_ARP_ALERT_RANGE_POLLER) != 0U);
    free(analysis);

    /* A burst of one-off targets cannot evict a repeated target from the bounded table. */
    analysis = fresh(&config);
    local_target(target, 200U);
    for (long index = 0; index < 4; ++index) {
        observation = make(1U, 11U, 1U, target, 100 + index);
        sn_arp_analysis_observe(analysis, &observation);
    }
    for (unsigned int host = 1U; host <= 200U; ++host) {
        local_target(target, host);
        observation = make(1U, 11U, 1U, target, 300);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 11U)->target_count == SN_ARP_TRACKED_TARGETS);
    free(analysis);
}

static void test_off_link_and_local_network(void)
{
    struct sn_arp_analysis_config config;
    struct sn_arp_analysis *analysis;
    struct sn_arp_observation observation;
    uint8_t outside[4] = {8U, 8U, 8U, 8U};
    uint8_t zero[4] = {0U, 0U, 0U, 0U};
    uint8_t target[4];

    sn_arp_analysis_config_init(&config);
    config.local_known = true;
    config.local_network[0] = 192U;
    config.local_network[1] = 168U;
    config.local_network[2] = 1U;
    config.local_prefix = 24U;
    config.off_link_min_requests = 3U;
    config.talkative_requests_per_minute = 0U;
    config.sweep_targets = 0U;
    config.range_poll_min_targets = 0U;
    analysis = fresh(&config);
    local_target(target, 200U);
    for (int index = 0; index < 10; ++index) {
        observation = make(1U, 6U, 1U, target, 100 + index);
        sn_arp_analysis_observe(analysis, &observation);
        observation = make(1U, 6U, 1U, zero, 100 + index);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 6U)->alerts == 0U);
    for (int index = 0; index < 2; ++index) {
        observation = make(1U, 6U, 1U, outside, 200 + index);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 6U)->alerts == 0U);
    observation = make(1U, 6U, 1U, outside, 300);
    sn_arp_analysis_observe(analysis, &observation);
    assert((host_at(analysis, 6U)->alerts & SN_ARP_ALERT_OFF_LINK) != 0U);
    free(analysis);

    /* Without a local network the detector stays inactive. */
    config.local_known = false;
    analysis = fresh(&config);
    for (int index = 0; index < 10; ++index) {
        observation = make(1U, 6U, 1U, outside, 100 + index);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 6U)->alerts == 0U);
    free(analysis);
}

static void test_mac_change_probes_and_replies(void)
{
    struct sn_arp_analysis *analysis = fresh(NULL);
    struct sn_arp_observation observation;
    uint8_t target[4];

    local_target(target, 1U);
    observation = make(1U, 20U, 1U, target, 100);
    sn_arp_analysis_observe(analysis, &observation);
    observation = make(2U, 20U, 1U, target, 101);
    sn_arp_analysis_observe(analysis, &observation);
    assert(host_at(analysis, 20U)->alerts == 0U);
    assert(host_at(analysis, 20U)->replies == 1U && host_at(analysis, 20U)->requests == 1U);
    observation = make(2U, 20U, 2U, target, 102);
    sn_arp_analysis_observe(analysis, &observation);
    assert((host_at(analysis, 20U)->alerts & SN_ARP_ALERT_MAC_CHANGE) != 0U);
    assert(host_at(analysis, 20U)->mac_count == 2U && host_at(analysis, 20U)->mac_changes == 1U);

    /* Sender 0.0.0.0 is an address probe and never becomes a host. */
    observation = make(1U, 0U, 3U, target, 103);
    observation.packet.sender_ipv4[0] = 0U;
    observation.packet.sender_ipv4[1] = 0U;
    observation.packet.sender_ipv4[2] = 0U;
    sn_arp_analysis_observe(analysis, &observation);
    assert(analysis->probes == 1U && sn_arp_analysis_host_count(analysis) == 1U);
    sn_arp_analysis_observe(analysis, NULL);
    sn_arp_analysis_observe(NULL, &observation);
    free(analysis);
}

static void test_baseline_sorting_eviction_and_text(void)
{
    struct sn_arp_analysis_config config;
    struct sn_arp_analysis *analysis;
    struct sn_arp_observation observation;
    const struct sn_arp_host *sorted[SN_ARP_HOST_CAPACITY];
    uint8_t target[4];
    char text[64];
    char tiny[6];

    sn_arp_analysis_config_init(&config);
    config.talkative_requests_per_minute = 3U;
    config.sweep_targets = 0U;
    config.range_poll_min_targets = 0U;
    config.baseline_ips[0][0] = 192U;
    config.baseline_ips[0][1] = 168U;
    config.baseline_ips[0][2] = 1U;
    config.baseline_ips[0][3] = 30U;
    config.baseline_count = 1U;
    analysis = fresh(&config);
    local_target(target, 1U);
    for (int index = 0; index < 3; ++index) {
        observation = make(1U, 30U, 1U, target, 100 + index);
        sn_arp_analysis_observe(analysis, &observation);
        observation = make(1U, 31U, 1U, target, 100 + index);
        sn_arp_analysis_observe(analysis, &observation);
    }
    observation = make(1U, 32U, 1U, target, 100);
    sn_arp_analysis_observe(analysis, &observation);
    for (int index = 0; index < 10; ++index) {
        observation = make(1U, 33U, 1U, target, 500 + index * 100);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(host_at(analysis, 30U)->baseline && host_at(analysis, 30U)->alerts != 0U);
    assert(sn_arp_analysis_sorted(analysis, sorted, SN_ARP_HOST_CAPACITY) == 4U);
    assert(sorted[0]->ip[3] == 31U);   /* unsuppressed alert first */
    assert(sorted[1]->ip[3] == 30U);   /* baseline alert after it */
    assert(sorted[2]->ip[3] == 33U);   /* quiet hosts by request count */
    assert(sorted[3]->ip[3] == 32U);
    assert(sn_arp_analysis_sorted(analysis, sorted, 2U) == 2U);
    assert(sn_arp_analysis_sorted(NULL, sorted, 2U) == 0U);
    free(analysis);

    analysis = fresh(NULL);
    for (unsigned int host = 0U; host < SN_ARP_HOST_CAPACITY + 1U; ++host) {
        observation = make(1U, 1U, 1U, target, 100 + (long)host);
        observation.packet.sender_ipv4[2] = (uint8_t)(host / 200U);
        observation.packet.sender_ipv4[3] = (uint8_t)(host % 200U + 1U);
        sn_arp_analysis_observe(analysis, &observation);
    }
    assert(sn_arp_analysis_host_count(analysis) == SN_ARP_HOST_CAPACITY);
    assert(analysis->evictions == 1U);
    free(analysis);

    assert(sn_arp_alerts_text(0U, text, sizeof(text)) && text[0] == '\0');
    assert(sn_arp_alerts_text(SN_ARP_ALERT_TALKATIVE | SN_ARP_ALERT_SWEEP, text, sizeof(text)));
    assert(strcmp(text, "talkative,sweep") == 0);
    assert(!sn_arp_alerts_text(SN_ARP_ALERT_RANGE_POLLER | SN_ARP_ALERT_MAC_CHANGE, tiny, sizeof(tiny)));
    assert(!sn_arp_alerts_text(1U, NULL, 0U));
}

static void write_config(const char *path, const char *text)
{
    FILE *stream = fopen(path, "w");

    assert(stream != NULL && fputs(text, stream) >= 0 && fclose(stream) == 0);
}

static void test_analysis_config(void)
{
    char template[] = "/tmp/sniffit-ng-arp-analysis-XXXXXX";
    char error[256];
    struct sn_arp_config config;
    int descriptor = mkstemp(template);

    assert(descriptor >= 0 && close(descriptor) == 0);
    write_config(template, "packet_logging = false\naddress_logging = false\n");
    assert(sn_arp_config_load(template, &config, error, sizeof(error)));
    assert(!config.analysis.local_known && config.analysis.sweep_targets == 100U);
    assert(config.analysis.talkative_requests_per_minute == 60U);

    write_config(template,
                 "packet_logging = false\naddress_logging = false\n"
                 "local_network = 192.168.1.0/24\n"
                 "baseline_ips = 192.168.1.101, 192.168.1.102\n"
                 "talkative_requests_per_minute = 90\nsweep_targets = 128\n"
                 "sweep_window_seconds = 30\nrange_poll_repeat = 500\n"
                 "range_poll_min_targets = 4\noff_link_min_requests = 5\n");
    assert(sn_arp_config_load(template, &config, error, sizeof(error)));
    assert(config.analysis.local_known && config.analysis.local_prefix == 24U);
    assert(config.analysis.local_network[2] == 1U && config.analysis.baseline_count == 2U);
    assert(config.analysis.baseline_ips[1][3] == 102U);
    assert(config.analysis.talkative_requests_per_minute == 90U);
    assert(config.analysis.sweep_targets == 128U && config.analysis.sweep_window_seconds == 30U);
    assert(config.analysis.range_poll_repeat == 500U && config.analysis.range_poll_min_targets == 4U);
    assert(config.analysis.off_link_min_requests == 5U);

    static const char *const bad[] = {
        "local_network = 192.168.1.0\n", "local_network = 192.168.1.0/33\n",
        "local_network = 300.1.1.0/24\n", "local_network = /24\n",
        "baseline_ips = 192.168.1.1,nope\n", "baseline_ips = 192.168.1.1,\n",
        "sweep_targets = 513\n", "sweep_targets = 10\nsweep_window_seconds = 0\n",
        "talkative_requests_per_minute = -1\n", "sweep_targets = 5\nsweep_targets = 6\n",
        ("baseline_ips = 1.1.1.1,1.1.1.2,1.1.1.3,1.1.1.4,1.1.1.5,1.1.1.6,1.1.1.7,1.1.1.8,"
         "1.1.1.9,1.1.1.10,1.1.1.11,1.1.1.12,1.1.1.13,1.1.1.14,1.1.1.15,1.1.1.16,1.1.1.17\n")
    };

    for (size_t index = 0U; index < sizeof(bad) / sizeof(bad[0]); ++index) {
        char contents[512];

        assert(snprintf(contents, sizeof(contents),
                        "packet_logging = false\naddress_logging = false\n%s", bad[index]) > 0);
        write_config(template, contents);
        assert(!sn_arp_config_load(template, &config, error, sizeof(error)));
    }
    write_config(template, "packet_logging = false\naddress_logging = false\nlocal_network =\n");
    assert(sn_arp_config_load(template, &config, error, sizeof(error)) && !config.analysis.local_known);
    assert(unlink(template) == 0);
}

int main(void)
{
    test_talkative_boundary_and_window();
    test_sweep_boundary_duplicates_and_window();
    test_range_poller_needs_repeats_and_enough_targets();
    test_off_link_and_local_network();
    test_mac_change_probes_and_replies();
    test_baseline_sorting_eviction_and_text();
    test_analysis_config();
    puts("arp analysis tests passed");
    return 0;
}
