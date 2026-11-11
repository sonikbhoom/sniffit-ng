#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/arp.h"
#include "sniffit_ng/arp_replay.h"
#include "sniffit_ng/capture.h"
#include "test_temp.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8U);
    bytes[1] = (uint8_t)value;
}

static size_t make_frame(uint8_t *frame, int dlt, unsigned int tag_count,
                         uint16_t network_protocol)
{
    size_t header_length = dlt == DLT_EN10MB ? 14U : 16U;
    size_t protocol_offset = dlt == DLT_EN10MB ? 12U : 14U;
    size_t payload_offset = header_length;

    memset(frame, 0, 96U);
    if (tag_count == 0U) {
        write_be16(frame + protocol_offset, network_protocol);
    } else {
        write_be16(frame + protocol_offset, tag_count > 1U ? 0x88a8U : 0x8100U);
        for (unsigned int index = 0U; index < tag_count; ++index) {
            uint16_t next_protocol = index + 1U == tag_count
                ? network_protocol : 0x8100U;

            write_be16(frame + payload_offset + 2U, next_protocol);
            payload_offset += 4U;
        }
    }
    if (network_protocol == 0x0806U) {
        write_be16(frame + payload_offset, 1U);
        write_be16(frame + payload_offset + 2U, 0x0800U);
        frame[payload_offset + 4U] = 6U;
        frame[payload_offset + 5U] = 4U;
        write_be16(frame + payload_offset + 6U, 1U);
        return payload_offset + 28U;
    }
    return payload_offset;
}

static void dump_frame(pcap_dumper_t *dumper, int dlt, unsigned int tag_count,
                       uint16_t network_protocol)
{
    uint8_t frame[96];
    size_t length = make_frame(frame, dlt, tag_count, network_protocol);
    struct pcap_pkthdr header = {
        .ts.tv_sec = 1,
        .caplen = (bpf_u_int32)length,
        .len = (bpf_u_int32)length
    };

    pcap_dump((u_char *)dumper, &header, frame);
}

static void create_test_pcap(char *path, size_t capacity, int dlt)
{
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    int descriptor;

    assert(sn_test_temp_template(path, capacity, "arp-filter"));
    descriptor = mkstemp(path);
    assert(descriptor >= 0 && close(descriptor) == 0);
    dead_capture = pcap_open_dead(dlt, 256);
    assert(dead_capture != NULL);
    dumper = pcap_dump_open(dead_capture, path);
    assert(dumper != NULL);
    dump_frame(dumper, dlt, 0U, 0x0800U);
    dump_frame(dumper, dlt, 0U, 0x0806U);
    dump_frame(dumper, dlt, 1U, 0x0806U);
    dump_frame(dumper, dlt, 2U, 0x0806U);
    dump_frame(dumper, dlt, 1U, 0x0800U);
    dump_frame(dumper, dlt, 3U, 0x0806U);
    assert(pcap_dump_flush(dumper) == 0);
    pcap_dump_close(dumper);
    pcap_close(dead_capture);
}

static void test_filter(int dlt, enum sn_packet_link_type link_type)
{
    struct sn_arp_config config;
    struct sn_arp_replay_stats stats;
    char path[4096];
    char error[256] = {0};
    struct sn_capture *capture;
    struct sn_capture_stats capture_stats = {0};
    const char *expression = sn_arp_bpf_filter_expression(link_type);

    assert(expression != NULL);
    create_test_pcap(path, sizeof(path), dlt);
    sn_arp_config_init(&config);
    config.rotation.packet_logging = false;
    config.rotation.address_logging = false;
    assert(sn_arp_replay_file(path, &config, &stats, error, sizeof(error)));
    assert(stats.state.decoded == 3U && stats.non_arp == 2U && stats.unclassified == 1U);
    sn_arp_replay_stats_release(&stats);

    capture = sn_capture_open_offline(path, error, sizeof(error));
    assert(capture != NULL);
    sn_arp_config_init(&config);
    assert(snprintf(config.log_directory, sizeof(config.log_directory), "%s", path) > 0);
    assert(!sn_arp_capture_process(capture, &config, &stats, NULL,
                                   error, sizeof(error)));
    assert(error[0] != '\0');
    sn_arp_replay_stats_release(&stats);
    assert(!sn_capture_get_stats(capture, &capture_stats, error, sizeof(error)));
    assert(strstr(error, "only available for live sources") != NULL);
    assert(sn_capture_set_filter(capture, expression, error, sizeof(error)));
    sn_arp_config_init(&config);
    config.rotation.packet_logging = false;
    config.rotation.address_logging = false;
    assert(sn_arp_capture_process(capture, &config, &stats, NULL,
                                  error, sizeof(error)));
    assert(stats.state.captured == 3U && stats.state.decoded == 3U);
    assert(stats.state.truncated == 0U && stats.state.malformed == 0U &&
           stats.state.unsupported == 0U);
    assert(stats.non_arp == 0U && stats.unclassified == 0U);
    sn_arp_replay_stats_release(&stats);
    sn_capture_close(capture);
    assert(unlink(path) == 0);
}

int main(void)
{
    assert(sn_arp_bpf_filter_expression((enum sn_packet_link_type)99) == NULL);
    test_filter(DLT_EN10MB, SN_PACKET_LINK_ETHERNET);
    test_filter(DLT_LINUX_SLL, SN_PACKET_LINK_LINUX_SLL);
    puts("ARP capture filter tests passed");
    return 0;
}