#include "sniffit_ng/monitor.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ETHERNET_LENGTH 14U
#define IPV4_LENGTH 20U
#define TCP_LENGTH 20U
#define FRAME_LENGTH (ETHERNET_LENGTH + IPV4_LENGTH + TCP_LENGTH)

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)(value & 0xffU);
}

static void make_tcp_frame(uint8_t *frame,
                           uint8_t source_last,
                           uint16_t source_port,
                           uint8_t destination_last,
                           uint16_t destination_port)
{
    uint8_t *ip = frame + ETHERNET_LENGTH;
    uint8_t *tcp = ip + IPV4_LENGTH;

    memset(frame, 0, FRAME_LENGTH);
    write_be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, IPV4_LENGTH + TCP_LENGTH);
    ip[8] = 64U;
    ip[9] = 6U;
    ip[12] = 192U;
    ip[14] = 2U;
    ip[15] = source_last;
    ip[16] = 192U;
    ip[18] = 2U;
    ip[19] = destination_last;
    write_be16(tcp, source_port);
    write_be16(tcp + 2U, destination_port);
    tcp[12] = 0x50U;
}

static size_t make_group_protocol_frame(uint8_t *frame, uint8_t protocol)
{
    uint8_t *ip = frame + ETHERNET_LENGTH;
    size_t transport_length = protocol == 2U ? 8U : 12U;
    uint8_t *transport = ip + IPV4_LENGTH;

    memset(frame, 0, FRAME_LENGTH);
    write_be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, (uint16_t)(IPV4_LENGTH + transport_length));
    ip[8] = 64U;
    ip[9] = protocol;
    ip[12] = 192U;
    ip[15] = 1U;
    ip[16] = 224U;
    ip[19] = 1U;
    if (protocol == 2U) {
        transport[0] = 0x16U;
        transport[4] = 239U;
        transport[5] = 1U;
        transport[6] = 2U;
        transport[7] = 3U;
    } else {
        transport[0] = 0x21U;
        transport[1] = 7U;
        transport[2] = 100U;
        transport[3] = 1U;
        transport[5] = 1U;
        transport[8] = 192U;
        transport[10] = 2U;
        transport[11] = 1U;
    }
    return ETHERNET_LENGTH + IPV4_LENGTH + transport_length;
}

static struct sn_capture_packet capture_packet(uint8_t *frame, size_t length, long seconds)
{
    struct sn_capture_packet packet = {0};

    packet.data = frame;
    packet.captured_length = length;
    packet.wire_length = length;
    packet.timestamp.tv_sec = seconds;
    packet.timestamp.tv_usec = 0;
    return packet;
}

static void test_capture_to_flow_events(void)
{
    struct sn_monitor monitor;
    struct sn_monitor_event event;
    uint8_t frame[FRAME_LENGTH];
    struct sn_capture_packet packet;

    sn_monitor_init(&monitor, 10000000000ULL);
    make_tcp_frame(frame, 1U, 12345U, 2U, 443U);
    packet = capture_packet(frame, sizeof(frame), 100L);
    assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_PROCESSED);
    assert(monitor.stats.captured_packets == 1U);
    assert(monitor.stats.ipv4_packets == 1U);
    assert(monitor.stats.tcp_packets == 1U);
    assert(sn_monitor_next_event(&monitor, &event));
    assert(event.kind == SN_MONITOR_FLOW_CREATED);
    assert(event.flow.packets[0] == 1U);

    make_tcp_frame(frame, 2U, 443U, 1U, 12345U);
    packet = capture_packet(frame, sizeof(frame), 101L);
    assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_PROCESSED);
    assert(sn_monitor_next_event(&monitor, &event));
    assert(event.kind == SN_MONITOR_FLOW_UPDATED);
    assert(event.flow.packets[0] == 1U && event.flow.packets[1] == 1U);
    assert(!sn_monitor_next_event(&monitor, &event));
}

static void test_reject_bad_frames_without_flow_events(void)
{
    struct sn_monitor monitor;
    struct sn_monitor_event event;
    uint8_t frame[FRAME_LENGTH];
    struct sn_capture_packet packet;

    sn_monitor_init(&monitor, 10000000000ULL);
    make_tcp_frame(frame, 1U, 12345U, 2U, 443U);
    packet = capture_packet(frame, ETHERNET_LENGTH - 1U, 100L);
    assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_TRUNCATED);
    assert(monitor.stats.truncated_packets == 1U);
    assert(sn_flow_table_count(&monitor.flows) == 0U);
    assert(!sn_monitor_next_event(&monitor, &event));

    packet = capture_packet(frame, sizeof(frame), -1L);
    assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_INVALID);
    assert(monitor.stats.invalid_packets == 1U);
}

static void test_igmp_and_vrrp_capture_to_decoded_flows(void)
{
    struct sn_monitor monitor;
    struct sn_monitor_event event;
    uint8_t frame[FRAME_LENGTH];
    struct sn_capture_packet packet;

    sn_monitor_init(&monitor, UINT64_MAX);
    size_t frame_length = make_group_protocol_frame(frame, 2U);
    packet = capture_packet(frame, frame_length, 100L);
    assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_PROCESSED);
    assert(monitor.stats.igmp_packets == 1U);
    assert(sn_monitor_next_event(&monitor, &event));
    assert(event.flow.protocol == 2U);
    assert(strstr(event.flow.decode_history[0].text, "IGMP v2 report") != NULL);

    frame_length = make_group_protocol_frame(frame, 112U);
    packet = capture_packet(frame, frame_length, 101L);
    assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_PROCESSED);
    assert(monitor.stats.vrrp_packets == 1U);
    assert(sn_monitor_next_event(&monitor, &event));
    assert(event.flow.protocol == 112U);
    assert(strstr(event.flow.decode_history[0].text, "VRRPv2 advert") != NULL);
}

static void test_sll_ntp_reply_reaches_flow_decoder(void)
{
    uint8_t frame[16U + IPV4_LENGTH + 8U + 48U] = {0};
    uint8_t *ip = frame + 16U;
    uint8_t *udp = ip + IPV4_LENGTH;
    uint8_t *ntp = udp + 8U;
    struct sn_monitor monitor;
    struct sn_monitor_event event;
    struct sn_capture_packet packet;

    write_be16(frame + 14U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, IPV4_LENGTH + 8U + 48U);
    ip[8] = 48U;
    ip[9] = 17U;
    ip[12] = 132U;
    ip[13] = 246U;
    ip[14] = 11U;
    ip[15] = 237U;
    ip[16] = 174U;
    ip[17] = 88U;
    ip[18] = 220U;
    ip[19] = 62U;
    write_be16(udp, 123U);
    write_be16(udp + 2U, 44136U);
    write_be16(udp + 4U, 56U);
    ntp[0] = 0x24U;
    ntp[1] = 2U;
    ntp[2] = 0U;
    ntp[3] = 231U;
    ntp[12] = 0x84U;
    ntp[13] = 0xf6U;
    ntp[14] = 0x0bU;
    ntp[15] = 0xe7U;

    packet = capture_packet(frame, sizeof(frame), 100L);
    packet.link_type = SN_PACKET_LINK_LINUX_SLL;
    sn_monitor_init(&monitor, UINT64_MAX);
    assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_PROCESSED);
    assert(monitor.stats.udp_packets == 1U);
    assert(sn_monitor_next_event(&monitor, &event));
    assert(event.flow.protocol == 17U);
    assert(event.flow.decode_history_count == 1U);
    assert(strstr(event.flow.decode_history[0].text,
                  "NTP v4 server LI=0 stratum=2 poll=0 precision=-25 refid=84f60be7") != NULL);
}

static void test_bounded_event_queue_drops_newest(void)
{
    struct sn_monitor monitor;
    uint8_t frame[FRAME_LENGTH];
    struct sn_capture_packet packet;

    sn_monitor_init(&monitor, UINT64_MAX);
    for (size_t index = 0U; index < SN_MONITOR_EVENT_CAPACITY + 1U; ++index) {
        make_tcp_frame(frame, (uint8_t)(index & 0xffU),
                       (uint16_t)(1000U + index), 250U, 443U);
        frame[ETHERNET_LENGTH + 13U] = (uint8_t)(index >> 8);
        packet = capture_packet(frame, sizeof(frame), (long)index + 1L);
        if (index < SN_MONITOR_EVENT_CAPACITY) {
            assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_PROCESSED);
        } else {
            assert(sn_monitor_process(&monitor, &packet) == SN_MONITOR_EVENT_DROPPED);
        }
    }
    assert(monitor.event_count == SN_MONITOR_EVENT_CAPACITY);
    assert(monitor.stats.dropped_events == 1U);
}

static void test_three_second_rate_sampling_and_reset(void)
{
    struct sn_monitor_rate_sampler sampler;
    struct sn_monitor_stats stats = {0};
    struct sn_monitor_rates rates = {0};

    sn_monitor_rate_sampler_init(&sampler);
    stats.ipv4_packets = 10U;
    stats.tcp_packets = 3U;
    stats.udp_packets = 4U;
    stats.icmp_packets = 2U;
    stats.igmp_packets = 1U;
    stats.vrrp_packets = 2U;
    stats.tcp_bytes = 300U;
    stats.udp_bytes = 400U;
    assert(!sn_monitor_rate_sample(&sampler, &stats, 1000000000ULL, &rates));

    stats.ipv4_packets = 40U;
    stats.tcp_packets = 9U;
    stats.udp_packets = 10U;
    stats.icmp_packets = 8U;
    stats.igmp_packets = 7U;
    stats.vrrp_packets = 8U;
    stats.tcp_bytes = 1500U;
    stats.udp_bytes = 2800U;
    assert(!sn_monitor_rate_sample(&sampler, &stats, 3999999999ULL, &rates));
    assert(sn_monitor_rate_sample(&sampler, &stats, 4000000000ULL, &rates));
    assert(rates.ipv4_packets_per_second == 10U);
    assert(rates.tcp_packets_per_second == 2U);
    assert(rates.udp_packets_per_second == 2U);
    assert(rates.icmp_packets_per_second == 2U);
    assert(rates.igmp_packets_per_second == 2U);
    assert(rates.vrrp_packets_per_second == 2U);
    assert(rates.tcp_bytes_per_second == 400U);
    assert(rates.udp_bytes_per_second == 800U);

    stats.ipv4_packets = 9U;
    stats.tcp_packets = 2U;
    stats.udp_packets = 1U;
    stats.icmp_packets = 1U;
    stats.igmp_packets = 0U;
    stats.vrrp_packets = 1U;
    stats.tcp_bytes = 600U;
    stats.udp_bytes = 200U;
    assert(sn_monitor_rate_sample(&sampler, &stats, 7000000000ULL, &rates));
    assert(rates.ipv4_packets_per_second == 3U);
    assert(rates.tcp_packets_per_second == 0U);
    assert(rates.udp_packets_per_second == 0U);
    assert(rates.icmp_packets_per_second == 0U);
    assert(rates.igmp_packets_per_second == 0U);
    assert(rates.vrrp_packets_per_second == 0U);
    assert(rates.tcp_bytes_per_second == 200U);
}

int main(void)
{
    test_capture_to_flow_events();
    test_reject_bad_frames_without_flow_events();
    test_igmp_and_vrrp_capture_to_decoded_flows();
    test_sll_ntp_reply_reaches_flow_decoder();
    test_bounded_event_queue_drops_newest();
    test_three_second_rate_sampling_and_reset();
    puts("monitor tests passed");
    return 0;
}
