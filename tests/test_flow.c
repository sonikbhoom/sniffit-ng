#include "sniffit_ng/flow.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct packet_fixture {
    struct sn_packet_view view;
    uint8_t transport[8];
};

static void set_port(uint8_t *bytes, uint16_t port)
{
    bytes[0] = (uint8_t)(port >> 8);
    bytes[1] = (uint8_t)(port & 0xffU);
}

static struct packet_fixture make_tcp_packet(
    uint8_t source_last,
    uint16_t source_port,
    uint8_t destination_last,
    uint16_t destination_port,
    uint16_t packet_length)
{
    struct packet_fixture packet = {0};

    packet.view.protocol = 6U;
    packet.view.ipv4_total_length = packet_length;
    packet.view.transport = packet.transport;
    packet.view.transport_length = sizeof(packet.transport);
    packet.view.transport_header_present = true;
    packet.view.source_ipv4[0] = 192U;
    packet.view.source_ipv4[1] = 0U;
    packet.view.source_ipv4[2] = 2U;
    packet.view.source_ipv4[3] = source_last;
    packet.view.destination_ipv4[0] = 192U;
    packet.view.destination_ipv4[1] = 0U;
    packet.view.destination_ipv4[2] = 2U;
    packet.view.destination_ipv4[3] = destination_last;
    set_port(packet.transport, source_port);
    set_port(packet.transport + 2U, destination_port);
    return packet;
}

static void bind_packet_buffer(struct packet_fixture *packet)
{
    packet->view.transport = packet->transport;
}

static void test_reverse_packets_update_one_flow(void)
{
    struct sn_flow_table table;
    const struct sn_flow *flow;
    struct packet_fixture outbound = make_tcp_packet(1U, 12345U, 2U, 443U, 60U);
    struct packet_fixture inbound = make_tcp_packet(2U, 443U, 1U, 12345U, 80U);

    bind_packet_buffer(&outbound);
    bind_packet_buffer(&inbound);
    sn_flow_table_init(&table, 100U);
    assert(sn_flow_table_update(&table, &outbound.view, 10U, &flow) == SN_FLOW_CREATED);
    assert(sn_flow_table_count(&table) == 1U);
    assert(flow->packets[0] == 1U && flow->packets[1] == 0U);
    assert(flow->bytes[0] == 60U);

    assert(sn_flow_table_update(&table, &inbound.view, 20U, &flow) == SN_FLOW_UPDATED);
    assert(sn_flow_table_count(&table) == 1U);
    assert(flow->packets[0] == 1U && flow->packets[1] == 1U);
    assert(flow->bytes[1] == 80U);
}

static void test_idle_timeout_expires_flow(void)
{
    struct sn_flow_table table;
    const struct sn_flow *flow;
    struct packet_fixture packet = make_tcp_packet(1U, 12345U, 2U, 443U, 60U);

    bind_packet_buffer(&packet);
    sn_flow_table_init(&table, 50U);
    assert(sn_flow_table_update(&table, &packet.view, 10U, &flow) == SN_FLOW_CREATED);
    assert(sn_flow_table_update(&table, &packet.view, 60U, &flow) == SN_FLOW_CREATED);
    assert(sn_flow_table_count(&table) == 1U);
    assert(flow->packets[0] == 1U);
}

static void test_invalid_and_unsupported_packets(void)
{
    struct sn_flow_table table;
    struct packet_fixture packet = make_tcp_packet(1U, 12345U, 2U, 443U, 60U);

    bind_packet_buffer(&packet);
    sn_flow_table_init(&table, 100U);
    packet.view.protocol = 47U;
    assert(sn_flow_table_update(&table, &packet.view, 10U, NULL) == SN_FLOW_IGNORED);
    packet.view.protocol = 6U;
    packet.view.transport_header_present = false;
    assert(sn_flow_table_update(&table, &packet.view, 10U, NULL) == SN_FLOW_INVALID);
    assert(sn_flow_table_update(&table, NULL, 10U, NULL) == SN_FLOW_INVALID);
    assert(sn_flow_table_count(&table) == 0U);
}

static void test_capacity_evicts_oldest_flow(void)
{
    struct sn_flow_table table;
    struct packet_fixture packet;

    sn_flow_table_init(&table, UINT64_MAX);
    for (size_t index = 0U; index < SN_FLOW_TABLE_CAPACITY + 1U; ++index) {
        packet = make_tcp_packet((uint8_t)(index & 0xffU),
                                 (uint16_t)(1000U + index),
                                 250U, 443U, 60U);
        bind_packet_buffer(&packet);
        packet.view.source_ipv4[1] = (uint8_t)(index >> 8);
        enum sn_flow_update_result result = sn_flow_table_update(
            &table, &packet.view, (uint64_t)index + 1U, NULL);
        if (index < SN_FLOW_TABLE_CAPACITY) {
            assert(result == SN_FLOW_CREATED);
        } else {
            assert(result == SN_FLOW_EVICTED);
        }
    }
    assert(sn_flow_table_count(&table) == SN_FLOW_TABLE_CAPACITY);
}

static void test_time_must_be_monotonic_per_flow(void)
{
    struct sn_flow_table table;
    struct packet_fixture packet = make_tcp_packet(1U, 12345U, 2U, 443U, 60U);

    bind_packet_buffer(&packet);
    sn_flow_table_init(&table, 100U);
    assert(sn_flow_table_update(&table, &packet.view, 20U, NULL) == SN_FLOW_CREATED);
    assert(sn_flow_table_update(&table, &packet.view, 19U, NULL) == SN_FLOW_INVALID);
}

static void test_counters_saturate(void)
{
    struct sn_flow_table table;
    struct packet_fixture packet = make_tcp_packet(1U, 12345U, 2U, 443U, 60U);

    bind_packet_buffer(&packet);
    sn_flow_table_init(&table, 100U);
    assert(sn_flow_table_update(&table, &packet.view, 10U, NULL) == SN_FLOW_CREATED);
    table.entries[0].packets[0] = UINT64_MAX;
    table.entries[0].bytes[0] = UINT64_MAX;
    assert(sn_flow_table_update(&table, &packet.view, 20U, NULL) == SN_FLOW_UPDATED);
    assert(table.entries[0].packets[0] == UINT64_MAX);
    assert(table.entries[0].bytes[0] == UINT64_MAX);
}

static void test_icmp_payload_requires_opt_in_and_is_bounded(void)
{
    struct sn_flow_table table;
    struct sn_packet_view packet = {0};
    const struct sn_flow *flow = NULL;
    uint8_t icmp_header[8] = {8U, 0U, 0U, 0U, 0x12U, 0x34U, 0U, 7U};
    uint8_t payload[SN_FLOW_ICMP_SAMPLE_CAPACITY + 12U];

    for (size_t index = 0U; index < sizeof(payload); ++index) {
        payload[index] = (uint8_t)('A' + (index % 26U));
    }
    packet.protocol = 1U;
    packet.icmp_type = 8U;
    packet.icmp_identifier = 0x1234U;
    packet.icmp_sequence = 7U;
    packet.ipv4_total_length = 20U + sizeof(icmp_header) + sizeof(payload);
    packet.source_ipv4[0] = 192U;
    packet.source_ipv4[3] = 1U;
    packet.destination_ipv4[0] = 192U;
    packet.destination_ipv4[3] = 2U;
    packet.transport = icmp_header;
    packet.transport_length = sizeof(icmp_header) + sizeof(payload);
    packet.transport_header_present = true;
    packet.payload = payload;
    packet.payload_length = sizeof(payload);

    sn_flow_table_init(&table, 100U);
    assert(sn_flow_table_update(&table, &packet, 1U, &flow) == SN_FLOW_CREATED);
    assert(flow != NULL && !flow->has_icmp_echo_sample);

    sn_flow_table_set_payload_inspection(&table, true);
    assert(sn_flow_table_update(&table, &packet, 2U, &flow) == SN_FLOW_UPDATED);
    assert(flow->has_icmp_echo_sample);
    assert(flow->icmp_type == 8U);
    assert(flow->icmp_echo_direction == 0U);
    assert(flow->icmp_identifier == 0x1234U);
    assert(flow->icmp_sequence == 7U);
    assert(flow->icmp_payload_sample_length == SN_FLOW_ICMP_SAMPLE_CAPACITY);
    assert(memcmp(flow->icmp_payload_sample, payload,
                  SN_FLOW_ICMP_SAMPLE_CAPACITY) == 0);

    packet.icmp_type = 0U;
    packet.source_ipv4[3] = 2U;
    packet.destination_ipv4[3] = 1U;
    packet.icmp_sequence = 8U;
    assert(sn_flow_table_update(&table, &packet, 3U, &flow) == SN_FLOW_UPDATED);
    assert(flow->icmp_type == 0U);
    assert(flow->icmp_echo_direction == 1U);
    assert(flow->icmp_sequence == 8U);

    sn_flow_table_set_payload_inspection(&table, false);
    assert(!flow->has_icmp_echo_sample);
    assert(flow->icmp_payload_sample_length == 0U);
    for (size_t index = 0U; index < sizeof(flow->icmp_payload_sample); ++index) {
        assert(flow->icmp_payload_sample[index] == 0U);
    }
}

int main(void)
{
    test_reverse_packets_update_one_flow();
    test_idle_timeout_expires_flow();
    test_invalid_and_unsupported_packets();
    test_capacity_evicts_oldest_flow();
    test_time_must_be_monotonic_per_flow();
    test_counters_saturate();
    test_icmp_payload_requires_opt_in_and_is_bounded();
    puts("flow tests passed");
    return 0;
}
