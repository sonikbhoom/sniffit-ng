#include "sniffit_ng/flow.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct packet_fixture {
    struct sn_packet_view view;
    uint8_t transport[64];
    uint8_t payload[64];
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
    packet.transport[12] = 0x50U;
    return packet;
}

static void bind_packet_buffer(struct packet_fixture *packet)
{
    packet->view.transport = packet->transport;
    if (packet->view.protocol == 17U) {
        packet->view.payload = packet->payload;
    }
}

static struct packet_fixture make_dns_packet(bool response,
                                             uint8_t source_last,
                                             uint16_t source_port,
                                             uint8_t destination_last,
                                             uint16_t destination_port,
                                             uint16_t identifier)
{
    struct packet_fixture packet = {0};
    static const uint8_t question[] = {
        7U, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3U, 'c', 'o', 'm', 0U, 0U, 1U, 0U, 1U
    };
    size_t dns_length = 12U + sizeof(question);

    packet.view.protocol = 17U;
    packet.view.ipv4_total_length = (uint16_t)(20U + 8U + dns_length);
    packet.view.source_ipv4[0] = 192U;
    packet.view.source_ipv4[1] = 0U;
    packet.view.source_ipv4[2] = 2U;
    packet.view.source_ipv4[3] = source_last;
    packet.view.destination_ipv4[0] = 192U;
    packet.view.destination_ipv4[1] = 0U;
    packet.view.destination_ipv4[2] = 2U;
    packet.view.destination_ipv4[3] = destination_last;
    packet.view.transport = packet.transport;
    packet.view.transport_length = 8U + dns_length;
    packet.view.transport_header_present = true;
    packet.view.payload = packet.payload;
    packet.view.payload_length = dns_length;
    set_port(packet.transport, source_port);
    set_port(packet.transport + 2U, destination_port);
    set_port(packet.transport + 4U, (uint16_t)(8U + dns_length));
    packet.payload[0] = (uint8_t)(identifier >> 8);
    packet.payload[1] = (uint8_t)identifier;
    packet.payload[2] = response ? 0x81U : 0x01U;
    packet.payload[3] = response ? 0x80U : 0x00U;
    packet.payload[5] = 1U;
    memcpy(packet.payload + 12U, question, sizeof(question));
    return packet;
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

static void test_syn_only_flow_requires_header_only_syn_packets(void)
{
    struct sn_flow_table table;
    const struct sn_flow *flow = NULL;
    struct packet_fixture packet = make_tcp_packet(1U, 40000U, 2U, 23U, 40U);

    bind_packet_buffer(&packet);
    packet.transport[13] = 0x02U;
    sn_flow_table_init(&table, UINT64_MAX);
    assert(sn_flow_table_update(&table, &packet.view, 1U, &flow) == SN_FLOW_CREATED);
    assert(flow->tcp_syn_only_no_payload);
    assert(sn_flow_table_update(&table, &packet.view, 2U, &flow) == SN_FLOW_UPDATED);
    assert(flow->tcp_syn_only_no_payload);

    packet.transport[13] = 0x12U;
    assert(sn_flow_table_update(&table, &packet.view, 3U, &flow) == SN_FLOW_UPDATED);
    assert(!flow->tcp_syn_only_no_payload);

    packet = make_tcp_packet(3U, 40001U, 4U, 23U, 41U);
    bind_packet_buffer(&packet);
    packet.transport[13] = 0x02U;
    packet.view.payload_length = 1U;
    assert(sn_flow_table_update(&table, &packet.view, 4U, &flow) == SN_FLOW_CREATED);
    assert(!flow->tcp_syn_only_no_payload);
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
    packet.payload_length = 128U;

    sn_flow_table_init(&table, 100U);
    assert(sn_flow_table_update(&table, &packet, 1U, &flow) == SN_FLOW_CREATED);
    assert(flow != NULL && flow->icmp_history_count == 0U);
    assert(strcmp(flow->security_advisory,
                  "SECURITY: unencrypted and unauthenticated diagnostic traffic") == 0);
    assert(flow->decode_history_count == 1U);
    assert(strstr(flow->decode_history[0].text, "SECURITY:") == NULL);

    sn_flow_table_set_payload_inspection(&table, true);
    assert(sn_flow_table_update(&table, &packet, 2U, &flow) == SN_FLOW_UPDATED);
    size_t latest = (flow->icmp_history_next + SN_FLOW_ICMP_HISTORY_CAPACITY - 1U) %
                    SN_FLOW_ICMP_HISTORY_CAPACITY;
    assert(flow->icmp_history_count == 1U);
    assert(flow->icmp_history[latest].type == 8U);
    assert(flow->icmp_history[latest].direction == 0U);
    assert(flow->icmp_history[latest].identifier == 0x1234U);
    assert(flow->icmp_history[latest].sequence == 7U);
    assert(flow->icmp_history[latest].payload_length == 128U);
    assert(flow->icmp_history[latest].original_payload_length == 128U);
    assert(!flow->icmp_history[latest].payload_truncated);
    assert(memcmp(flow->icmp_history[latest].payload, payload,
                  128U) == 0);

    packet.payload_length = sizeof(payload);
    assert(sn_flow_table_update(&table, &packet, 3U, &flow) == SN_FLOW_UPDATED);
    latest = (flow->icmp_history_next + SN_FLOW_ICMP_HISTORY_CAPACITY - 1U) %
             SN_FLOW_ICMP_HISTORY_CAPACITY;
    assert(flow->icmp_history[latest].payload_length == SN_FLOW_ICMP_SAMPLE_CAPACITY);
    assert(flow->icmp_history[latest].original_payload_length == sizeof(payload));
    assert(flow->icmp_history[latest].payload_truncated);
    assert(memcmp(flow->icmp_history[latest].payload, payload,
                  SN_FLOW_ICMP_SAMPLE_CAPACITY) == 0);

    packet.icmp_type = 0U;
    packet.source_ipv4[3] = 2U;
    packet.destination_ipv4[3] = 1U;
    packet.icmp_sequence = 8U;
    assert(sn_flow_table_update(&table, &packet, 4U, &flow) == SN_FLOW_UPDATED);
    latest = (flow->icmp_history_next + SN_FLOW_ICMP_HISTORY_CAPACITY - 1U) %
             SN_FLOW_ICMP_HISTORY_CAPACITY;
    assert(flow->icmp_history_count == 3U);
    assert(flow->icmp_history[latest].type == 0U);
    assert(flow->icmp_history[latest].direction == 1U);
    assert(flow->icmp_history[latest].sequence == 8U);

    sn_flow_table_set_payload_inspection(&table, false);
    assert(flow->icmp_history_count == 0U);
    for (size_t sample = 0U; sample < SN_FLOW_ICMP_HISTORY_CAPACITY; ++sample) {
        assert(flow->icmp_history[sample].payload_length == 0U);
        for (size_t index = 0U; index < sizeof(flow->icmp_history[sample].payload); ++index) {
            assert(flow->icmp_history[sample].payload[index] == 0U);
        }
    }
}

static void test_icmp_history_keeps_recent_samples_in_order(void)
{
    struct sn_flow_table table;
    struct sn_packet_view packet = {0};
    const struct sn_flow *flow = NULL;
    uint8_t transport[8] = {8U, 0U, 0U, 0U, 0U, 9U, 0U, 0U};
    uint8_t payload = 'x';

    packet.protocol = 1U;
    packet.icmp_type = 8U;
    packet.icmp_identifier = 9U;
    packet.ipv4_total_length = 29U;
    packet.source_ipv4[0] = 192U;
    packet.source_ipv4[3] = 1U;
    packet.destination_ipv4[0] = 192U;
    packet.destination_ipv4[3] = 2U;
    packet.transport = transport;
    packet.transport_length = sizeof(transport) + 1U;
    packet.transport_header_present = true;
    packet.payload = &payload;
    packet.payload_length = 1U;

    sn_flow_table_init(&table, UINT64_MAX);
    sn_flow_table_set_payload_inspection(&table, true);
    for (uint16_t sequence = 1U; sequence <= SN_FLOW_ICMP_HISTORY_CAPACITY + 4U; ++sequence) {
        packet.icmp_sequence = sequence;
        transport[6] = (uint8_t)(sequence >> 8);
        transport[7] = (uint8_t)sequence;
        assert(sn_flow_table_update(&table, &packet, sequence, &flow) ==
               (sequence == 1U ? SN_FLOW_CREATED : SN_FLOW_UPDATED));
    }

    assert(flow->icmp_history_count == SN_FLOW_ICMP_HISTORY_CAPACITY);
    for (size_t index = 0U; index < SN_FLOW_ICMP_HISTORY_CAPACITY; ++index) {
        const struct sn_icmp_echo_sample *sample =
            sn_flow_icmp_history_at(flow, index);
        assert(sample != NULL);
        assert(sample->sequence == index + 5U);
        assert(sample->payload_length == 1U);
        assert(sample->payload[0] == 'x');
    }
    assert(sn_flow_icmp_history_at(flow, SN_FLOW_ICMP_HISTORY_CAPACITY) == NULL);
}

static void test_protocol_decode_history_is_bounded_metadata(void)
{
    struct sn_flow_table table;
    struct sn_packet_view packet = {0};
    const struct sn_flow *flow = NULL;
    uint8_t igmp[8] = {0x16U, 0U, 0U, 0U, 239U, 1U, 2U, 3U};

    packet.protocol = 2U;
    packet.ipv4_total_length = 28U;
    packet.source_ipv4[0] = 192U;
    packet.source_ipv4[3] = 1U;
    packet.destination_ipv4[0] = 192U;
    packet.destination_ipv4[3] = 2U;
    packet.transport = igmp;
    packet.transport_length = sizeof(igmp);
    packet.transport_header_present = true;

    sn_flow_table_init(&table, UINT64_MAX);
    assert(!table.inspect_payloads);
    for (uint64_t sequence = 0U;
         sequence < SN_FLOW_DEFAULT_DECODE_HISTORY_CAPACITY + 4U; ++sequence) {
        igmp[7] = (uint8_t)sequence;
        assert(sn_flow_table_update(&table, &packet, sequence + 1U, &flow) ==
               (sequence == 0U ? SN_FLOW_CREATED : SN_FLOW_UPDATED));
    }
    assert(flow->decode_history_count == SN_FLOW_DEFAULT_DECODE_HISTORY_CAPACITY);
    assert(strstr(sn_flow_decode_history_at(flow, 0U)->text, "239.1.2.4") != NULL);
    assert(strstr(sn_flow_decode_history_at(flow,
                   SN_FLOW_DEFAULT_DECODE_HISTORY_CAPACITY - 1U)->text,
                   "239.1.2.19") != NULL);
    assert(sn_flow_decode_history_at(
               flow, SN_FLOW_DEFAULT_DECODE_HISTORY_CAPACITY) == NULL);
}

static void test_dns_queries_share_a_long_lived_session(void)
{
    struct sn_flow_table table;
    const struct sn_flow *flow = NULL;
    struct packet_fixture packet;
    const uint64_t minute_ns = 60000000000ULL;

    sn_flow_table_init(&table, 0U);
    for (uint16_t identifier = 1U; identifier <= 40U; ++identifier) {
        uint64_t packet_time_ns = identifier == 1U ? 1000000000ULL :
            identifier == 2U ? 120000000000ULL :
            120000000000ULL + ((uint64_t)identifier - 2U) * 1000000000ULL;

        packet = make_dns_packet(false, 1U,
                                 (uint16_t)(53000U + identifier),
                                 53U, 53U, identifier);
        bind_packet_buffer(&packet);
        assert(sn_flow_table_update(&table, &packet.view, packet_time_ns,
                                    &flow) ==
               (identifier == 1U ? SN_FLOW_CREATED : SN_FLOW_UPDATED));
        assert(flow != NULL && flow->dns_session);

        packet = make_dns_packet(true, 53U, 53U, 1U,
                                 (uint16_t)(53000U + identifier), identifier);
        bind_packet_buffer(&packet);
        assert(sn_flow_table_update(&table, &packet.view,
                                    packet_time_ns + 1000000ULL,
                                    &flow) == SN_FLOW_UPDATED);
    }

    assert(sn_flow_table_count(&table) == 1U);
    assert(flow->endpoints[0].ipv4[3] == 1U);
    assert(flow->endpoints[0].port == 0U);
    assert(flow->endpoints[1].ipv4[3] == 53U);
    assert(flow->endpoints[1].port == 53U);
    assert(flow->packets[0] == 40U && flow->packets[1] == 40U);
    assert(flow->decode_history_count == SN_FLOW_DECODE_HISTORY_CAPACITY);
    assert(strstr(sn_flow_decode_history_at(flow, 0U)->text,
                  "DNS REQUEST id=0x0019") != NULL);
    assert(strstr(sn_flow_decode_history_at(flow, 1U)->text,
                  "DNS RESPONSE id=0x0019") != NULL);
    assert(strstr(sn_flow_decode_history_at(
                      flow, SN_FLOW_DECODE_HISTORY_CAPACITY - 1U)->text,
                  "DNS RESPONSE id=0x0028") != NULL);

    packet = make_dns_packet(false, 1U, 53100U, 53U, 53U, 0x1234U);
    bind_packet_buffer(&packet);
    assert(sn_flow_table_update(&table, &packet.view,
                                flow->last_seen_ns + 5U * minute_ns,
                                &flow) == SN_FLOW_CREATED);
    assert(sn_flow_table_count(&table) == 1U);
}

int main(void)
{
    test_reverse_packets_update_one_flow();
    test_syn_only_flow_requires_header_only_syn_packets();
    test_idle_timeout_expires_flow();
    test_invalid_and_unsupported_packets();
    test_capacity_evicts_oldest_flow();
    test_time_must_be_monotonic_per_flow();
    test_counters_saturate();
    test_icmp_payload_requires_opt_in_and_is_bounded();
    test_icmp_history_keeps_recent_samples_in_order();
    test_protocol_decode_history_is_bounded_metadata();
    test_dns_queries_share_a_long_lived_session();
    puts("flow tests passed");
    return 0;
}
