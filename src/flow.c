#include "sniffit_ng/flow.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

struct flow_key {
    uint8_t protocol;
    struct sn_flow_endpoint endpoints[2];
    unsigned int direction;
};

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static int compare_endpoints(const struct sn_flow_endpoint *left,
                             const struct sn_flow_endpoint *right)
{
    int address_order = memcmp(left->ipv4, right->ipv4, sizeof(left->ipv4));

    if (address_order != 0) {
        return address_order;
    }
    if (left->port < right->port) {
        return -1;
    }
    if (left->port > right->port) {
        return 1;
    }
    return 0;
}

static bool flow_matches(const struct sn_flow *flow, const struct flow_key *key)
{
    return flow->active && flow->protocol == key->protocol &&
           compare_endpoints(&flow->endpoints[0], &key->endpoints[0]) == 0 &&
           compare_endpoints(&flow->endpoints[1], &key->endpoints[1]) == 0;
}

static enum sn_flow_update_result make_flow_key(
    const struct sn_packet_view *packet,
    struct flow_key *key)
{
    uint16_t source_port = 0U;
    uint16_t destination_port = 0U;

    if (packet == NULL || key == NULL || packet->ipv4_total_length == 0U) {
        return SN_FLOW_INVALID;
    }
    if (packet->protocol != 6U && packet->protocol != 17U &&
        packet->protocol != 1U && packet->protocol != 2U &&
        packet->protocol != 112U) {
        return SN_FLOW_IGNORED;
    }
    if (!packet->transport_header_present || packet->transport == NULL ||
        packet->transport_length < 4U) {
        return SN_FLOW_INVALID;
    }

    if (packet->protocol == 6U || packet->protocol == 17U) {
        source_port = read_be16(packet->transport);
        destination_port = read_be16(packet->transport + 2U);
    }

    key->protocol = packet->protocol;
    memcpy(key->endpoints[0].ipv4, packet->source_ipv4, sizeof(key->endpoints[0].ipv4));
    memcpy(key->endpoints[1].ipv4, packet->destination_ipv4,
           sizeof(key->endpoints[1].ipv4));
    key->endpoints[0].port = source_port;
    key->endpoints[1].port = destination_port;
    key->direction = 0U;

    if (compare_endpoints(&key->endpoints[0], &key->endpoints[1]) > 0) {
        struct sn_flow_endpoint endpoint = key->endpoints[0];
        key->endpoints[0] = key->endpoints[1];
        key->endpoints[1] = endpoint;
        key->direction = 1U;
    }

    return SN_FLOW_CREATED;
}

static void increment_saturated(uint64_t *value, uint64_t amount)
{
    if (UINT64_MAX - *value < amount) {
        *value = UINT64_MAX;
    } else {
        *value += amount;
    }
}

void sn_flow_table_init(struct sn_flow_table *table, uint64_t idle_timeout_ns)
{
    if (table == NULL) {
        return;
    }
    memset(table, 0, sizeof(*table));
    table->idle_timeout_ns = idle_timeout_ns == 0U ?
        SN_FLOW_DEFAULT_IDLE_TIMEOUT_NS : idle_timeout_ns;
}

void sn_flow_table_set_payload_inspection(struct sn_flow_table *table, bool enabled)
{
    if (table == NULL) {
        return;
    }
    table->inspect_payloads = enabled;
    if (!enabled) {
        for (size_t index = 0U; index < SN_FLOW_TABLE_CAPACITY; ++index) {
            struct sn_flow *flow = &table->entries[index];
            memset(flow->icmp_history, 0, sizeof(flow->icmp_history));
            flow->icmp_history_count = 0U;
            flow->icmp_history_next = 0U;
        }
    }
}

enum sn_flow_update_result sn_flow_table_update(
    struct sn_flow_table *table,
    const struct sn_packet_view *packet,
    uint64_t timestamp_ns,
    const struct sn_flow **flow_out)
{
    struct flow_key key;
    struct sn_flow *slot = NULL;
    enum sn_flow_update_result key_result;
    size_t oldest_index = 0U;
    bool evicting = true;
    bool creating;

    if (flow_out != NULL) {
        *flow_out = NULL;
    }
    if (table == NULL) {
        return SN_FLOW_INVALID;
    }

    key_result = make_flow_key(packet, &key);
    if (key_result != SN_FLOW_CREATED) {
        return key_result;
    }

    for (size_t index = 0U; index < SN_FLOW_TABLE_CAPACITY; ++index) {
        struct sn_flow *entry = &table->entries[index];

        if (entry->active && timestamp_ns >= entry->last_seen_ns &&
            timestamp_ns - entry->last_seen_ns >= table->idle_timeout_ns) {
            entry->active = false;
        }
        if (flow_matches(entry, &key)) {
            if (timestamp_ns < entry->last_seen_ns) {
                return SN_FLOW_INVALID;
            }
            slot = entry;
            evicting = false;
            break;
        }
        if (!entry->active && slot == NULL) {
            slot = entry;
            evicting = false;
        } else if (slot == NULL && entry->last_seen_ns <
                   table->entries[oldest_index].last_seen_ns) {
            oldest_index = index;
        }
    }

    if (slot == NULL) {
        slot = &table->entries[oldest_index];
    }

    creating = !slot->active || !flow_matches(slot, &key);
    if (creating) {
        *slot = (struct sn_flow){0};
        slot->active = true;
        slot->protocol = key.protocol;
        slot->endpoints[0] = key.endpoints[0];
        slot->endpoints[1] = key.endpoints[1];
    }

    increment_saturated(&slot->packets[key.direction], 1U);
    increment_saturated(&slot->bytes[key.direction], packet->ipv4_total_length);
    slot->last_seen_ns = timestamp_ns;
    {
        char decoded[SN_PACKET_DECODE_TEXT_CAPACITY];

        if (sn_protocol_decode(packet, decoded, sizeof(decoded))) {
            struct sn_packet_decode_record *record =
                &slot->decode_history[slot->decode_history_next];
            (void)snprintf(record->text, sizeof(record->text), "%s", decoded);
            slot->decode_history_next =
                (slot->decode_history_next + 1U) % SN_FLOW_DECODE_HISTORY_CAPACITY;
            if (slot->decode_history_count < SN_FLOW_DECODE_HISTORY_CAPACITY) {
                ++slot->decode_history_count;
            }
        }
    }
    if (table->inspect_payloads && packet->protocol == 1U &&
        (packet->icmp_type == 0U || packet->icmp_type == 8U)) {
        size_t sample_length = packet->payload_length;
        struct sn_icmp_echo_sample *sample =
            &slot->icmp_history[slot->icmp_history_next];

        if (sample_length > SN_FLOW_ICMP_SAMPLE_CAPACITY) {
            sample_length = SN_FLOW_ICMP_SAMPLE_CAPACITY;
        }
        *sample = (struct sn_icmp_echo_sample){0};
        sample->type = packet->icmp_type;
        sample->direction = (uint8_t)key.direction;
        sample->identifier = packet->icmp_identifier;
        sample->sequence = packet->icmp_sequence;
        sample->original_payload_length = packet->payload_length;
        sample->payload_length = sample_length;
        sample->payload_truncated = packet->payload_length > sample_length;
        if (sample_length > 0U && packet->payload != NULL) {
            memcpy(sample->payload, packet->payload, sample_length);
        }
        slot->icmp_history_next =
            (slot->icmp_history_next + 1U) % SN_FLOW_ICMP_HISTORY_CAPACITY;
        if (slot->icmp_history_count < SN_FLOW_ICMP_HISTORY_CAPACITY) {
            ++slot->icmp_history_count;
        }
    }

    if (flow_out != NULL) {
        *flow_out = slot;
    }
    if (evicting) {
        return SN_FLOW_EVICTED;
    }
    return creating ? SN_FLOW_CREATED : SN_FLOW_UPDATED;
}

size_t sn_flow_table_count(const struct sn_flow_table *table)
{
    size_t count = 0U;

    if (table == NULL) {
        return 0U;
    }
    for (size_t index = 0U; index < SN_FLOW_TABLE_CAPACITY; ++index) {
        if (table->entries[index].active) {
            ++count;
        }
    }
    return count;
}

const struct sn_icmp_echo_sample *sn_flow_icmp_history_at(
    const struct sn_flow *flow,
    size_t chronological_index)
{
    size_t oldest_index;

    if (flow == NULL || chronological_index >= flow->icmp_history_count) {
        return NULL;
    }
    oldest_index = (flow->icmp_history_next + SN_FLOW_ICMP_HISTORY_CAPACITY -
                    flow->icmp_history_count) % SN_FLOW_ICMP_HISTORY_CAPACITY;
    return &flow->icmp_history[(oldest_index + chronological_index) %
                               SN_FLOW_ICMP_HISTORY_CAPACITY];
}

const struct sn_packet_decode_record *sn_flow_decode_history_at(
    const struct sn_flow *flow,
    size_t chronological_index)
{
    size_t oldest_index;

    if (flow == NULL || chronological_index >= flow->decode_history_count) {
        return NULL;
    }
    oldest_index = (flow->decode_history_next + SN_FLOW_DECODE_HISTORY_CAPACITY -
                    flow->decode_history_count) % SN_FLOW_DECODE_HISTORY_CAPACITY;
    return &flow->decode_history[(oldest_index + chronological_index) %
                                 SN_FLOW_DECODE_HISTORY_CAPACITY];
}
