#include "protocol_decode_internal.h"

#include <stdio.h>

struct sn_ber_tlv {
    uint8_t tag;
    const uint8_t *value;
    size_t length;
    const uint8_t *next;
};

static bool read_tlv(const uint8_t **cursor,
                     const uint8_t *end,
                     struct sn_ber_tlv *tlv)
{
    const uint8_t *position;
    size_t length;
    uint8_t first_length;

    if (cursor == NULL || *cursor == NULL || end == NULL || tlv == NULL || *cursor >= end) {
        return false;
    }
    position = *cursor;
    tlv->tag = *position++;
    if (position >= end) {
        return false;
    }
    first_length = *position++;
    if ((first_length & 0x80U) == 0U) {
        length = first_length;
    } else {
        size_t length_bytes = first_length & 0x7fU;
        if (length_bytes == 0U || length_bytes > 4U ||
            (size_t)(end - position) < length_bytes) {
            return false;
        }
        length = 0U;
        for (size_t index = 0U; index < length_bytes; ++index) {
            if (length > (SIZE_MAX >> 8)) {
                return false;
            }
            length = (length << 8) | position[index];
        }
        position += length_bytes;
    }
    if (length > (size_t)(end - position)) {
        return false;
    }
    tlv->value = position;
    tlv->length = length;
    tlv->next = position + length;
    *cursor = tlv->next;
    return true;
}

static bool read_integer(const struct sn_ber_tlv *tlv, uint32_t *value)
{
    uint32_t result = 0U;

    if (tlv == NULL || value == NULL || tlv->tag != 0x02U ||
        tlv->length == 0U || tlv->length > 4U) {
        return false;
    }
    for (size_t index = 0U; index < tlv->length; ++index) {
        result = (result << 8) | tlv->value[index];
    }
    *value = result;
    return true;
}

static const char *version_name(uint32_t version)
{
    switch (version) {
    case 0U: return "v1";
    case 1U: return "v2c";
    case 3U: return "v3";
    default: return "unknown";
    }
}

static const char *pdu_name(uint8_t tag)
{
    switch (tag) {
    case 0xa0U: return "GetRequest";
    case 0xa1U: return "GetNextRequest";
    case 0xa2U: return "Response";
    case 0xa3U: return "SetRequest";
    case 0xa4U: return "Trap";
    case 0xa5U: return "GetBulkRequest";
    case 0xa6U: return "InformRequest";
    case 0xa7U: return "TrapV2";
    case 0xa8U: return "Report";
    default: return NULL;
    }
}

static bool count_varbinds(const struct sn_ber_tlv *list, size_t *count)
{
    const uint8_t *cursor;
    struct sn_ber_tlv entry;
    size_t entries = 0U;

    if (list == NULL || count == NULL || list->tag != 0x30U) {
        return false;
    }
    cursor = list->value;
    while (cursor < list->next) {
        if (!read_tlv(&cursor, list->next, &entry) || entry.tag != 0x30U) {
            return false;
        }
        ++entries;
    }
    *count = entries;
    return true;
}

bool sn_decode_snmp(const uint8_t *bytes,
                    size_t length,
                    char *output,
                    size_t output_capacity)
{
    const uint8_t *cursor;
    const uint8_t *end;
    struct sn_ber_tlv message;
    struct sn_ber_tlv version_tlv;
    struct sn_ber_tlv community_tlv;
    struct sn_ber_tlv pdu;
    struct sn_ber_tlv field;
    struct sn_ber_tlv header_data;
    struct sn_ber_tlv security_parameters;
    struct sn_ber_tlv scoped_pdu;
    uint32_t version;
    uint32_t request_id = 0U;
    size_t varbind_count = 0U;
    const char *name;

    if (bytes == NULL || output == NULL || output_capacity == 0U || length == 0U) {
        return false;
    }
    cursor = bytes;
    end = bytes + length;
    if (!read_tlv(&cursor, end, &message) || message.tag != 0x30U || cursor != end) {
        return false;
    }
    cursor = message.value;
    end = message.next;
    if (!read_tlv(&cursor, end, &version_tlv) || !read_integer(&version_tlv, &version)) {
        return false;
    }
    if (version == 3U) {
        if (!read_tlv(&cursor, end, &header_data) || header_data.tag != 0x30U ||
            !read_tlv(&cursor, end, &security_parameters) ||
            security_parameters.tag != 0x04U ||
            !read_tlv(&cursor, end, &scoped_pdu) ||
            (scoped_pdu.tag != 0x30U && scoped_pdu.tag != 0x04U) || cursor != end) {
            return false;
        }
        return sn_decode_result_fits(snprintf(output, output_capacity,
                                              "SNMPv3 message"), output_capacity);
    }
    if (version > 1U) {
        return false;
    }
    if (!read_tlv(&cursor, end, &community_tlv) || community_tlv.tag != 0x04U ||
        !read_tlv(&cursor, end, &pdu)) {
        return false;
    }
    name = pdu_name(pdu.tag);
    if (name == NULL) {
        return false;
    }
    if (pdu.tag == 0xa4U) {
        if (version != 0U) {
            return false;
        }
        cursor = pdu.value;
        end = pdu.next;
        if (!read_tlv(&cursor, end, &field) || field.tag != 0x06U ||
            !read_tlv(&cursor, end, &field) || field.tag != 0x40U || field.length != 4U ||
            !read_tlv(&cursor, end, &field) || field.tag != 0x02U ||
            !read_tlv(&cursor, end, &field) || field.tag != 0x02U ||
            !read_tlv(&cursor, end, &field) || field.tag != 0x43U ||
            !read_tlv(&cursor, end, &field) || !count_varbinds(&field, &varbind_count) ||
            cursor != end) {
            return false;
        }
        return sn_decode_result_fits(snprintf(output, output_capacity, "SNMP%s Trap",
                                              version_name(version)), output_capacity);
    }
    cursor = pdu.value;
    end = pdu.next;
    if (!read_tlv(&cursor, end, &field) || !read_integer(&field, &request_id) ||
        !read_tlv(&cursor, end, &field) || field.tag != 0x02U ||
        !read_tlv(&cursor, end, &field) || field.tag != 0x02U ||
        !read_tlv(&cursor, end, &field) || !count_varbinds(&field, &varbind_count) ||
        cursor != end) {
        return false;
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
                    "SNMP%s %s id=%u vars=%zu", version_name(version), name,
                    request_id, varbind_count), output_capacity);
}