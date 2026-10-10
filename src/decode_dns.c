#include "protocol_decode_internal.h"

#include <stdio.h>
#include <string.h>

#define DNS_HEADER_LENGTH 12U
#define DNS_MAX_QUESTIONS 16U
#define DNS_MAX_POINTER_JUMPS 32U
#define DNS_NAME_CAPACITY 128U

struct dns_name {
    char text[DNS_NAME_CAPACITY];
    size_t next_offset;
};

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static bool append_label_character(char *name, size_t *name_length, uint8_t byte)
{
    char character;

    if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') || byte == '-' || byte == '_') {
        character = (char)byte;
    } else {
        character = '_';
    }
    if (*name_length + 1U >= DNS_NAME_CAPACITY) {
        return false;
    }
    name[(*name_length)++] = character;
    return true;
}

static bool decode_name(const uint8_t *message,
                        size_t message_length,
                        size_t start,
                        struct dns_name *name)
{
    size_t cursor = start;
    size_t name_length = 0U;
    size_t next_offset = 0U;
    size_t visited[DNS_MAX_POINTER_JUMPS];
    size_t visited_count = 0U;
    bool jumped = false;

    if (message == NULL || name == NULL || start >= message_length) {
        return false;
    }
    name->text[0] = '\0';
    for (;;) {
        uint8_t label_length;

        if (cursor >= message_length) {
            return false;
        }
        label_length = message[cursor];
        if (label_length == 0U) {
            if (!jumped) {
                next_offset = cursor + 1U;
            }
            if (name_length == 0U) {
                name->text[name_length++] = '.';
            }
            name->text[name_length] = '\0';
            name->next_offset = next_offset;
            return true;
        }
        if ((label_length & 0xc0U) == 0xc0U) {
            size_t pointer;

            if (cursor + 1U >= message_length ||
                visited_count >= DNS_MAX_POINTER_JUMPS) {
                return false;
            }
            pointer = (size_t)(((uint16_t)(label_length & 0x3fU) << 8) |
                               message[cursor + 1U]);
            if (pointer >= cursor || pointer >= message_length) {
                return false;
            }
            for (size_t index = 0U; index < visited_count; ++index) {
                if (visited[index] == pointer) {
                    return false;
                }
            }
            visited[visited_count++] = pointer;
            if (!jumped) {
                next_offset = cursor + 2U;
                jumped = true;
            }
            cursor = pointer;
            continue;
        }
        if ((label_length & 0xc0U) != 0U || label_length > 63U ||
            (size_t)label_length > message_length - cursor - 1U) {
            return false;
        }
        if (name_length > 0U) {
            if (name_length + 1U >= DNS_NAME_CAPACITY) {
                return false;
            }
            name->text[name_length++] = '.';
        }
        for (size_t index = 0U; index < label_length; ++index) {
            if (!append_label_character(name->text, &name_length,
                                        message[cursor + 1U + index])) {
                return false;
            }
        }
        cursor += (size_t)label_length + 1U;
    }
}

static const char *record_type_name(uint16_t record_type)
{
    switch (record_type) {
    case 1U: return "A";
    case 2U: return "NS";
    case 5U: return "CNAME";
    case 6U: return "SOA";
    case 12U: return "PTR";
    case 15U: return "MX";
    case 16U: return "TXT";
    case 28U: return "AAAA";
    case 33U: return "SRV";
    case 255U: return "ANY";
    default: return "other";
    }
}

static bool decode_dns_message(const uint8_t *bytes,
                               size_t length,
                               char *output,
                               size_t output_capacity)
{
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
    size_t cursor = DNS_HEADER_LENGTH;
    struct dns_name first_question = {{0}, 0U};
    uint16_t first_type = 0U;
    uint16_t first_class = 0U;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < DNS_HEADER_LENGTH) {
        return false;
    }
    flags = read_be16(bytes + 2U);
    question_count = read_be16(bytes + 4U);
    answer_count = read_be16(bytes + 6U);
    authority_count = read_be16(bytes + 8U);
    additional_count = read_be16(bytes + 10U);
    if (((flags >> 11) & 0x0fU) > 5U || question_count > DNS_MAX_QUESTIONS) {
        return false;
    }

    for (size_t index = 0U; index < question_count; ++index) {
        struct dns_name question;

        if (!decode_name(bytes, length, cursor, &question) ||
            question.next_offset > length || length - question.next_offset < 4U) {
            return false;
        }
        if (index == 0U) {
            first_question = question;
            first_type = read_be16(bytes + question.next_offset);
            first_class = read_be16(bytes + question.next_offset + 2U);
        }
        cursor = question.next_offset + 4U;
    }

    if (question_count > 0U) {
        return sn_decode_result_fits(snprintf(output, output_capacity,
            "DNS %s opcode=%u rcode=%u q=%u an=%u ns=%u ar=%u name=%s type=%s/%u class=%u",
            (flags & 0x8000U) != 0U ? "response" : "query",
            (unsigned int)((flags >> 11) & 0x0fU), (unsigned int)(flags & 0x0fU),
            question_count, answer_count, authority_count, additional_count,
            first_question.text, record_type_name(first_type), first_type, first_class),
            output_capacity);
    }
    return sn_decode_result_fits(snprintf(output, output_capacity,
        "DNS %s opcode=%u rcode=%u q=0 an=%u ns=%u ar=%u",
        (flags & 0x8000U) != 0U ? "response" : "query",
        (unsigned int)((flags >> 11) & 0x0fU), (unsigned int)(flags & 0x0fU),
        answer_count, authority_count, additional_count), output_capacity);
}

bool sn_decode_dns(const uint8_t *bytes,
                   size_t length,
                   char *output,
                   size_t output_capacity)
{
    return decode_dns_message(bytes, length, output, output_capacity);
}

bool sn_decode_dns_tcp(const uint8_t *bytes,
                       size_t length,
                       char *output,
                       size_t output_capacity)
{
    size_t dns_length;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < 2U) {
        return false;
    }
    dns_length = read_be16(bytes);
    if (dns_length < DNS_HEADER_LENGTH || dns_length != length - 2U) {
        return false;
    }
    return decode_dns_message(bytes + 2U, dns_length, output, output_capacity);
}