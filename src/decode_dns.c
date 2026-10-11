#include "protocol_decode_internal.h"

#include <stdio.h>
#include <string.h>

#define DNS_HEADER_LENGTH 12U
#define DNS_MAX_QUESTIONS 16U
#define DNS_MAX_POINTER_JUMPS 32U
#define DNS_NAME_CAPACITY 256U

struct dns_name {
    char text[DNS_NAME_CAPACITY];
    size_t next_offset;
};

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
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

static const char *record_class_name(uint16_t record_class)
{
    switch (record_class) {
    case 1U: return "IN";
    case 3U: return "CH";
    case 4U: return "HS";
    case 255U: return "ANY";
    default: return "other";
    }
}

static const char *opcode_name(uint16_t opcode)
{
    switch (opcode) {
    case 0U: return "QUERY";
    case 1U: return "IQUERY";
    case 2U: return "STATUS";
    case 4U: return "NOTIFY";
    case 5U: return "UPDATE";
    default: return "other";
    }
}

static const char *rcode_name(uint16_t rcode)
{
    switch (rcode) {
    case 0U: return "NOERROR";
    case 1U: return "FORMERR";
    case 2U: return "SERVFAIL";
    case 3U: return "NXDOMAIN";
    case 4U: return "NOTIMP";
    case 5U: return "REFUSED";
    default: return "other";
    }
}

static bool finish_dns_text(int written, char *output, size_t output_capacity)
{
    if (written < 0 || output == NULL || output_capacity == 0U) {
        return false;
    }
    if ((size_t)written >= output_capacity) {
        if (output_capacity >= 4U) {
            output[output_capacity - 4U] = '.';
            output[output_capacity - 3U] = '.';
            output[output_capacity - 2U] = '.';
            output[output_capacity - 1U] = '\0';
        } else {
            output[output_capacity - 1U] = '\0';
        }
    }
    return true;
}

static bool format_record_data(const uint8_t *message,
                               size_t message_length,
                               uint16_t record_type,
                               size_t data_offset,
                               size_t data_length,
                               uint32_t ttl,
                               char *output,
                               size_t output_capacity)
{
    size_t data_end = data_offset + data_length;
    int written = 0;

    if (output != NULL && output_capacity > 0U) {
        output[0] = '\0';
    }
    switch (record_type) {
    case 1U:
        if (data_length != 4U) {
            return false;
        }
        if (output != NULL) {
            written = snprintf(output, output_capacity,
                               "A=%u.%u.%u.%u ttl=%u",
                               message[data_offset], message[data_offset + 1U],
                               message[data_offset + 2U], message[data_offset + 3U],
                               (unsigned int)ttl);
        }
        break;
    case 28U:
        if (data_length != 16U) {
            return false;
        }
        if (output != NULL) {
            written = snprintf(output, output_capacity,
                "AAAA=%x:%x:%x:%x:%x:%x:%x:%x ttl=%u",
                read_be16(message + data_offset),
                read_be16(message + data_offset + 2U),
                read_be16(message + data_offset + 4U),
                read_be16(message + data_offset + 6U),
                read_be16(message + data_offset + 8U),
                read_be16(message + data_offset + 10U),
                read_be16(message + data_offset + 12U),
                read_be16(message + data_offset + 14U), (unsigned int)ttl);
        }
        break;
    case 2U:
    case 5U:
    case 12U: {
        struct dns_name target;

        if (data_length == 0U ||
            !decode_name(message, message_length, data_offset, &target) ||
            target.next_offset > data_end) {
            return false;
        }
        if (output != NULL) {
            written = snprintf(output, output_capacity, "%s=%s ttl=%u",
                               record_type_name(record_type), target.text,
                               (unsigned int)ttl);
        }
        break;
    }
    case 15U: {
        struct dns_name exchange;

        if (data_length < 3U ||
            !decode_name(message, message_length, data_offset + 2U, &exchange) ||
            exchange.next_offset > data_end) {
            return false;
        }
        if (output != NULL) {
            written = snprintf(output, output_capacity, "MX=%u,%s ttl=%u",
                               read_be16(message + data_offset), exchange.text,
                               (unsigned int)ttl);
        }
        break;
    }
    case 33U: {
        struct dns_name target;

        if (data_length < 7U ||
            !decode_name(message, message_length, data_offset + 6U, &target) ||
            target.next_offset > data_end) {
            return false;
        }
        if (output != NULL) {
            written = snprintf(output, output_capacity,
                "SRV=%u,%u,%u,%s ttl=%u",
                read_be16(message + data_offset),
                read_be16(message + data_offset + 2U),
                read_be16(message + data_offset + 4U), target.text,
                (unsigned int)ttl);
        }
        break;
    }
    case 6U: {
        struct dns_name primary;
        struct dns_name mailbox;
        size_t numbers_offset;

        if (!decode_name(message, message_length, data_offset, &primary) ||
            primary.next_offset > data_end ||
            !decode_name(message, message_length, primary.next_offset, &mailbox) ||
            mailbox.next_offset > data_end) {
            return false;
        }
        numbers_offset = mailbox.next_offset;
        if (data_end - numbers_offset != 20U) {
            return false;
        }
        if (output != NULL) {
            written = snprintf(output, output_capacity,
                "SOA=%s,%s serial=%u refresh=%u retry=%u expire=%u minimum=%u ttl=%u",
                primary.text, mailbox.text,
                (unsigned int)read_be32(message + numbers_offset),
                (unsigned int)read_be32(message + numbers_offset + 4U),
                (unsigned int)read_be32(message + numbers_offset + 8U),
                (unsigned int)read_be32(message + numbers_offset + 12U),
                (unsigned int)read_be32(message + numbers_offset + 16U),
                (unsigned int)ttl);
        }
        break;
    }
    case 16U: {
        size_t cursor = data_offset;
        size_t string_count = 0U;

        while (cursor < data_end) {
            size_t string_length = message[cursor];
            if (string_length > data_end - cursor - 1U) {
                return false;
            }
            cursor += string_length + 1U;
            ++string_count;
        }
        if (output != NULL) {
            written = snprintf(output, output_capacity,
                               "TXT strings=%zu bytes=%zu content=hidden ttl=%u",
                               string_count, data_length, (unsigned int)ttl);
        }
        break;
    }
    default:
        if (output != NULL) {
            written = snprintf(output, output_capacity,
                               "TYPE%u bytes=%zu content=hidden ttl=%u",
                               record_type, data_length, (unsigned int)ttl);
        }
        break;
    }
    return output == NULL || finish_dns_text(written, output, output_capacity);
}

static bool skip_record_section(const uint8_t *message,
                                size_t message_length,
                                size_t *cursor,
                                uint16_t record_count,
                                bool capture_first,
                                char *first_record,
                                size_t first_record_capacity)
{
    for (size_t index = 0U; index < record_count; ++index) {
        struct dns_name owner;
        size_t record_offset;
        size_t data_offset;
        size_t data_length;
        uint16_t record_type;
        uint32_t ttl;

        if (!decode_name(message, message_length, *cursor, &owner) ||
            owner.next_offset > message_length ||
            message_length - owner.next_offset < 10U) {
            return false;
        }
        record_offset = owner.next_offset;
        record_type = read_be16(message + record_offset);
        ttl = read_be32(message + record_offset + 4U);
        data_length = read_be16(message + record_offset + 8U);
        data_offset = record_offset + 10U;
        if (data_length > message_length - data_offset ||
            !format_record_data(message, message_length, record_type,
                                data_offset, data_length, ttl,
                                capture_first && index == 0U ? first_record : NULL,
                                first_record_capacity)) {
            return false;
        }
        *cursor = data_offset + data_length;
    }
    return true;
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
    char first_answer[128] = {0};
    unsigned int opcode;
    bool response;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < DNS_HEADER_LENGTH) {
        return false;
    }
    flags = read_be16(bytes + 2U);
    opcode = (unsigned int)((flags >> 11) & 0x0fU);
    response = (flags & 0x8000U) != 0U;
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

    if ((size_t)answer_count + authority_count + additional_count >
            (length - cursor) / 11U ||
        !skip_record_section(bytes, length, &cursor, answer_count, true,
                             first_answer, sizeof(first_answer)) ||
        !skip_record_section(bytes, length, &cursor, authority_count, false,
                             first_answer, sizeof(first_answer)) ||
        !skip_record_section(bytes, length, &cursor, additional_count, false,
                             first_answer, sizeof(first_answer))) {
        return false;
    }

    if (question_count > 0U) {
        if (response) {
            return finish_dns_text(snprintf(output, output_capacity,
                "DNS RESPONSE id=0x%04x status=%s opcode=%s AA=%u TC=%u RD=%u RA=%u\n"
                "Question: %s %s/%s\nAnswer: %s\n"
                "Counts: answers=%u authority=%u additional=%u",
                read_be16(bytes), rcode_name(flags & 0x0fU), opcode_name(opcode),
                (flags & 0x0400U) != 0U, (flags & 0x0200U) != 0U,
                (flags & 0x0100U) != 0U, (flags & 0x0080U) != 0U,
                first_question.text, record_type_name(first_type),
                record_class_name(first_class),
                first_answer[0] != '\0' ? first_answer : "none",
                answer_count, authority_count, additional_count),
                output, output_capacity);
        }
            return finish_dns_text(snprintf(output, output_capacity,
            "DNS REQUEST id=0x%04x opcode=%s RD=%u CD=%u\nQuestion: %s %s/%s",
            read_be16(bytes), opcode_name(opcode),
            (flags & 0x0100U) != 0U, (flags & 0x0010U) != 0U,
            first_question.text, record_type_name(first_type),
                record_class_name(first_class)), output, output_capacity);
    }
            return finish_dns_text(snprintf(output, output_capacity,
        "DNS %s id=0x%04x status=%s opcode=%s questions=0 answers=%u "
        "authority=%u additional=%u",
        response ? "RESPONSE" : "REQUEST", read_be16(bytes),
        rcode_name(flags & 0x0fU), opcode_name(opcode), answer_count,
            authority_count, additional_count), output, output_capacity);
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