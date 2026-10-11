#include "protocol_decode_internal.h"

#include <stdio.h>
#include <string.h>

#define TELNET_IAC 255U
#define TELNET_MAX_EVENTS 4U
#define TELNET_EVENT_CAPACITY 64U

struct telnet_summary {
    char events[TELNET_MAX_EVENTS][TELNET_EVENT_CAPACITY];
    size_t event_count;
    size_t omitted_events;
    size_t data_bytes;
    size_t control_count;
};

static const char *command_name(uint8_t command, char *unknown, size_t capacity)
{
    switch (command) {
    case 240U: return "SE";
    case 241U: return "NOP";
    case 242U: return "DM";
    case 243U: return "BRK";
    case 244U: return "IP";
    case 245U: return "AO";
    case 246U: return "AYT";
    case 247U: return "EC";
    case 248U: return "EL";
    case 249U: return "GA";
    case 250U: return "SB";
    case 251U: return "WILL";
    case 252U: return "WONT";
    case 253U: return "DO";
    case 254U: return "DONT";
    case TELNET_IAC: return "IAC";
    default:
        (void)snprintf(unknown, capacity, "CMD(%u)", (unsigned int)command);
        return unknown;
    }
}

static const char *option_name(uint8_t option, char *unknown, size_t capacity)
{
    switch (option) {
    case 0U: return "BINARY";
    case 1U: return "ECHO";
    case 3U: return "SUPPRESS-GO-AHEAD";
    case 5U: return "STATUS";
    case 6U: return "TIMING-MARK";
    case 24U: return "TERMINAL-TYPE";
    case 25U: return "EOR";
    case 31U: return "NAWS";
    case 32U: return "TERMINAL-SPEED";
    case 33U: return "REMOTE-FLOW-CONTROL";
    case 34U: return "LINEMODE";
    case 36U: return "OLD-ENVIRON";
    case 37U: return "AUTHENTICATION";
    case 38U: return "ENCRYPT";
    case 39U: return "NEW-ENVIRON";
    case 40U: return "TN3270E";
    case 42U: return "CHARSET";
    case 44U: return "COM-PORT";
    case 46U: return "START-TLS";
    case 48U: return "SEND-URL";
    case 49U: return "FORWARD-X";
    default:
        (void)snprintf(unknown, capacity, "OPTION(%u)", (unsigned int)option);
        return unknown;
    }
}

static void add_event(struct telnet_summary *summary, const char *event)
{
    if (summary->event_count < TELNET_MAX_EVENTS) {
        (void)snprintf(summary->events[summary->event_count],
                       sizeof(summary->events[summary->event_count]), "%s", event);
        ++summary->event_count;
    } else {
        ++summary->omitted_events;
    }
}

static bool append_text(char *output,
                        size_t output_capacity,
                        size_t *output_length,
                        const char *text)
{
    int written;

    if (*output_length >= output_capacity) {
        return false;
    }
    written = snprintf(output + *output_length,
                       output_capacity - *output_length, "%s", text);
    if (written < 0 || (size_t)written >= output_capacity - *output_length) {
        return false;
    }
    *output_length += (size_t)written;
    return true;
}

static void parse_subnegotiation(const uint8_t *bytes,
                                 size_t length,
                                 size_t start,
                                 uint8_t option,
                                 struct telnet_summary *summary,
                                 size_t *next_offset)
{
    size_t cursor = start;
    size_t subnegotiation_bytes = 0U;
    char unknown_option[24];
    const char *name = option_name(option, unknown_option, sizeof(unknown_option));
    char event[TELNET_EVENT_CAPACITY];

    while (cursor < length) {
        if (bytes[cursor] != TELNET_IAC) {
            ++subnegotiation_bytes;
            ++cursor;
            continue;
        }
        if (cursor + 1U >= length) {
            ++cursor;
            break;
        }
        if (bytes[cursor + 1U] == TELNET_IAC) {
            ++subnegotiation_bytes;
            cursor += 2U;
            continue;
        }
        if (bytes[cursor + 1U] == 240U) {
            cursor += 2U;
            (void)snprintf(event, sizeof(event), "SB %s(%u) bytes=%zu", name,
                           (unsigned int)option, subnegotiation_bytes);
            add_event(summary, event);
            ++summary->control_count;
            *next_offset = cursor;
            return;
        }
        (void)snprintf(event, sizeof(event), "SB %s(%u) bytes=%zu malformed", name,
                   (unsigned int)option, subnegotiation_bytes);
        add_event(summary, event);
        ++summary->control_count;
        *next_offset = length;
        return;
    }

    (void)snprintf(event, sizeof(event), "SB %s(%u) bytes=%zu incomplete", name,
                   (unsigned int)option, subnegotiation_bytes);
    add_event(summary, event);
    ++summary->control_count;
    *next_offset = length;
}

static void parse_telnet(const uint8_t *bytes,
                         size_t length,
                         struct telnet_summary *summary)
{
    size_t cursor = 0U;

    while (cursor < length) {
        uint8_t command;
        char unknown_command[24];
        const char *name;
        char event[TELNET_EVENT_CAPACITY];

        if (bytes[cursor] != TELNET_IAC) {
            ++summary->data_bytes;
            ++cursor;
            continue;
        }
        if (cursor + 1U >= length) {
            add_event(summary, "IAC incomplete");
            break;
        }
        command = bytes[cursor + 1U];
        name = command_name(command, unknown_command, sizeof(unknown_command));
        if (command == TELNET_IAC) {
            ++summary->data_bytes;
            ++summary->control_count;
            add_event(summary, "IAC escaped");
            cursor += 2U;
            continue;
        }
        if (command == 251U || command == 252U ||
            command == 253U || command == 254U) {
            char unknown_option[24];
            const char *option;

            if (length - cursor < 3U) {
                (void)snprintf(event, sizeof(event), "%s incomplete", name);
                add_event(summary, event);
                break;
            }
            option = option_name(bytes[cursor + 2U], unknown_option,
                                 sizeof(unknown_option));
            (void)snprintf(event, sizeof(event), "%s %s(%u)", name, option,
                           (unsigned int)bytes[cursor + 2U]);
            add_event(summary, event);
            ++summary->control_count;
            cursor += 3U;
            continue;
        }
        if (command == 250U) {
            if (length - cursor < 3U) {
                add_event(summary, "SB incomplete");
                break;
            }
            parse_subnegotiation(bytes, length, cursor + 3U,
                                 bytes[cursor + 2U], summary, &cursor);
            continue;
        }
        (void)snprintf(event, sizeof(event), "%s", name);
        add_event(summary, event);
        ++summary->control_count;
        cursor += 2U;
    }
}

bool sn_decode_telnet(const uint8_t *bytes,
                      size_t length,
                      char *output,
                      size_t output_capacity)
{
    struct telnet_summary summary = {0};
    size_t output_length = 0U;
    int formatted_length;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL && length != 0U) {
        return false;
    }
    parse_telnet(bytes, length, &summary);
    formatted_length = snprintf(output, output_capacity,
                                "TELNET payload=%zu data=%zu controls=%zu",
                                length, summary.data_bytes,
                                summary.control_count);
    if (!sn_decode_result_fits(formatted_length, output_capacity)) {
        output[0] = '\0';
        return false;
    }
    output_length = (size_t)formatted_length;
    for (size_t index = 0U; index < summary.event_count; ++index) {
        if (!append_text(output, output_capacity, &output_length,
                         index == 0U ? "; " : ", ") ||
            !append_text(output, output_capacity, &output_length,
                         summary.events[index])) {
            output[0] = '\0';
            return false;
        }
    }
    if (summary.omitted_events > 0U) {
        char omitted[48];

        (void)snprintf(omitted, sizeof(omitted), ", +%zu controls",
                       summary.omitted_events);
        if (!append_text(output, output_capacity, &output_length, omitted)) {
            output[0] = '\0';
            return false;
        }
    }
    return true;
}