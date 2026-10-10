#include "protocol_decode_internal.h"

#include <stdio.h>
#include <string.h>

#define BOOTP_FIXED_LENGTH 236U
#define DHCP_COOKIE_LENGTH 4U
#define DHCP_OPTIONS_OFFSET (BOOTP_FIXED_LENGTH + DHCP_COOKIE_LENGTH)
#define DHCP_HARDWARE_ADDRESS_CAPACITY 16U

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static const char *message_type_name(uint8_t message_type)
{
    switch (message_type) {
    case 1U: return "Discover";
    case 2U: return "Offer";
    case 3U: return "Request";
    case 4U: return "Decline";
    case 5U: return "ACK";
    case 6U: return "NAK";
    case 7U: return "Release";
    case 8U: return "Inform";
    case 9U: return "ForceRenew";
    case 10U: return "LeaseQuery";
    case 11U: return "LeaseUnassigned";
    case 12U: return "LeaseUnknown";
    case 13U: return "LeaseActive";
    default: return "Unknown";
    }
}

static bool format_hardware_address(const uint8_t *bytes,
                                    size_t length,
                                    char *output,
                                    size_t output_capacity)
{
    size_t required_length;
    size_t offset = 0U;

    if (bytes == NULL || output == NULL || length == 0U ||
        length > DHCP_HARDWARE_ADDRESS_CAPACITY) {
        return false;
    }
    required_length = length * 3U;
    if (required_length > output_capacity) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        int written = snprintf(output + offset, output_capacity - offset,
                               index == 0U ? "%02x" : ":%02x", bytes[index]);
        if (written < 0 || (size_t)written >= output_capacity - offset) {
            return false;
        }
        offset += (size_t)written;
    }
    return true;
}

bool sn_decode_dhcp4(const uint8_t *bytes,
                     size_t length,
                     char *output,
                     size_t output_capacity)
{
    static const uint8_t cookie[DHCP_COOKIE_LENGTH] = {99U, 130U, 83U, 99U};
    char hardware_address[DHCP_HARDWARE_ADDRESS_CAPACITY * 3U];
    uint8_t operation;
    uint8_t hardware_type;
    uint8_t hardware_length;
    uint8_t dhcp_message_type = 0U;
    uint32_t transaction_id;
    uint32_t lease_seconds = 0U;
    size_t option_count = 0U;
    bool has_cookie;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < BOOTP_FIXED_LENGTH) {
        return false;
    }
    operation = bytes[0];
    hardware_type = bytes[1];
    hardware_length = bytes[2];
    if ((operation != 1U && operation != 2U) || hardware_length == 0U ||
        hardware_length > DHCP_HARDWARE_ADDRESS_CAPACITY) {
        return false;
    }
    if (!format_hardware_address(bytes + 28U, hardware_length,
                                 hardware_address, sizeof(hardware_address))) {
        return false;
    }
    transaction_id = read_be32(bytes + 4U);
    has_cookie = length >= DHCP_OPTIONS_OFFSET &&
        memcmp(bytes + BOOTP_FIXED_LENGTH, cookie, sizeof(cookie)) == 0;

    if (has_cookie) {
        size_t cursor = DHCP_OPTIONS_OFFSET;
        bool found_end = false;

        while (cursor < length) {
            uint8_t code = bytes[cursor++];
            size_t option_length;

            if (code == 0U) {
                continue;
            }
            if (code == 255U) {
                found_end = true;
                break;
            }
            if (cursor >= length) {
                return false;
            }
            option_length = bytes[cursor++];
            if (option_length > length - cursor) {
                return false;
            }
            ++option_count;
            if (code == 53U) {
                if (option_length != 1U) {
                    return false;
                }
                dhcp_message_type = bytes[cursor];
            } else if (code == 51U) {
                if (option_length != 4U) {
                    return false;
                }
                lease_seconds = read_be32(bytes + cursor);
            }
            cursor += option_length;
        }
        if (!found_end) {
            return false;
        }
        if (dhcp_message_type == 0U) {
            return false;
        }
        return sn_decode_result_fits(snprintf(output, output_capacity,
            "DHCPv4 %s xid=0x%08x htype=%u chaddr=%s lease=%u options=%zu",
            message_type_name(dhcp_message_type), transaction_id, hardware_type,
            hardware_address, lease_seconds, option_count), output_capacity);
    }

    return sn_decode_result_fits(snprintf(output, output_capacity,
        "BOOTP %s xid=0x%08x htype=%u hlen=%u chaddr=%s",
        operation == 1U ? "request" : "reply", transaction_id,
        hardware_type, hardware_length, hardware_address), output_capacity);
}