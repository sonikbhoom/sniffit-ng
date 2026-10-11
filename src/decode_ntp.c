#include "protocol_decode_internal.h"

#include <stdio.h>

#define NTP_HEADER_LENGTH 48U

static int read_signed_byte(uint8_t value)
{
    return value < 128U ? (int)value : (int)value - 256;
}

static const char *mode_name(uint8_t mode)
{
    switch (mode) {
    case 1U: return "PEER MESSAGE (symmetric-active)";
    case 2U: return "PEER MESSAGE (symmetric-passive)";
    case 3U: return "CLIENT REQUEST";
    case 4U: return "SERVER RESPONSE";
    case 5U: return "BROADCAST";
    default: return NULL;
    }
}

static const char *leap_indicator_name(uint8_t leap_indicator)
{
    switch (leap_indicator) {
    case 0U: return "no-warning";
    case 1U: return "insert-second";
    case 2U: return "delete-second";
    default: return "unsynchronized";
    }
}

static const char *stratum_name(uint8_t stratum)
{
    if (stratum == 0U) {
        return "unspecified/KoD";
    }
    return stratum == 1U ? "primary" : "secondary";
}

bool sn_decode_ntp(const uint8_t *bytes,
                   size_t length,
                   char *output,
                   size_t output_capacity)
{
    uint8_t leap_indicator;
    uint8_t version;
    uint8_t mode;
    uint8_t stratum;
    int formatted_length;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < NTP_HEADER_LENGTH) {
        return false;
    }

    leap_indicator = (uint8_t)(bytes[0] >> 6);
    version = (uint8_t)((bytes[0] >> 3) & 0x07U);
    mode = (uint8_t)(bytes[0] & 0x07U);
    stratum = bytes[1];
    if (version == 0U || version > 4U || mode < 1U || mode > 5U || stratum > 15U) {
        return false;
    }

    formatted_length = snprintf(output, output_capacity,
                                "NTP %s v%u\nStatus: leap=%s stratum=%u (%s)\n"
                                "Parameters: poll=%d precision=%d refid=%02x%02x%02x%02x",
                                mode_name(mode), version,
                                leap_indicator_name(leap_indicator), stratum,
                                stratum_name(stratum),
                                read_signed_byte(bytes[2]), read_signed_byte(bytes[3]),
                                bytes[12], bytes[13], bytes[14], bytes[15]);
    if (!sn_decode_result_fits(formatted_length, output_capacity)) {
        output[0] = '\0';
        return false;
    }
    return true;
}