#include "protocol_decode_internal.h"

#include <stdio.h>

#define TLS_RECORD_HEADER_LENGTH 5U
#define TLS_HANDSHAKE_HEADER_LENGTH 4U

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_be24(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 16) | ((uint32_t)bytes[1] << 8) | bytes[2];
}

static const char *record_type_name(uint8_t content_type)
{
    switch (content_type) {
    case 20U: return "change-cipher-spec";
    case 21U: return "alert";
    case 22U: return "handshake";
    case 23U: return "application-data";
    case 24U: return "heartbeat";
    default: return NULL;
    }
}

static const char *handshake_type_name(uint8_t handshake_type)
{
    switch (handshake_type) {
    case 0U: return "HelloRequest";
    case 1U: return "ClientHello";
    case 2U: return "ServerHello";
    case 4U: return "NewSessionTicket";
    case 8U: return "EncryptedExtensions";
    case 11U: return "Certificate";
    case 12U: return "ServerKeyExchange";
    case 13U: return "CertificateRequest";
    case 14U: return "ServerHelloDone";
    case 15U: return "CertificateVerify";
    case 16U: return "ClientKeyExchange";
    case 20U: return "Finished";
    case 24U: return "KeyUpdate";
    default: return "other";
    }
}

bool sn_decode_tls(const uint8_t *bytes,
                   size_t length,
                   char *output,
                   size_t output_capacity)
{
    const char *record_name;
    uint16_t record_version;
    uint16_t record_length;
    int formatted_length;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (bytes == NULL || length < TLS_RECORD_HEADER_LENGTH) {
        return false;
    }
    record_name = record_type_name(bytes[0]);
    record_version = read_be16(bytes + 1U);
    record_length = read_be16(bytes + 3U);
    if (record_name == NULL || (record_version >> 8) != 3U ||
        (record_version & 0xffU) > 4U ||
        record_length > length - TLS_RECORD_HEADER_LENGTH) {
        return false;
    }

    if (bytes[0] == 22U && record_length >= TLS_HANDSHAKE_HEADER_LENGTH) {
        uint32_t handshake_length = read_be24(bytes + TLS_RECORD_HEADER_LENGTH + 1U);
        if (handshake_length > record_length - TLS_HANDSHAKE_HEADER_LENGTH) {
            return false;
        }
        formatted_length = snprintf(output, output_capacity,
            "TLS record=handshake version=0x%04x record-bytes=%u handshake=%s handshake-bytes=%u",
            record_version, record_length,
            handshake_type_name(bytes[TLS_RECORD_HEADER_LENGTH]), handshake_length);
    } else {
        formatted_length = snprintf(output, output_capacity,
            "TLS record=%s version=0x%04x record-bytes=%u",
            record_name, record_version, record_length);
    }
    return sn_decode_result_fits(formatted_length, output_capacity);
}