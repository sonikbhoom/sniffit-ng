#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/payload_log.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)(value & 0xffU);
}

static void test_acknowledgment_is_exact(void)
{
    FILE *input = tmpfile();
    FILE *output = tmpfile();
    char warning[512] = {0};

    assert(input != NULL && output != NULL);
    assert(fprintf(input, "%s\n", SN_PAYLOAD_ACK_PHRASE) > 0);
    rewind(input);
    assert(sn_capture_recording_confirm(input, output));
    rewind(output);
    assert(fread(warning, 1U, sizeof(warning) - 1U, output) > 0U);
    assert(strstr(warning, "authorized") != NULL);
    fclose(input);
    fclose(output);

    input = tmpfile();
    output = tmpfile();
    assert(input != NULL && output != NULL);
    fputs("yes\n", input);
    rewind(input);
    assert(!sn_capture_recording_confirm(input, output));
    fclose(input);
    fclose(output);

    input = tmpfile();
    output = tmpfile();
    assert(input != NULL && output != NULL);
    assert(!sn_capture_recording_confirm(input, output));
    fclose(input);
    fclose(output);
}

static void make_payload_frame(uint8_t *frame, size_t capacity)
{
    uint8_t *ip = frame + 14U;
    uint8_t *tcp = ip + 20U;

    memset(frame, 0, capacity);
    write_be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, 20U + 20U + 5U);
    ip[8] = 64U;
    ip[9] = 6U;
    ip[12] = 192U;
    ip[14] = 2U;
    ip[15] = 1U;
    ip[16] = 198U;
    ip[17] = 51U;
    ip[18] = 100U;
    ip[19] = 2U;
    write_be16(tcp, 12345U);
    write_be16(tcp + 2U, 443U);
    tcp[12] = 0x50U;
    memcpy(tcp + 20U, "hello", 5U);
}

static void test_log_is_exclusive_private_and_hex_encoded(void)
{
    char path_template[] = "/tmp/sniffit-ng-payload-XXXXXX";
    char error[256] = {0};
    struct stat metadata;
    struct sn_capture_packet packet = {0};
    struct sn_payload_log *log;
    uint8_t frame[59];
    char content[512] = {0};
    int descriptor = mkstemp(path_template);

    assert(descriptor >= 0);
    close(descriptor);
    assert(unlink(path_template) == 0);

    make_payload_frame(frame, sizeof(frame));
    packet.data = frame;
    packet.captured_length = sizeof(frame);
    packet.wire_length = sizeof(frame);
    packet.timestamp.tv_sec = 10;
    packet.timestamp.tv_usec = 20;

    log = sn_payload_log_open(path_template, error, sizeof(error));
    assert(log != NULL);
    assert(sn_payload_log_write_packet(log, &packet));
    assert(sn_payload_log_close(log));
    assert(stat(path_template, &metadata) == 0);
    assert((metadata.st_mode & 0777U) == 0600U);

    FILE *stream = fopen(path_template, "r");
    assert(stream != NULL);
    assert(fread(content, 1U, sizeof(content) - 1U, stream) > 0U);
    fclose(stream);
    assert(strstr(content, "payload=5 hex=68656c6c6f") != NULL);
    assert(strstr(content, "hello") == NULL);

    assert(sn_payload_log_open(path_template, error, sizeof(error)) == NULL);
    assert(unlink(path_template) == 0);
}

int main(void)
{
    test_acknowledgment_is_exact();
    test_log_is_exclusive_private_and_hex_encoded();
    puts("payload logging tests passed");
    return 0;
}
