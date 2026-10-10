#include "sniffit_ng/payload_log.h"

#include "sniffit_ng/packet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct sn_payload_log {
    FILE *stream;
};

static void copy_error(char *destination, size_t capacity, const char *message)
{
    if (destination != NULL && capacity > 0U) {
        (void)snprintf(destination, capacity, "%s", message != NULL ? message : "");
    }
}

bool sn_payload_logging_confirm(FILE *input, FILE *output)
{
    char response[96];
    char *newline;

    if (input == NULL || output == NULL) {
        return false;
    }
    fputs("WARNING: Payload logging may capture credentials, personal information, and confidential communications.\n"
          "Only capture traffic you own or are explicitly authorized to inspect. Obtain required consent,\n"
          "minimize collection, protect the output file, and delete it according to your retention policy.\n"
          "To continue, type exactly:\n"
          SN_PAYLOAD_ACK_PHRASE "\n> ", output);
    if (fflush(output) != 0 || fgets(response, sizeof(response), input) == NULL) {
        return false;
    }
    newline = strchr(response, '\n');
    if (newline == NULL) {
        return false;
    }
    *newline = '\0';
    if (newline > response && newline[-1] == '\r') {
        newline[-1] = '\0';
    }
    return strcmp(response, SN_PAYLOAD_ACK_PHRASE) == 0;
}

struct sn_payload_log *sn_payload_log_open(
    const char *path,
    char *error_buffer,
    size_t error_buffer_size)
{
    struct sn_payload_log *log;
    int descriptor;

    if (path == NULL || path[0] == '\0') {
        copy_error(error_buffer, error_buffer_size, "payload log path must not be empty");
        return NULL;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        copy_error(error_buffer, error_buffer_size, strerror(errno));
        return NULL;
    }
    if (fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
        int saved_errno = errno;
        close(descriptor);
        unlink(path);
        copy_error(error_buffer, error_buffer_size, strerror(saved_errno));
        return NULL;
    }

    log = calloc(1U, sizeof(*log));
    if (log == NULL) {
        close(descriptor);
        unlink(path);
        copy_error(error_buffer, error_buffer_size, "out of memory opening payload log");
        return NULL;
    }
    log->stream = fdopen(descriptor, "w");
    if (log->stream == NULL) {
        int saved_errno = errno;
        close(descriptor);
        unlink(path);
        free(log);
        copy_error(error_buffer, error_buffer_size, strerror(saved_errno));
        return NULL;
    }
    if (fputs("# Sniffit NG payload log; fields are followed by hex-encoded payload bytes\n",
              log->stream) == EOF || fflush(log->stream) != 0) {
        int saved_errno = errno;
        fclose(log->stream);
        unlink(path);
        free(log);
        copy_error(error_buffer, error_buffer_size, strerror(saved_errno));
        return NULL;
    }
    copy_error(error_buffer, error_buffer_size, "");
    return log;
}

static const char *protocol_name(uint8_t protocol)
{
    switch (protocol) {
    case 6U:
        return "TCP";
    case 17U:
        return "UDP";
    case 1U:
        return "ICMP";
    default:
        return "IP";
    }
}

bool sn_payload_log_write_packet(
    struct sn_payload_log *log,
    const struct sn_capture_packet *packet)
{
    struct sn_packet_view view;
    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];
    uint16_t source_port = 0U;
    uint16_t destination_port = 0U;

    if (log == NULL || log->stream == NULL || packet == NULL || packet->data == NULL) {
        return false;
    }
    if (packet->timestamp.tv_usec < 0 || packet->timestamp.tv_usec >= 1000000 ||
        sn_packet_parse_ethernet_ipv4(packet->data, packet->captured_length, &view) != SN_PACKET_OK ||
        view.payload_length == 0U) {
        return true;
    }
    if (inet_ntop(AF_INET, view.source_ipv4, source, sizeof(source)) == NULL ||
        inet_ntop(AF_INET, view.destination_ipv4, destination, sizeof(destination)) == NULL) {
        return false;
    }
    if ((view.protocol == 6U || view.protocol == 17U) &&
        view.transport_header_present && view.transport_length >= 4U) {
        source_port = (uint16_t)(((uint16_t)view.transport[0] << 8) | view.transport[1]);
        destination_port = (uint16_t)(((uint16_t)view.transport[2] << 8) | view.transport[3]);
    }

    if (fprintf(log->stream, "%lld.%06ld %s %s:%u -> %s:%u payload=%zu hex=",
                (long long)packet->timestamp.tv_sec,
                (long)packet->timestamp.tv_usec,
                protocol_name(view.protocol), source, source_port,
                destination, destination_port, view.payload_length) < 0) {
        return false;
    }
    for (size_t index = 0U; index < view.payload_length; ++index) {
        if (fprintf(log->stream, "%02x", (unsigned int)view.payload[index]) < 0) {
            return false;
        }
    }
    return fputc('\n', log->stream) != EOF && fflush(log->stream) == 0;
}

bool sn_payload_log_close(struct sn_payload_log *log)
{
    bool success;

    if (log == NULL) {
        return true;
    }
    success = log->stream == NULL || fclose(log->stream) == 0;
    free(log);
    return success;
}
