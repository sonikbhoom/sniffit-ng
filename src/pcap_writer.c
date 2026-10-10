#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/pcap_writer.h"

#include <errno.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct sn_pcap_writer {
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    enum sn_packet_link_type link_type;
};

static void copy_error(char *destination, size_t capacity, const char *message)
{
    if (destination != NULL && capacity > 0U) {
        (void)snprintf(destination, capacity, "%s", message != NULL ? message : "");
    }
}

static int datalink_type(enum sn_packet_link_type link_type)
{
    switch (link_type) {
    case SN_PACKET_LINK_ETHERNET:
        return DLT_EN10MB;
    case SN_PACKET_LINK_LINUX_SLL:
#ifdef DLT_LINUX_SLL
        return DLT_LINUX_SLL;
#else
        return -1;
#endif
    default:
        return -1;
    }
}

struct sn_pcap_writer *sn_pcap_writer_open(
    const char *path,
    enum sn_packet_link_type link_type,
    char *error_buffer,
    size_t error_buffer_size)
{
    struct sn_pcap_writer *writer;
    int descriptor;
    int datalink;
    FILE *stream;
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    char pcap_error[PCAP_ERRBUF_SIZE] = {0};

    if (path == NULL || path[0] == '\0') {
        copy_error(error_buffer, error_buffer_size, "pcap output path must not be empty");
        return NULL;
    }
    datalink = datalink_type(link_type);
    if (datalink < 0) {
        copy_error(error_buffer, error_buffer_size, "unsupported link type for pcap output");
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
    stream = fdopen(descriptor, "wb");
    if (stream == NULL) {
        int saved_errno = errno;
        close(descriptor);
        unlink(path);
        copy_error(error_buffer, error_buffer_size, strerror(saved_errno));
        return NULL;
    }
    dead_capture = pcap_open_dead(datalink, 65535);
    if (dead_capture == NULL) {
        fclose(stream);
        unlink(path);
        copy_error(error_buffer, error_buffer_size, "cannot create pcap output header");
        return NULL;
    }
    dumper = pcap_dump_fopen(dead_capture, stream);
    if (dumper == NULL) {
        (void)snprintf(pcap_error, sizeof(pcap_error), "%s", pcap_geterr(dead_capture));
        pcap_close(dead_capture);
        fclose(stream);
        unlink(path);
        copy_error(error_buffer, error_buffer_size, pcap_error);
        return NULL;
    }
    writer = calloc(1U, sizeof(*writer));
    if (writer == NULL) {
        pcap_dump_close(dumper);
        pcap_close(dead_capture);
        unlink(path);
        copy_error(error_buffer, error_buffer_size, "out of memory opening pcap output");
        return NULL;
    }
    writer->dead_capture = dead_capture;
    writer->dumper = dumper;
    writer->link_type = link_type;
    copy_error(error_buffer, error_buffer_size, "");
    return writer;
}

bool sn_pcap_writer_write(struct sn_pcap_writer *writer,
                          const struct sn_capture_packet *packet)
{
    struct pcap_pkthdr header;

    if (writer == NULL || writer->dumper == NULL || packet == NULL ||
        packet->data == NULL || packet->link_type != writer->link_type ||
        packet->captured_length > UINT32_MAX || packet->wire_length > UINT32_MAX ||
        packet->timestamp.tv_sec < 0 || packet->timestamp.tv_usec < 0 ||
        packet->timestamp.tv_usec >= 1000000) {
        return false;
    }
    header.ts = packet->timestamp;
    header.caplen = (bpf_u_int32)packet->captured_length;
    header.len = (bpf_u_int32)packet->wire_length;
    pcap_dump((u_char *)writer->dumper, &header, packet->data);
    return pcap_dump_flush(writer->dumper) == 0;
}

bool sn_pcap_writer_close(struct sn_pcap_writer *writer)
{
    FILE *stream;
    bool success = true;

    if (writer == NULL) {
        return true;
    }
    if (writer->dumper != NULL) {
        stream = pcap_dump_file(writer->dumper);
        if (pcap_dump_flush(writer->dumper) != 0 ||
            (stream != NULL && fsync(fileno(stream)) != 0)) {
            success = false;
        }
        pcap_dump_close(writer->dumper);
    }
    if (writer->dead_capture != NULL) {
        pcap_close(writer->dead_capture);
    }
    free(writer);
    return success;
}
