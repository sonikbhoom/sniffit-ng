#ifndef SNIFFIT_NG_PCAP_WRITER_H
#define SNIFFIT_NG_PCAP_WRITER_H

#include "sniffit_ng/capture.h"

#include <stdbool.h>
#include <stddef.h>

struct sn_pcap_writer;

struct sn_pcap_writer *sn_pcap_writer_open(
    const char *path,
    enum sn_packet_link_type link_type,
    char *error_buffer,
    size_t error_buffer_size);

bool sn_pcap_writer_write(struct sn_pcap_writer *writer,
                          const struct sn_capture_packet *packet);

bool sn_pcap_writer_close(struct sn_pcap_writer *writer);

#endif
