#ifndef SNIFFIT_NG_HTTP_DECODE_EXTENSION_H
#define SNIFFIT_NG_HTTP_DECODE_EXTENSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SN_HTTP_EXTENSION_OUTPUT_CAPACITY 64U

/*
 * Optional build-time hook for one bounded HTTP-over-TCP payload span. It is
 * called only when the operator enables tainted_extensions. The default
 * implementation returns false and emits no output.
 */
bool sn_http_decode_extension(const uint8_t *payload,
                              size_t payload_length,
                              char *output,
                              size_t output_capacity);

#endif
