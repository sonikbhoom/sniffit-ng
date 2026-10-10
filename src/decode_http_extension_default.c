#include "sniffit_ng/http_decode_extension.h"

bool sn_http_decode_extension(const uint8_t *payload,
                              size_t payload_length,
                              char *output,
                              size_t output_capacity)
{
    (void)payload;
    (void)payload_length;
    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    return false;
}
