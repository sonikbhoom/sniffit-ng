#ifndef SNIFFIT_NG_PRIVILEGE_H
#define SNIFFIT_NG_PRIVILEGE_H

#include <stdbool.h>
#include <stddef.h>

bool sn_enable_capture_capability(char *error_buffer, size_t error_buffer_size);
bool sn_drop_privileges_to_real_user(char *error_buffer, size_t error_buffer_size);

#endif
