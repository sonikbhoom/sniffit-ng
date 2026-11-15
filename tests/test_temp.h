#ifndef SNIFFIT_NG_TEST_TEMP_H
#define SNIFFIT_NG_TEST_TEMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

static inline bool sn_test_temp_template(char *path, size_t capacity, const char *name)
{
    const char *directory = getenv("TMPDIR");
    int length;

    if (path == NULL || capacity == 0U || name == NULL || name[0] == '\0') {
        return false;
    }
    if (directory == NULL || directory[0] == '\0') {
        directory = "/tmp";
    }
    length = snprintf(path, capacity, "%s/%s-XXXXXX", directory, name);
    return length > 0 && (size_t)length < capacity;
}

#endif