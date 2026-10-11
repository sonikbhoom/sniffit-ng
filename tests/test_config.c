#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/config.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_config_file(char *path, const char *contents)
{
    char template[] = "/tmp/sniffit-ng-config-XXXXXX";
    int descriptor = mkstemp(template);
    FILE *stream;

    assert(descriptor >= 0);
    stream = fdopen(descriptor, "w");
    assert(stream != NULL);
    assert(fputs(contents, stream) >= 0);
    assert(fclose(stream) == 0);
    assert(snprintf(path, 80U, "%s", template) > 0);
}

static void test_payload_inspection_requires_recorded_ack(void)
{
    char path[80];
    char error[256] = {0};
    struct sn_app_config config;

    write_config_file(path, "inspect_payloads = true\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(strstr(error, "acknowledgment") != NULL);
    assert(unlink(path) == 0);

    write_config_file(path,
        "inspect_payloads = true\n"
        SN_CONFIG_PAYLOAD_ACK_COMMENT "\n");
    assert(sn_config_load_file(path, &config, error, sizeof(error)));
    assert(config.inspect_payloads);
    assert(config.payload_display_acknowledged);
    assert(unlink(path) == 0);
}

static void test_payload_inspection_defaults_off(void)
{
    char path[80];
    char error[256] = {0};
    struct sn_app_config config;

    write_config_file(path, "inspect_payloads = false\n");
    assert(sn_config_load_file(path, &config, error, sizeof(error)));
    assert(!config.inspect_payloads);
    assert(!config.payload_display_acknowledged);
    assert(!config.resolve_external_addr);
    assert(unlink(path) == 0);
}

static void test_external_address_lookup_is_opt_in(void)
{
    char path[80];
    char error[256] = {0};
    struct sn_app_config config;

    write_config_file(path, "resolve_external_addr = true\n");
    assert(sn_config_load_file(path, &config, error, sizeof(error)));
    assert(config.resolve_external_addr);
    assert(unlink(path) == 0);

    write_config_file(path, "resolve_external_addr = false\n");
    assert(sn_config_load_file(path, &config, error, sizeof(error)));
    assert(!config.resolve_external_addr);
    assert(unlink(path) == 0);

    write_config_file(path, "resolve_external_addr = maybe\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(strstr(error, "resolve_external_addr") != NULL);
    assert(unlink(path) == 0);

    write_config_file(path,
                      "resolve_external_addr = false\n"
                      "resolve_external_addr = true\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(unlink(path) == 0);
}

static void test_unknown_duplicate_and_invalid_values_are_rejected(void)
{
    char path[80];
    char error[256] = {0};
    struct sn_app_config config;

    write_config_file(path, "unknown = true\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(unlink(path) == 0);

    write_config_file(path, "inspect_payloads = maybe\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(unlink(path) == 0);

    write_config_file(path, "inspect_payloads = false\ninspect_payloads = true\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(unlink(path) == 0);
}

int main(void)
{
    test_payload_inspection_requires_recorded_ack();
    test_payload_inspection_defaults_off();
    test_external_address_lookup_is_opt_in();
    test_unknown_duplicate_and_invalid_values_are_rejected();
    puts("config tests passed");
    return 0;
}
