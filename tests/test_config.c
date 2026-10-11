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
    assert(!config.show_raw_flows);
    assert(!config.tainted_extensions);
    for (size_t index = 0U; index < SN_DECODER_MODULE_COUNT; ++index) {
        assert(config.decoder_modes[index] == SN_DECODER_SIMPLIFIED);
    }
    assert(unlink(path) == 0);
}

static void test_raw_flow_and_tainted_extension_options(void)
{
    char path[80];
    char error[256] = {0};
    struct sn_app_config config;

    write_config_file(path,
        "show_raw_flows = true\n"
        "tainted_extensions = true\n");
    assert(sn_config_load_file(path, &config, error, sizeof(error)));
    assert(config.show_raw_flows);
    assert(config.tainted_extensions);
    assert(unlink(path) == 0);

    write_config_file(path, "tainted_extensions = maybe\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(strstr(error, "tainted_extensions") != NULL);
    assert(unlink(path) == 0);

    write_config_file(path,
        "show_raw_flows = true\n"
        "show_raw_flows = false\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(unlink(path) == 0);
}

static void test_decoder_modes_are_named_and_validated(void)
{
    char path[80];
    char error[256] = {0};
    struct sn_app_config config;

    write_config_file(path,
        "dns = raw\n"
        "http = simplified\n"
        "telnet = raw\n");
    assert(sn_config_load_file(path, &config, error, sizeof(error)));
    assert(config.decoder_modes[SN_DECODER_DNS] == SN_DECODER_RAW);
    assert(config.decoder_modes[SN_DECODER_HTTP] == SN_DECODER_SIMPLIFIED);
    assert(config.decoder_modes[SN_DECODER_TELNET] == SN_DECODER_RAW);
    assert(unlink(path) == 0);

    write_config_file(path, "dns = detailed\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
    assert(strstr(error, "raw or simplified") != NULL);
    assert(unlink(path) == 0);

    write_config_file(path, "dns = raw\ndns = simplified\n");
    assert(!sn_config_load_file(path, &config, error, sizeof(error)));
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
    test_raw_flow_and_tainted_extension_options();
    test_decoder_modes_are_named_and_validated();
    puts("config tests passed");
    return 0;
}
