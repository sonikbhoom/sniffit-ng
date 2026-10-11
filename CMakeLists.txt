cmake_minimum_required(VERSION 3.16)
project(sniffit_ng VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include(CTest)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
pkg_check_modules(NCURSESW REQUIRED IMPORTED_TARGET ncursesw)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
option(SNIFFIT_NG_ENABLE_SANITIZERS "Build with AddressSanitizer and UBSan" OFF)
option(SNIFFIT_NG_BUILD_PACKET_FUZZER "Build the Clang/libFuzzer Ethernet/SLL packet parser target" OFF)
set(SNIFFIT_NG_CUSTOM_HTTP_DECODER_SOURCE "" CACHE FILEPATH
    "Optional user-supplied HTTP metadata extension source (disabled by default)")

add_library(sniffit_packet STATIC src/packet.c)
target_include_directories(sniffit_packet PUBLIC include)

if(SNIFFIT_NG_BUILD_PACKET_FUZZER)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "SNIFFIT_NG_BUILD_PACKET_FUZZER requires Clang with libFuzzer")
    endif()
    add_executable(fuzz_packet tests/fuzz_packet.c src/packet.c)
    target_include_directories(fuzz_packet PRIVATE include)
    target_compile_options(fuzz_packet PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer
    )
    target_link_options(fuzz_packet PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

add_library(sniffit_decode STATIC
    src/protocol_decode.c
    src/decode_icmp.c
    src/decode_tcp.c
    src/decode_http.c
    src/decode_udp.c
    src/decode_igmp.c
    src/decode_snmp.c
    src/decode_vrrp.c
    src/decode_dns.c
    src/decode_dhcp4.c
    src/decode_ntp.c
    src/decode_tls.c
    src/decode_quic.c
    src/decode_rtp.c
    src/decode_rtcp.c
    src/decode_syslog.c
    src/decode_radius.c
    src/decode_tacacs.c
    src/decode_icmpv6.c
    src/decode_ndp.c
    src/decode_dhcp6.c
    src/decode_ospf3.c
    src/decode_ripng.c
    src/decode_arp.c
    src/decode_lldp.c
    src/decode_cdp.c
    src/decode_stp.c
    src/decode_rstp.c
    src/decode_lacp.c
    src/decode_bgp.c
    src/decode_ospf2.c
    src/decode_isis.c
    src/decode_rip.c
    src/decode_hsrp.c
    src/decode_glbp.c
    src/decode_mpls.c
    src/decode_gre.c
    src/decode_ipip.c
    src/decode_vxlan.c
    src/decode_geneve.c
)
if(SNIFFIT_NG_CUSTOM_HTTP_DECODER_SOURCE)
    target_sources(sniffit_decode PRIVATE "${SNIFFIT_NG_CUSTOM_HTTP_DECODER_SOURCE}")
else()
    target_sources(sniffit_decode PRIVATE src/decode_http_extension_default.c)
endif()
target_include_directories(sniffit_decode PUBLIC include PRIVATE src)
target_link_libraries(sniffit_decode PUBLIC sniffit_packet)

add_library(sniffit_flow STATIC src/flow.c)
target_include_directories(sniffit_flow PUBLIC include)
target_link_libraries(sniffit_flow PUBLIC sniffit_packet sniffit_decode)

add_library(sniffit_capture STATIC src/capture.c)
target_include_directories(sniffit_capture PUBLIC include)
target_link_libraries(sniffit_capture PUBLIC PkgConfig::PCAP)
target_compile_definitions(sniffit_capture PRIVATE _DEFAULT_SOURCE)

add_library(sniffit_pcap_writer STATIC src/pcap_writer.c)
target_include_directories(sniffit_pcap_writer PUBLIC include)
target_link_libraries(sniffit_pcap_writer PUBLIC PkgConfig::PCAP)
target_compile_definitions(sniffit_pcap_writer PRIVATE _DEFAULT_SOURCE)

add_library(sniffit_monitor STATIC src/monitor.c)
target_include_directories(sniffit_monitor PUBLIC include)
target_link_libraries(sniffit_monitor PUBLIC sniffit_capture sniffit_flow)

add_library(sniffit_payload_log STATIC src/payload_log.c)
target_include_directories(sniffit_payload_log PUBLIC include)
target_link_libraries(sniffit_payload_log PUBLIC sniffit_packet)
target_compile_definitions(sniffit_payload_log PRIVATE _DEFAULT_SOURCE)

add_library(sniffit_privilege STATIC src/privilege.c)
target_include_directories(sniffit_privilege PUBLIC include)

add_library(sniffit_network_info STATIC src/network_info.c)
target_include_directories(sniffit_network_info PUBLIC include)
target_compile_definitions(sniffit_network_info PRIVATE _DEFAULT_SOURCE)
target_link_libraries(sniffit_network_info PUBLIC PkgConfig::CURL)

add_library(sniffit_config STATIC src/config.c)
target_include_directories(sniffit_config PUBLIC include)

add_library(sniffit_ui STATIC src/ui.c)
target_include_directories(sniffit_ui PUBLIC include)
target_sources(sniffit_ui PRIVATE src/ui_window.c src/icmp_payload_view.c)
target_link_libraries(sniffit_ui PUBLIC sniffit_monitor PkgConfig::NCURSESW)

add_executable(sniffit-ng src/main.c)
target_link_libraries(sniffit-ng PRIVATE
    sniffit_ui sniffit_payload_log sniffit_pcap_writer sniffit_privilege
    sniffit_network_info sniffit_config
)

install(TARGETS sniffit-ng
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES README.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/sniffit-ng
)
install(FILES sniffit-ng.conf.example
    DESTINATION ${CMAKE_INSTALL_DATADIR}/sniffit-ng
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sniffit_packet PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_flow PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_decode PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_capture PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_pcap_writer PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_monitor PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_payload_log PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_privilege PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_network_info PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_config PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_ui PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit-ng PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
endif()

if(BUILD_TESTING)
    add_executable(test_packet tests/test_packet.c)
    target_link_libraries(test_packet PRIVATE sniffit_packet)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_packet PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME packet_parser COMMAND test_packet)

    add_executable(test_protocol_decode tests/test_protocol_decode.c)
    target_include_directories(test_protocol_decode PRIVATE src)
    target_link_libraries(test_protocol_decode PRIVATE sniffit_decode)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_protocol_decode PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME protocol_decoders COMMAND test_protocol_decode)

    add_executable(test_flow tests/test_flow.c)
    target_link_libraries(test_flow PRIVATE sniffit_flow)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_flow PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME flow_state COMMAND test_flow)

    add_executable(test_capture tests/test_capture.c)
    target_link_libraries(test_capture PRIVATE sniffit_capture PkgConfig::PCAP)
    target_compile_definitions(test_capture PRIVATE _DEFAULT_SOURCE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_capture PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME capture_offline COMMAND test_capture)

    add_executable(test_pcap_writer tests/test_pcap_writer.c)
    target_link_libraries(test_pcap_writer PRIVATE sniffit_pcap_writer sniffit_capture)
    target_compile_definitions(test_pcap_writer PRIVATE _DEFAULT_SOURCE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_pcap_writer PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME pcap_writer COMMAND test_pcap_writer)

    add_executable(test_capture_pipeline tests/test_capture_pipeline.c)
    target_link_libraries(test_capture_pipeline PRIVATE sniffit_monitor PkgConfig::PCAP)
    target_compile_definitions(test_capture_pipeline PRIVATE _DEFAULT_SOURCE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_capture_pipeline PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME capture_pipeline COMMAND test_capture_pipeline)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(test_capture_live tests/test_capture_live.c)
        target_link_libraries(test_capture_live PRIVATE
            sniffit_capture sniffit_packet sniffit_privilege
        )
        target_compile_definitions(test_capture_live PRIVATE _DEFAULT_SOURCE)
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(test_capture_live PRIVATE
                -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
            )
        endif()
        add_test(NAME capture_live_loopback COMMAND test_capture_live)
        set_tests_properties(capture_live_loopback PROPERTIES
            SKIP_RETURN_CODE 77
            TIMEOUT 10
        )
    endif()

    add_executable(test_monitor tests/test_monitor.c)
    target_link_libraries(test_monitor PRIVATE sniffit_monitor)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_monitor PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME monitor_pipeline COMMAND test_monitor)

    add_executable(test_payload_log tests/test_payload_log.c)
    target_link_libraries(test_payload_log PRIVATE sniffit_payload_log)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_payload_log PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME payload_logging COMMAND test_payload_log)

    add_executable(test_privilege tests/test_privilege.c)
    target_link_libraries(test_privilege PRIVATE sniffit_privilege)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_privilege PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME privilege_drop COMMAND test_privilege)
    set_tests_properties(privilege_drop PROPERTIES SKIP_RETURN_CODE 77)

    add_test(NAME cli_help COMMAND sniffit-ng --help)
    add_test(NAME cli_version COMMAND sniffit-ng --version)
    add_test(NAME cli_inspection_requires_ack
        COMMAND sniffit-ng --read-pcap /dev/null --inspect-payloads)
    set_tests_properties(cli_inspection_requires_ack PROPERTIES WILL_FAIL TRUE)
    add_test(NAME cli_write_pcap_requires_source
        COMMAND sniffit-ng --write-pcap ${CMAKE_CURRENT_BINARY_DIR}/unused-output.pcap)
    set_tests_properties(cli_write_pcap_requires_source PROPERTIES WILL_FAIL TRUE)

    add_executable(test_ui_window tests/test_ui_window.c src/ui_window.c)
    target_include_directories(test_ui_window PRIVATE include)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_ui_window PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME ui_window COMMAND test_ui_window)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        find_library(UTIL_LIBRARY util)
        add_executable(test_ui_pty tests/test_ui_pty.c)
        target_link_libraries(test_ui_pty PRIVATE sniffit_ui ${UTIL_LIBRARY})
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(test_ui_pty PRIVATE
                -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
            )
        endif()
        add_test(NAME ui_curses_pty COMMAND test_ui_pty)
        set_tests_properties(ui_curses_pty PROPERTIES TIMEOUT 15)
    endif()

    add_executable(test_config tests/test_config.c)
    target_link_libraries(test_config PRIVATE sniffit_config)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_config PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME config_validation COMMAND test_config)

    add_executable(test_network_info tests/test_network_info.c)
    target_link_libraries(test_network_info PRIVATE sniffit_network_info)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_network_info PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME network_info COMMAND test_network_info)

    add_executable(test_icmp_payload_view
        tests/test_icmp_payload_view.c src/icmp_payload_view.c
    )
    target_include_directories(test_icmp_payload_view PRIVATE include)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_icmp_payload_view PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME icmp_payload_view COMMAND test_icmp_payload_view)
endif()

if(BUILD_TESTING AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    get_property(test_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    foreach(test_target IN LISTS test_targets)
        if(test_target MATCHES "^test_")
            target_compile_options(${test_target} PRIVATE -UNDEBUG)
        endif()
    endforeach()
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND SNIFFIT_NG_ENABLE_SANITIZERS)
    foreach(target sniffit_packet sniffit_decode sniffit_flow sniffit_capture sniffit_pcap_writer sniffit_monitor sniffit_payload_log sniffit_privilege sniffit_network_info sniffit_config sniffit_ui sniffit-ng test_ui_window test_ui_pty test_config test_network_info test_icmp_payload_view test_pcap_writer)
        target_compile_options(${target} PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PUBLIC -fsanitize=address,undefined)
    endforeach()
endif()

set(CPACK_PACKAGE_NAME "sniffit-ng")
set(CPACK_PACKAGE_VENDOR "Sniffit NG contributors")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Defensive network protocol monitor")
set(CPACK_PACKAGE_DESCRIPTION
    "Sniffit NG is a privilege-reduced network monitor with bounded Ethernet/SLL IPv4 parsing and a curses flow viewer.")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "Sniffit NG maintainers")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/sonikbhoom/sniffit-ng")
set(CPACK_PACKAGE_DIRECTORY "${CMAKE_BINARY_DIR}/packages")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CPACK_GENERATOR "RPM;DEB")
    set(CPACK_RPM_PACKAGE_RELEASE "1")
    set(CPACK_RPM_PACKAGE_LICENSE "NOASSERTION")
    set(CPACK_RPM_PACKAGE_AUTOREQPROV ON)
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Sniffit NG maintainers")
    set(CPACK_DEBIAN_PACKAGE_SECTION "net")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libc6, libncursesw6, libtinfo6, libpcap0.8 | libpcap0.8t64, libcurl4 | libcurl4t64")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
else()
    set(CPACK_GENERATOR "TGZ")
endif()

include(CPack)
