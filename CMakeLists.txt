cmake_minimum_required(VERSION 3.16)
project(sniffit_ng VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include(CTest)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
pkg_check_modules(NCURSESW REQUIRED IMPORTED_TARGET ncursesw)
option(SNIFFIT_NG_ENABLE_SANITIZERS "Build with AddressSanitizer and UBSan" OFF)

add_library(sniffit_packet STATIC src/packet.c)
target_include_directories(sniffit_packet PUBLIC include)

add_library(sniffit_flow STATIC src/flow.c)
target_include_directories(sniffit_flow PUBLIC include)
target_link_libraries(sniffit_flow PUBLIC sniffit_packet)

add_library(sniffit_capture STATIC src/capture.c)
target_include_directories(sniffit_capture PUBLIC include)
target_link_libraries(sniffit_capture PUBLIC PkgConfig::PCAP)
target_compile_definitions(sniffit_capture PRIVATE _DEFAULT_SOURCE)

add_library(sniffit_monitor STATIC src/monitor.c)
target_include_directories(sniffit_monitor PUBLIC include)
target_link_libraries(sniffit_monitor PUBLIC sniffit_capture sniffit_flow)

add_library(sniffit_payload_log STATIC src/payload_log.c)
target_include_directories(sniffit_payload_log PUBLIC include)
target_link_libraries(sniffit_payload_log PUBLIC sniffit_packet)
target_compile_definitions(sniffit_payload_log PRIVATE _DEFAULT_SOURCE)

add_library(sniffit_privilege STATIC src/privilege.c)
target_include_directories(sniffit_privilege PUBLIC include)

add_library(sniffit_config STATIC src/config.c)
target_include_directories(sniffit_config PUBLIC include)

add_library(sniffit_ui STATIC src/ui.c)
target_include_directories(sniffit_ui PUBLIC include)
target_sources(sniffit_ui PRIVATE src/ui_window.c)
target_link_libraries(sniffit_ui PUBLIC sniffit_monitor PkgConfig::NCURSESW)

add_executable(sniffit-ng src/main.c)
target_link_libraries(sniffit-ng PRIVATE
    sniffit_ui sniffit_payload_log sniffit_privilege sniffit_config
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sniffit_packet PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_flow PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    )
    target_compile_options(sniffit_capture PRIVATE
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

    add_executable(test_ui_window tests/test_ui_window.c src/ui_window.c)
    target_include_directories(test_ui_window PRIVATE include)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_ui_window PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME ui_window COMMAND test_ui_window)

    add_executable(test_config tests/test_config.c)
    target_link_libraries(test_config PRIVATE sniffit_config)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_config PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
        )
    endif()
    add_test(NAME config_validation COMMAND test_config)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND SNIFFIT_NG_ENABLE_SANITIZERS)
    foreach(target sniffit_packet sniffit_flow sniffit_capture sniffit_monitor sniffit_payload_log sniffit_privilege sniffit_config sniffit_ui sniffit-ng test_ui_window test_config)
        target_compile_options(${target} PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PUBLIC -fsanitize=address,undefined)
    endforeach()
endif()
