# Copilot instructions for Sniffit NG

## Build, test, and lint

Run commands from the project root. The project requires a C17 compiler, CMake 3.16+, pkg-config, and development files for libpcap, ncursesw, and libcurl.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

To run one test, use its CTest name; for example:

```sh
ctest --test-dir build -R '^packet_parser$' --output-on-failure
```

List the registered test names with `ctest --test-dir build -N`. Tests are separate executables under `tests/`, registered in the root `CMakeLists.txt`; the Linux live-loopback test and privilege-drop test may report skipped when the required capability is unavailable.

CI also exercises an AddressSanitizer/UBSan build:

```sh
cmake -S . -B build/sanitizers -G Ninja -DSNIFFIT_NG_ENABLE_SANITIZERS=ON
cmake --build build/sanitizers --parallel 2
ctest --test-dir build/sanitizers --output-on-failure
```

The optional packet-parser fuzzer requires Clang with libFuzzer:

```sh
cmake -S . -B build/fuzz -G Ninja -DCMAKE_C_COMPILER=clang \
  -DSNIFFIT_NG_BUILD_PACKET_FUZZER=ON -DBUILD_TESTING=OFF
cmake --build build/fuzz --target fuzz_packet
./build/fuzz/fuzz_packet -runs=20000 -max_len=2048
```

There is no separate lint target or lint workflow. GCC and Clang builds enable `-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes`.

## Architecture

- `src/main.c` owns command-line orchestration and connects config, capture, monitoring, optional recording, privilege handling, and the terminal UI.
- `src/capture.c` wraps libpcap for offline and live sources and reports the supported link type. `src/packet.c` validates Ethernet or Linux cooked v1 (SLL) framing and IPv4/transport headers, then exposes a `sn_packet_view` to later stages.
- `src/monitor.c` processes each capture record, maintains counters and flow state, and queues copied flow events for consumers. `src/flow.c` groups packets into direction-aware IPv4 flows, applies bounded retention, and stores bounded decode histories.
- `src/protocol_decode.c` dispatches to the focused `src/decode_*.c` protocol summaries. `src/config.c` validates runtime decoder modes and display options. The curses UI in `src/ui.c` renders monitor events and flow details; keep UI presentation separate from packet parsing and decoding.
- Public module interfaces live in `include/sniffit_ng/`; implementation-only decoder declarations live in `src/`. The root CMake file builds these modules as static libraries and links them into `sniffit-ng`.
- Live capture must drop elevated capture privileges before packet processing/UI work. Payload logging and full-packet recording are separate opt-in paths with their own interactive acknowledgments; do not merge them with the default metadata summaries.

## Codebase-specific conventions

- Keep packet parsing length-bounded. Use the supplied captured length and explicit offsets before reading fields; preserve the distinction between malformed, truncated, and unsupported packets in `enum sn_packet_result`. Packet spans are borrowed from libpcap and must not outlive the next capture read; copy data into an explicitly bounded record only when history is required.
- Decoder functions write into caller-provided buffers and report success/failure. Keep summaries short, bounded, and sanitized; protocol payloads are not TCP-reassembled. A custom decoder is compiled into the process, is not sandboxed, and is dispatched only when `tainted_extensions` is enabled.
- Retain fixed capacities and limits for flow tables, detail histories, and decoded output. Do not turn bounded metadata summaries into implicit payload display or persistence.
- UDP DNS flow identity deliberately ignores the client ephemeral port and keeps at most 32 decoded messages for five minutes of idle time; preserve chronological request/response ordering and the bounded-history contract.
- Config parsing is intentionally strict. New options should be validated, reject malformed values and duplicate settings consistently, and preserve fail-closed acknowledgment checks for sensitive features.
- Follow the existing C interface pattern: public declarations in `include/sniffit_ng/`, `sn_`-prefixed APIs, matching implementation modules in `src/`, and focused CTest executables registered in `CMakeLists.txt`.
- Use the README's authorization and privacy boundaries when changing capture, payload inspection, decoder extensions, or recording behavior. In particular, keep inspection/recording disabled unless explicitly opted into and acknowledged.

## Priority-port log

`src/priority_log.c` writes JSONL for inbound packets to `ui_priority` ports when `priority_log` (absolute path, off by default) is set; `main.c` wires it into `poll_live_capture` and `replay_pcap`. The file is opened 0600 with `O_NOFOLLOW` and a write failure stops capture. `scripts/sniffit-ng-scanmap.py` is the offline analyzer; its tests (`tests/scanmap`, ctest `scanmap_tool`) must never touch the network.
