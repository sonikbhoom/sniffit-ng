# Sniffit NG Development Plan

## Goal

Build a separate, defensive C successor to Sniffit that preserves its useful curses workflow while removing the legacy memory-safety, privilege, and reliability problems. Keep `/home/sonik/src/sniffit` unchanged by successor work.

## Evidence Driving the Work

The source review found packet parsing that does not receive or check libpcap's captured length, packet-declared lengths copied into fixed 5,000-byte plugin buffers, and an uninitialized description passed to `strcpy` in basic `-i` mode. Other high-risk paths include unchecked curses/config input, unsafe DNS compression parsing, unbounded ICMP code table indexing, root-owned logging/helper behavior, signal handlers that call curses, and a connection-list teardown leak. The prior checksum byte-order correction is a narrow legacy fix; it is not the successor's parser design.

## Design Principles

- Use C17 and small modules with explicit ownership and narrow interfaces: capture, packet parsing, filtering/configuration, flow state, output/logging, and curses UI.
- Pass every parser a byte pointer and captured length. Use checked offsets and lengths; never use packet declarations as proof that bytes are captured.
- Parse bytes without unaligned structure casts. Represent packet fields in host order or byte arrays with documented conversions.
- Keep the UI on one event loop. Deliver capture events through a bounded queue; do not call curses from signal handlers or share mutable UI state across processes.
- Keep policy independent of low-level capture and terminal details. In C, use small structs and function interfaces where they provide real boundaries; avoid a pattern or abstraction quota.
- Leave the legacy source intact and use offline fixtures/local test traffic for development.

## Delivery Stages

1. **Characterize parity:** Record legacy options, config behavior, interface layout/key bindings, live/offline capture, filters, connection counters/details, logging, plugins, and packet generation. Mark unsafe or incompatible behavior explicitly.
2. **Bootstrap `sniffit-ng`:** Maintain a standalone build, tests, and documentation. Start with a pure-C parser library so its safety can be tested without privileges, libpcap, or curses.
3. **Safe packet model:** Parse supported link framing and IPv4/TCP/UDP/ICMP using captured-span checks. Validate version, IHL, total length, and transport lengths. Expose payload only as a bounded view. Compute checksum validity without rejecting captures solely because of NIC checksum offload.
4. **Capture and flow engine:** Add live and offline libpcap sources, selected-interface/link-type validation, explicit filters, bounded flow state, and a bounded event queue. Do not require the whole application to remain root; open capture resources with the least required privilege, then drop privileges.
5. **Curses parity:** Recreate the connection list, selection/details, masks, packet-rate panel, and familiar key navigation. The UI consumes model events and never parses packets or owns capture handles.
6. **Output, config, extensions:** Add a validated config parser, restrictive file creation, bounded protocol decoders, and regression fixtures. Prefer built-in bounded decoders over native in-process plugins; evaluate isolated extensions only if there is a concrete need.
7. **Hardening and release:** Run compiler warnings/static analysis, ASan/UBSan, parser fuzzing, offline replay tests, and pseudo-terminal UI tests. Document platform support, permissions, threat model, migration limits, and any parity gaps.

## Inspection Gates

Before starting a stage, state its bounded deliverable, prerequisites, and a pass/fail check. If a required dependency, permission, or test fixture is unavailable, mark the stage blocked or partially verified rather than claiming completion.

After each stage, inspect the changed interfaces and tests against the stage's acceptance criteria. Run the narrowest test first, then the full sanitizer suite when relevant. Record failures and repair them before starting another feature slice.

**Capture gate before further curses work:** A generated offline pcap must traverse libpcap, the bounded parser, and flow state; tests must assert valid, truncated, malformed, and end-of-file outcomes using both `caplen` and wire length. A local live-capture probe may generate only its own loopback UDP packet. If opening loopback capture is denied, mark that test skipped with the exact permission reason; do not switch to third-party traffic or silently weaken the check. No further curses implementation proceeds until the offline end-to-end gate passes and the loopback result is recorded.

At each inspection checkpoint, report: deliverable completed, exact command/test result, environmental limitations, and the next achievable stage. Keep live capture, privilege separation, and UI changes as separate reviewable slices.

## Current Inspection Record

- **Offline capture pipeline:** Passed with ASan/UBSan. The generated pcap traversed libpcap, the bounded parser, and flow state; valid, truncated (`caplen < wire length`), malformed, and EOF outcomes were asserted.
- **Live loopback capture:** The post-drop test now waits on libpcap's selectable fd and uses the permitted-only `CAP_NET_RAW` path. A non-sanitized probe with temporary `cap_net_raw+p` passed after opening pcap, dropping capabilities, and capturing its own loopback UDP packet. The regular ASan/UBSan run skips live pcap because the test runner lacks `CAP_NET_RAW`.
- **Linux cooked capture and live NTP:** The user confirmed live capture on `ppp0` (libpcap DLT_LINUX_SLL). `ntpdate -4 -q time.nrc.ca` succeeded against `132.246.11.227` at stratum 2; the curses detail pane showed one request/reply pair and decoded NTPv4 client/server metadata, including server precision `-25` and reference ID `84f60be9`.
- **Gate status:** Offline and post-drop loopback capture gates passed. The user confirmed the live curses application now renders successfully with the capability-backed capture path. This closes the initial live UI bring-up gate; remaining parity interactions and longer-running capture behavior stay on the feature checklist.
- **Rate panel:** A deterministic three-second packet/byte sampler is implemented and unit-tested. The user confirmed the live rate display check is complete; the temporary file capability was removed afterward.
- **ICMP Enter details:** A right-side pane preserves the flow list on the left. Echo request/reply type, direction, identifier, sequence, and up to 256-byte hex/ASCII records append to a scrolling history as packets arrive; up to 16 records/flow are retained in memory, with longer payloads marked truncated and their original size shown. The pane does not repaint on idle polls; navigation keys switch flows, and other keys close it. Config acknowledgment gates all payload retention; no payload is written to disk by this feature.
- **Live inspection updates:** The detail pane now continues to refresh while capture runs, including new flows and updated counters. Selection remains tied to flow identity as sorting changes, and arrow navigation changes the inspected flow. A PTY regression covers these behaviors.
- **Interface context:** Live mode shows the interface and local IPv4 in the title. External IPv4 lookup is default-off and makes one HTTPS request to ifconfig.io only when explicitly enabled for an RFC 1918 interface. The request has not been manually exercised; no external request is part of tests.
- **Local address cue:** When terminal colors are available, the selected interface's IPv4 and matching flow-address text use muted green. SSH/Telnet priority sessions remain muted red outside that address span. The selected row retains the standard reverse-video focus treatment without session/local color, avoiding color flicker during navigation; 256-color terminals receive muted palette shades, with basic-color fallback elsewhere.
- **README screenshots:** Redacted monitor and inspection screenshots are linked in the README. Unredacted originals are ignored by Git.
- **SSH/Telnet emphasis:** TCP sessions involving port 22 or 23 are highlighted in red and sorted to the top, regardless of direction.
- **Current test status:** The non-sanitized `build/live` suite passed 18 tests; live loopback capture skipped because `CAP_NET_RAW` is not permitted. The last sanitizer-enabled run still crashed in `pcap_dump` while creating fixtures for `capture_offline` and `capture_pipeline`.

## Initial Feature Policy

- Preserve authorized live monitoring, offline pcap replay, filters, counters, connection summaries/details, and conventional logging.
- Keep payload display user-selected and in-memory by default. Do not automatically identify or extract credentials.
- Preserve packet generation only as a separately enabled diagnostic feature, with an explicit startup warning/confirmation and documentation restricting use to authorized test networks.
- Treat legacy config/CLI compatibility as a migration aid, not as permission to preserve unsafe parsing or ambiguous semantics.

## Approval Boundary

Payload logging is off by default and will not be enabled by a config file or remembered preference. The run-time `--payload-logging` switch enables persistent payload capture only for that invocation; `--payload-log PATH` selects an alternate output path. When supplied, the program displays an ethics/privacy warning covering authorization, consent, data minimization, secure storage, and retention, then requires the operator to type exactly `I ACKNOWLEDGE THE PRIVACY AND AUTHORIZATION RISKS` on `/dev/tty` before capture starts. Declining or running without a controlling terminal fails closed; there is no silent or unattended acknowledgment bypass. The output file is created exclusively with mode `0600`, and existing files/symlinks are rejected. The UI visibly indicates when payload logging was enabled for the replay. Tests verify the exact acknowledgment, fail-closed behavior, permissions, no-overwrite policy, and hex-only payload encoding.

ICMP Echo payload inspection is a distinct, in-memory-only feature. It is disabled by default and requires either `--inspect-payloads` or `inspect_payloads = true` in config, plus the exact active comment `## User has acknowledged to behave ethically and inspect only authorized traffic.` in the loaded config. This persisted marker avoids repeating a prompt but does not enable payload logging. When enabled, up to 16 recent ICMP Echo records per flow are retained, each with at most 256 payload bytes; larger samples are truncated and their original length is preserved for display. Other protocol payloads are not retained for this detail view. Printable text is sanitized before display. Disabling the setting clears retained sample bytes.

Packet generation will also be off by default and separately gated by an explicit command-line option plus an acknowledgment before sending. No stealth, evasion, or third-party traffic testing is in scope.

The user has explicitly authorized development and testing of live capture against self-generated loopback traffic. This authorization does not extend to unrelated hosts or networks; tests must send and inspect only their own localhost probes.

## Acceptance Criteria

- Malformed, truncated, or oversized packets never cause out-of-bounds reads/writes; parser APIs cannot read beyond captured bytes.
- Parser unit tests and fuzz targets cover boundary lengths, bad offsets, VLAN framing, fragments, and transport headers.
- No curses operation runs in an asynchronous signal handler, and capture-to-UI communication is bounded.
- Legacy interaction goals have a documented parity checklist; unsafe behavior is replaced with a deliberate and documented safer equivalent.
- Payload persistence and packet generation remain disabled unless explicitly requested and acknowledged at runtime.
- ICMP payload display defaults off, is bounded to in-memory Echo samples, and requires the recorded config acknowledgment; persistent logging remains separately gated.
- The independent project builds and its non-privileged tests pass without touching the legacy tree.

## Milestone Checkpoint: 2026-10-10

- **Publication choice:** Public repository, no license file for now. Public visibility does not grant reuse rights; revisit licensing before inviting contributions or advertising reuse.
- The isolated `sniffit-ng` project has a safe Ethernet/IPv4 parser, bounded TCP/UDP/ICMP flow state, offline and live libpcap sources, a bounded monitor event queue, an initial curses workflow, and fail-closed acknowledged payload logging.
- The non-sanitized `cap_net_raw+p` loopback test passed after privilege drop. The user confirmed the live curses screen and three-second rate display. The sanitizer suite passes; its live test is intentionally skipped when run without `CAP_NET_RAW`.
- Authorized LAN ping: `razorback` resolved to `192.168.1.6`; eight ICMP echoes sent via `enp0s31f6` succeeded with 0% loss while the live monitor was running, and the user confirmed the GUI check worked. No broader LAN scan was performed.
- ICMP detail MVP: Enter now shows ICMP Echo request/reply type, identifier, sequence, and sanitized payload text when the config-backed inspection acknowledgment is active. Samples are limited to 256 bytes each and cleared when inspection is disabled.
- Published Git milestone: public repository `sonikbhoom/sniffit-ng`, branch `main`; local work is pushed. The repository currently has no license, by user choice.

## Project TODO Checklist

This is the canonical list of open project work. Add newly agreed TODOs here under the matching category; remove or check off items when they are completed. Detailed decoder notes and constraints follow the checklist.

### Functional

| Status | Task |
| --- | --- |
| [ ] | Fix the sanitizer crashes in `capture_offline` and `capture_pipeline`, which currently fault in `pcap_dump` during test-pcap creation; then rerun the complete sanitizer suite. |
| [ ] | Manually verify the opt-in external-address lookup and its failure path on an authorized live interface. Keep this a manual check; tests must not contact third-party services. |
| [ ] | Run multi-day soak tests for memory, CPU use, idle-flow expiry, and counter stability before claiming long-running readiness. |
| [ ] | Expand corpus-backed fuzzing, malformed-pcap coverage, and privilege/capability tests across supported Linux environments. |
| [ ] | Add opt-in scanner tracking: `track_scanners = true` logs non-local IPv4 sources observed initiating TCP connections to local port 22 or 23. When tracking is enabled, `investigate_scanners = true` additionally performs bounded, rate-limited, cached WHOIS/geolocation lookups via a documented provider such as ipwhois.io. Define what counts as an attempt, log retention, third-party disclosure, lookup limits/failure behavior, and fixture-only tests; never make automated tests contact the provider. |
| [ ] | Add bounded passive SSH/TCP 22 connection metadata decoding for plaintext identification banners and pre-encryption key-exchange offers. Never attempt to decrypt or infer user-authentication credentials; usernames/passwords are encrypted after key exchange and identity investigation belongs in authorized endpoint authentication logs. |
| [ ] | Define and implement a small, explicitly mapped legacy CLI/config compatibility subset; preserve only validated, safe behavior. |
| [ ] | Add selected summary/dump output modes. Keep payload output disabled unless its existing authorization and privacy gates are satisfied. |
| [ ] | Add CPack generation/content checks to CI and verify install/remove on disposable Debian and RPM systems. RPM transaction testing and native Debian validation remain outstanding. |
| [ ] | Decide on a project license before inviting reuse or distributing packages for general use. |

### Interface Improvements

| Status | Task |
| --- | --- |
| [ ] | Choose ICMP detail row width at startup from the terminal dimensions, using the available pane width while preserving aligned offsets and ASCII; define a readable fallback for narrow terminals. |
| [ ] | Add quick protocol, local/remote port, and selected-flow filters. Clearly distinguish display-only filtering from capture filtering. |
| [ ] | Add a focus mode for the selected flow or either endpoint host, with a shortcut to apply and clear focus; keep it distinct from source/destination filters and cover it with PTY interaction tests. |
| [x] | Highlight TCP sessions involving port 22 or 23 in red and sort them to the top, regardless of traffic direction. |

### Protocol Decoding Features

| Status | Task |
| --- | --- |
| [ ] | Add bounded IPv6 parsing, then implement ICMPv6/Neighbor Discovery, DHCPv6, OSPFv3, and RIPng with malformed and truncated fixtures. |
| [ ] | Add non-IP Ethernet/link-layer parsing for ARP, LLDP/CDP, STP/RSTP, and LACP before enabling their placeholder decoders. |
| [ ] | Implement the remaining routing and gateway protocols: BGP, OSPFv2, IS-IS, RIP, HSRP, and GLBP, with their framing and parser prerequisites. |
| [ ] | Implement bounded MPLS, GRE, IP-in-IP, VXLAN, and Geneve decoding/inner-frame dispatch with recursion and size limits. |
| [ ] | Decide whether bounded TCP stream reassembly is in scope for packet-split protocol messages; if implemented, define per-flow memory/time limits and add adversarial fixtures. |

### Protocol Decoder Backlog

The capture/parser foundation is currently Ethernet plus IPv4. Prioritize decoders that fit that foundation first, and treat IPv6 or other link types as explicit prerequisite work rather than pretending their packets are already supported.

**Next on current Ethernet/IPv4 path:**

- **HTTP/1.x over TCP:** Implemented for packet-local start lines on ports 80, 8000, and 8080. Summaries include request method/validated Host or response status and allowlisted Server/Content-Type/Content-Length; paths, cookies, authorization headers, and bodies are omitted. TCP stream reassembly is not implemented, so split start lines may be missed. `SNIFFIT_NG_CUSTOM_HTTP_DECODER_SOURCE` is an explicit build-time analyst hook; default implementation is inert, receives one bounded segment, and its output is constrained to printable ASCII.
- **DNS (UDP and TCP):** Implemented in `src/decode_dns.c`, dispatched on port 53. Flow details show labeled request/response summaries with transaction ID, opcode/status, flags, the first question, section counts, and a typed preview of the first answer (A/AAAA, name records, MX, SRV, SOA). TXT and unknown RDATA contents are hidden; all declared resource-record sections are bounds-checked. Compression pointers must be backward, and traversals are bounded. TCP uses packet-local length framing; split messages/reassembly are not supported.
- **DHCPv4 / BOOTP (UDP):** Implemented in `src/decode_dhcp4.c` on UDP ports 67/68. Reports BOOTP operation or DHCP message type, transaction ID, hardware type/address, lease duration, and option count. Option iteration is bounded; arbitrary option values are not shown. Tests cover Discover, Offer, BOOTP, and malformed option lengths.
- **NTP (UDP):** Implemented in `src/decode_ntp.c` and dispatched from UDP port 123. It reports mode, version, leap indicator, stratum, poll/precision, and a hex reference identifier; timestamps are omitted. Focused tests cover valid, short, unsupported-mode, and small-output cases.
- **TLS over TCP:** Implemented for packet-local TLS records on common TLS TCP ports. Summaries include record version/type and handshake type/length only; SNI, certificates, and record contents are not decoded. No TCP stream reassembly.
- **QUIC over UDP:** Implemented on UDP/443. Reports bounded long-header version/type and connection-ID lengths or short-header payload length; IDs and protected payload are omitted.
- **RTP/RTCP over UDP:** Implemented on conventional/dynamic media ports. Reports validated RTP header/sequence/timestamp/SSRC or RTCP type/count/length; media bytes and CSRC IDs are omitted.
- **Syslog over UDP/TCP:** Implemented on port 514. Reports PRI/facility/severity and message length; message text is hidden.
- **RADIUS and TACACS+:** Implemented on common ports. Reports RADIUS code/id/declared length/attribute count and TACACS+ type/version/sequence/flags/body length; attribute and authentication data are omitted.

**After adding IPv6 parsing:**

- **ICMPv6 and Neighbor Discovery:** echo/error types plus bounded Router Solicitation/Advertisement, Neighbor Solicitation/Advertisement, and Redirect metadata; validate extension-header and option lengths.
- **DHCPv6:** message type, transaction ID, relay depth, and option codes/lengths with strict nesting and size limits.
- **OSPFv3 and RIPng:** routing-control message type, router/area identifiers, and bounded entry counts; do not infer routes from malformed or partial advertisements.

**After adding link-layer and routing protocol support:**

- **ARP:** request/reply, sender/target protocol addresses, and operation; requires an Ethernet/ARP parser path outside IPv4.
- **LLDP and optionally CDP:** chassis/port identifiers, TTL, and bounded TLV summaries; CDP is vendor-specific and should remain optional.
- **STP/RSTP and LACP:** bridge/root identifiers, port/state, actor/partner state, and bounded control TLVs; requires non-IP Ethernet protocol dispatch.
- **BGP:** message type/length and safe OPEN/KEEPALIVE/NOTIFICATION/UPDATE summaries; later expose bounded AS-path/prefix counts only after IPv4/IPv6 NLRI parsing is tested.
- **OSPFv2, IS-IS, and RIP:** control-message type, identifiers, and bounded adjacency/route-entry counts; IS-IS requires its own link-layer framing and must not be forced through IPv4 parsing.
- **HSRP/GLBP:** version, message/state, group/virtual-router ID, and priority; keep vendor-specific field handling isolated.
- **MPLS, GRE, IP-in-IP, VXLAN, and Geneve:** bounded encapsulation labels/keys/VNI and inner-frame dispatch, with recursion-depth and total-byte limits to prevent tunnel nesting abuse.

Each remaining backlog entry has an isolated placeholder source module under `src/decode_*.c`. These stubs are compiled but deliberately not called by the active dispatcher; they return "not decoded" and do not claim protocol support. Replace a stub only when its parser prerequisites and focused malformed/truncated fixtures are ready.

**Cross-cutting requirements:** Keep decoders in protocol-specific modules behind a dispatcher; expose decoder capability/status separately from payload-inspection consent; never let decoder output affect packet acceptance or flow accounting. Add IPv6, Ethernet-II protocol dispatch, and any required DLT/link-type support before claiming coverage for protocols that depend on them. Do not send probes to discover protocol support; use generated fixtures and authorized local traffic only.
