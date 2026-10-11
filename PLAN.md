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
- **ICMP Enter details:** A right-side pane preserves the flow list on the left. Echo request/reply type, direction, identifier, sequence, and 64-byte hex/ASCII records append to a scrolling history as packets arrive; up to 16 records/flow are retained in memory. The pane does not repaint on idle polls and closes on any key. Config acknowledgment gates all payload retention; no payload is written to disk by this feature.

## Initial Feature Policy

- Preserve authorized live monitoring, offline pcap replay, filters, counters, connection summaries/details, and conventional logging.
- Keep payload display user-selected and in-memory by default. Do not automatically identify or extract credentials.
- Preserve packet generation only as a separately enabled diagnostic feature, with an explicit startup warning/confirmation and documentation restricting use to authorized test networks.
- Treat legacy config/CLI compatibility as a migration aid, not as permission to preserve unsafe parsing or ambiguous semantics.

## Approval Boundary

Payload logging is off by default and will not be enabled by a config file or remembered preference. The run-time `--payload-logging` switch enables persistent payload capture only for that invocation; `--payload-log PATH` selects an alternate output path. When supplied, the program displays an ethics/privacy warning covering authorization, consent, data minimization, secure storage, and retention, then requires the operator to type exactly `I ACKNOWLEDGE THE PRIVACY AND AUTHORIZATION RISKS` on `/dev/tty` before capture starts. Declining or running without a controlling terminal fails closed; there is no silent or unattended acknowledgment bypass. The output file is created exclusively with mode `0600`, and existing files/symlinks are rejected. The UI visibly indicates when payload logging was enabled for the replay. Tests verify the exact acknowledgment, fail-closed behavior, permissions, no-overwrite policy, and hex-only payload encoding.

ICMP Echo payload inspection is a distinct, in-memory-only feature. It is disabled by default and requires either `--inspect-payloads` or `inspect_payloads = true` in config, plus the exact active comment `## User has acknowledged to behave ethically and inspect only authorized traffic.` in the loaded config. This persisted marker avoids repeating a prompt but does not enable payload logging. When enabled, up to 16 recent ICMP Echo records per flow are retained, each with at most 64 payload bytes; other protocol payloads are not retained for this detail view. Printable text is sanitized before display. Disabling the setting clears retained sample bytes.

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
- ICMP detail MVP: Enter now shows ICMP Echo request/reply type, identifier, sequence, and sanitized payload text when the config-backed inspection acknowledgment is active. Samples are limited to 64 bytes per flow and cleared when inspection is disabled.
- Published Git milestone: public repository `sonikbhoom/sniffit-ng`, branch `main`; local work is pushed. The repository currently has no license, by user choice.

## Remaining Refactor Work

1. **LAN ping display:** Verified against authorized host `razorback` (`192.168.1.6`) with eight successful pings and live GUI confirmation. No broader LAN scan was performed.
2. **Complete UI parity:** Flow-list scrolling/resize clamping, deterministic protocol/endpoint ordering, bounded TCP/UDP service hints, a split append-only inspection pane, and documented bidirectional host/port mask semantics are implemented with focused tests. Capture polling continues while details are open, and navigation keys switch the inspected flow without closing the pane. The initial list/details/mask/statistics/reset/quit workflow exists but is not full legacy parity.
3. **Configuration and compatibility:** The bounded `inspect_payloads` config and exact ethics-marker validation are implemented. Remaining: add an explicitly mapped legacy CLI/config subset; preserve only validated semantics.
4. **Output modes:** Safe pcap recording is implemented through `--write-pcap FILE` for live or offline capture. It preserves link type, caplen/wire length, and timestamps; creates a new mode-0600 file exclusively; and requires the interactive recording acknowledgment. Remaining: selected summary/dump modes. Keep cleartext payload output disabled unless the runtime acknowledgment policy is satisfied.
5. **Hardening:** An opt-in Clang/libFuzzer target exercises raw and structured Ethernet/SLL IPv4 TCP/UDP/ICMP/IGMP/VRRP frames; a 20,000-run ASan/UBSan smoke pass found no faults. A Linux PTY integration test now exercises the curses list/detail/navigation/close/quit path without live capture. Remaining: sustained corpus-backed fuzzing, a broader malformed-pcap corpus, and privilege/capability tests across supported Linux environments. Ethernet and Linux cooked v1 (SLL) are supported; other link types are rejected pending explicit parser/tests.
6. **CPack packaging:** CMake install rules and RPM/DEB CPack metadata are implemented. Both packages were generated and inspected; the DEB includes explicit runtime dependencies because `dpkg-shlibdeps` on Fedora has no Debian library database, and the RPM auto-requires runtime sonames. Both extracted binaries pass `--help`; the DEB also passed install/remove in a temporary dpkg root. RPM install/remove is still unverified because the isolated RPM transaction requires elevated privileges. Remaining: add CPack generation/content checks to CI, decide whether to publish packages while the project is unlicensed, and validate package install/remove on disposable Debian and RPM systems. Packages carry no `CAP_NET_RAW` file capabilities; post-install setup must remain separate and warn against capabilities on developer-writable binaries.
7. **Release/hardening:** GitHub Actions now runs the sanitizer suite and a Clang/libFuzzer parser smoke test on pushes and pull requests. Remaining: broaden malformed-pcap/fuzz corpora, extend capability testing across Linux environments, and decide licensing before inviting reuse/contributions. The initial milestone is already published. Never grant file capabilities to a developer-writable binary for deployment.
8. **Protocol decoding roadmap:** Active bounded modules now decode TCP, packet-local HTTP, DNS over UDP/TCP, DHCPv4/BOOTP, generic UDP, NTP, SNMP, TLS records, QUIC headers, RTP/RTCP, Syslog, RADIUS, TACACS+, ICMP, IGMP, and VRRP. Remaining entries below require IPv6 or non-IP link parsing. Each decoder must use bounded spans, emit metadata by default, and have malformed/truncated fixtures. Keep credentials, community strings, keys, and arbitrary payload hidden by default.

### Monitoring Experience TODO

- Add quick filters for protocol, specific local or remote ports, and a selected connection. Clearly label the difference between hiding rows in the display and filtering packets at capture time.
- Keep always-on monitoring practical: run multi-day soak tests for memory, CPU use, stale-flow expiry, and stable counters; document results before claiming long-term readiness.
- Add an optional threat-priority sort that moves explainable heuristic signals to the top of the list, such as unexpected inbound SSH/Telnet or validated command-and-control indicators. Show why a connection was prioritized; treat it as a lead to review, not proof of an attack or a verdict.
- Add direction colors: blue for outbound traffic, green when both directions are observed, and red for inbound traffic with no reply seen. Determine direction from the local host/interface, not endpoint sort order, and provide text cues for terminals without color.
- Add a small set of real, compressed screenshots to the README. Keep image files modest so the documentation stays quick to download.

### Protocol Decoder Backlog

The capture/parser foundation is currently Ethernet plus IPv4. Prioritize decoders that fit that foundation first, and treat IPv6 or other link types as explicit prerequisite work rather than pretending their packets are already supported.

**Next on current Ethernet/IPv4 path:**

- **HTTP/1.x over TCP:** Implemented for packet-local start lines on ports 80, 8000, and 8080. Summaries include request method/validated Host or response status and allowlisted Server/Content-Type/Content-Length; paths, cookies, authorization headers, and bodies are omitted. TCP stream reassembly is not implemented, so split start lines may be missed. `SNIFFIT_NG_CUSTOM_HTTP_DECODER_SOURCE` is an explicit build-time analyst hook; default implementation is inert, receives one bounded segment, and its output is constrained to printable ASCII.
- **DNS (UDP and TCP):** Implemented in `src/decode_dns.c`, dispatched on port 53. Summaries include transaction metadata, section counts, and the first safely decoded question name/type/class; answer RDATA and TXT values are not exposed. Compression pointers must be backward, and traversals are bounded. TCP uses packet-local length framing; split messages/reassembly are not supported.
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
