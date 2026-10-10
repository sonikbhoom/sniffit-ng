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
- **Gate status:** Offline and post-drop loopback capture gates passed. The user confirmed the live curses application now renders successfully with the capability-backed capture path. This closes the initial live UI bring-up gate; remaining parity interactions and longer-running capture behavior stay on the feature checklist.
- **Rate panel:** A deterministic three-second packet/byte sampler is implemented and unit-tested. The user confirmed the live rate display check is complete; the temporary file capability was removed afterward.

## Initial Feature Policy

- Preserve authorized live monitoring, offline pcap replay, filters, counters, connection summaries/details, and conventional logging.
- Keep payload display user-selected and in-memory by default. Do not automatically identify or extract credentials.
- Preserve packet generation only as a separately enabled diagnostic feature, with an explicit startup warning/confirmation and documentation restricting use to authorized test networks.
- Treat legacy config/CLI compatibility as a migration aid, not as permission to preserve unsafe parsing or ambiguous semantics.

## Approval Boundary

Payload logging is off by default and will not be enabled by a config file or remembered preference. The run-time `--payload-logging` switch enables persistent payload capture only for that invocation; `--payload-log PATH` selects an alternate output path. When supplied, the program displays an ethics/privacy warning covering authorization, consent, data minimization, secure storage, and retention, then requires the operator to type exactly `I ACKNOWLEDGE THE PRIVACY AND AUTHORIZATION RISKS` on `/dev/tty` before capture starts. Declining or running without a controlling terminal fails closed; there is no silent or unattended acknowledgment bypass. The output file is created exclusively with mode `0600`, and existing files/symlinks are rejected. The UI visibly indicates when payload logging was enabled for the replay. Tests verify the exact acknowledgment, fail-closed behavior, permissions, no-overwrite policy, and hex-only payload encoding.

ICMP Echo payload inspection is a distinct, in-memory-only feature. It is disabled by default and requires either `--inspect-payloads` or `inspect_payloads = true` in config, plus the exact active comment `## User has acknowledged to behave ethically and inspect only authorized traffic.` in the loaded config. This persisted marker avoids repeating a prompt but does not enable payload logging. When enabled, only the latest 64 bytes of ICMP Echo payload per flow are retained; other protocol payloads are not retained for the detail view. Printable text is sanitized before display. Disabling the setting clears retained sample bytes.

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
2. **Complete UI parity:** Scrolling and resize clamping are implemented with a pure helper test. Remaining: `-I`-style extended descriptions, deterministic flow ordering, and more detailed filter semantics. The initial list/details/mask/statistics/reset/quit workflow exists but is not full legacy parity.
3. **Configuration and compatibility:** The bounded `inspect_payloads` config and exact ethics-marker validation are implemented. Remaining: add an explicitly mapped legacy CLI/config subset; preserve only validated semantics.
4. **Output modes:** Add safe pcap recording and selected summary/dump modes. Keep cleartext payload output disabled unless the runtime acknowledgment policy is satisfied.
5. **Hardening:** Add parser fuzz targets, broader malformed-pcap corpus, pseudo-terminal curses interaction tests, and privilege/capability tests across supported Linux environments. Decide and document behavior for non-Ethernet link types.
6. **CPack packaging:** Add CPack configuration for RPM and DEB packages with explicit package metadata, runtime dependencies, install paths, and clean uninstall behavior. Validate package contents and install/remove in disposable environments; build both formats in CI where the required host tooling is available. Packages must not carry `CAP_NET_RAW` file capabilities; document post-install capability setup separately and warn that capabilities on user-writable binaries are unsafe.
7. **Release/hardening:** Add CI for sanitizer tests, document installation/file-capability policy, and decide licensing before inviting reuse/contributions. The initial milestone is already published. Never grant file capabilities to a developer-writable binary for deployment.
