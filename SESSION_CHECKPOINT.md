# Session Checkpoint

Date: 2026-10-11
Project: `/home/sonik/src/sniffit/sniffit-ng`
Branch: `main`
Remote: `https://github.com/sonikbhoom/sniffit-ng.git`

## Current State

- Successor repository is independent at `/home/sonik/src/sniffit/sniffit-ng`; legacy application files are under `/home/sonik/src/sniffit/sniffit-legacy`. Do not edit the legacy tree as part of successor work.
- Ethernet and Linux cooked v1 (SLL) IPv4 capture/parsing are supported. Other link types are rejected until implemented and tested.
- The live NTP check on `ppp0` was confirmed in the curses monitor: one request/reply flow, NTPv4 client/server metadata, stratum 2, server precision -25, and reference ID `84f60be9`. `ntpdate -4 -q time.nrc.ca` also succeeded without adjusting the system clock.
- Active bounded metadata decoders: TCP, packet-local HTTP/1.x, DNS over UDP/TCP, DHCPv4/BOOTP, generic UDP, NTP, SNMP, TLS record metadata, QUIC header metadata, RTP/RTCP, Syslog, RADIUS, TACACS+, ICMP, IGMP, and VRRP.
- HTTP built-in summaries omit paths, cookies, authorization, and bodies. Optional native HTTP/protocol callbacks are included at build time and selected by per-module runtime decoder config. Both callbacks require `tainted_extensions = true` for every protocol; the flag is explicit opt-in, not a sandbox. Built-in decoders/raw IPv4 metadata need no taint opt-in. Default extension implementations are no-ops. No built-in full packet/body dump is enabled.
- ICMP Echo payload bytes remain separately gated by the exact config acknowledgment and bounded in-memory history. Persistent payload logs and pcap recording require interactive authorization; outputs are exclusive mode 0600.
- Pcap recording via `--write-pcap FILE` preserves link type, caplen/wire length, and timestamps for Ethernet/SLL; existing paths and symlinks are rejected.
- Remaining protocol source files are inert placeholders, not active decoders or runtime plugins. See the protocol backlog in `PLAN.md`.
- README now warns against bypassing encryption/access controls, links the U.S. Copyright Office DMCA information, and states that it is not legal advice. A qualified legal-review TODO is in both README and the canonical plan.
- `PLAN.md` records the Oct 11 architecture review. Scanner tracking with external WHOIS/geolocation is not approved by the assessment; recommendation is to drop it as written. Broad routing/tunnel decoder work, stream reassembly, legacy compatibility, and dump output are deferred pending concrete needs. Packet generation is out of scope: the application remains receive-only, and its test harnesses may generate only their own loopback traffic. Reconsider application packet generation only after a concrete authorized test-network use case is documented and explicitly approved.
- Resource design is bounded (256 flow slots, 128 monitor events, bounded per-flow histories; saturating counters). Idle-flow expiry is packet-driven, so stale flows may remain visible during silence. Multi-day stability is not established.
- UI retains curses list/detail/filter/rate workflows, keyboard navigation, and a monochrome fallback. It requires at least 80x18; text equivalents for local/priority color cues, narrow-terminal behavior, screen-reader support, and low-vision usability remain open TODOs.

## Validation

- Full `build/live` CTest suite: 18 passed; live-loopback test skipped because this test runner lacks `CAP_NET_RAW`.
- Full ASan/UBSan `build/ci` CTest suite: 18 passed; live-loopback test skipped because this test runner lacks `CAP_NET_RAW`.
- `build/live` and `build/ci` rebuilt successfully after making both native decoder hooks taint-gated.
- Pcap writer tests round-trip Ethernet and SLL frames and verify permissions/no-overwrite behavior.
- Clang/libFuzzer parser target completed a 5,000-run smoke pass over the Ethernet/SLL IPv4 parser without a fault; this is not sustained corpus-backed fuzzing.
- Linux PTY curses interaction test passes.
- Live NTP traffic was observed on `ppp0` with tcpdump and decoded by Sniffit NG after adding SLL support.
- Focused decoder regressions verify neither native callback runs without `tainted_extensions`, and both can run with opt-in; built-in summaries and service advisories remain available without it.
- Diagnostics on `src/protocol_decode.c` and `tests/test_protocol_decode.c` reported no errors; `git diff --check` passed.
- After relocation, fresh `build/relocated-live` and `build/relocated-ci` trees configured and built successfully; each full suite passed 18 tests with the live-loopback test skipped for missing `CAP_NET_RAW`. Pre-relocation CMake build trees were left untouched and retain their old absolute source-path caches.

## Next Work

1. Keep packet generation out of scope; reconsider it only if a concrete authorized test-network need is documented and explicitly approved.
2. Run multi-day soak tests for resource/counter stability and decide whether idle-flow expiry needs a timer independent of packet arrival.
3. Expand corpus-backed fuzzing, malformed-pcap coverage, privilege/capability testing, and accessibility/PTY coverage.
4. Prioritize terminal accessibility (text cues, narrow layouts, monochrome/low-vision behavior) and validate before making broad accessibility claims.
5. Decide on a project license and obtain qualified legal review before broad distribution.
6. Consider IPv6 parser support as the next protocol foundation; defer broad routing/tunnel coverage and TCP reassembly until concrete use cases justify their complexity.
7. Revisit scanner tracking, external enrichment, legacy CLI compatibility, and summary/dump modes only against explicit user needs and privacy requirements. The current recommendation is to drop automatic third-party scanner enrichment.
8. Complete CPack RPM/DEB install/remove checks before packaging for distribution.

## Recovery Files

- `SESSION_TRANSCRIPT_2026-10-10.jsonl` is a local copy of the Copilot chat transcript and is excluded from Git because it may include private conversation and machine/network details.
- Do not stage or publish the raw transcript without explicit review and consent.

## Handoff Checkpoint — 2026-10-11

The user paused work for today. Do not continue implementation, rebuild, run capture, or roll back unless they ask to resume. They may later request a rollback to the last state where Telnet decode presentation was working; no commit or clean rollback point has been created, so preserve all current edits and identify the desired baseline before reverting anything.

### Current Issue

- The user reports that the Telnet `FULL DECODE` view is still missing its five explanatory lines and that SSH still does not visually match Telnet. Treat both reports as unresolved; do not claim the live UI is fixed based only on PTY fixtures.
- The reference `examples/telnet.png` shows the five lines: `FULL DECODE` capture metadata, local-link address, packet claims/flags, unauthenticated-source caveat, and the hex-purpose line.
- `src/ui.c` currently has a dedicated Telnet full-frame renderer and a separate SSH header-only renderer. SSH uses the `FULL DECODE` heading and should show link/IP/TCP headers only. The user says observed behavior is still broken; live output has not been reproduced safely in this session.
- The active default config is `/home/sonik/.config/sniffit-ng/config` (`XDG_CONFIG_HOME` was unset when checked); it contains `full_decode = true`, `telnet = raw`, and `ssh = raw`. Configuration mode is not the apparent cause.
- The PTY fixture was changed to send a generated TCP/22 frame through `sn_monitor_process` rather than manually seed the SSH record. Its last focused run passed, and the last full CTest run before the latest `decode_ssh.c` edit passed 18 tests with `capture_live_loopback` skipped by its permission gate.

### Current Worktree / Validation

- The worktree is intentionally dirty across the SSH implementation, monitor/UI, tests, build metadata, README, and flow changes. `1-day-logging.md` and `src/decode_ssh.c` are untracked. Preserve these and other user edits; do not use blanket checkout/reset operations.
- The user indicated that `src/decode_ssh.c` changed after the last request. Its current contents include the token `&&qq` in the SSH port check between the source-port and destination-port comparisons. Do not overwrite this edit; inspect with the user when resuming. No build or tests have run after that observed change, and the last passing binary is therefore not proof that the current source builds.
- Last full build path: `build/relocated-live/sniffit-ng`. A rebuild may clear `CAP_NET_RAW`; no live capture was performed as part of this checkpoint.
- Prior PTY assertion failures generated SIGABRT messages during test iteration. The test PTY checks are assert-based; disable core creation in the test shell (`ulimit -c 0`) when resuming focused runs if desired. No core files were found in the workspace.
- Screenshots in `examples/` are local reference assets; leave them unmodified and unpublished.

## REMINDER: Remove the Performance Monitor When Done (installed 2026-10-12)

A root cron job samples every `sniffit-ng` process (CPU, memory, fds, host load) into `/var/log/sniffit-ng-perf/perf.csv`. It runs unattended, so remove it once the measurement run is finished.

1. Review results first: `sudo SNIFFIT_NG_PERF_DIR=/var/log/sniffit-ng-perf /usr/local/sbin/sniffit-ng-perf.sh summary`. Copy `perf.csv*` elsewhere if the data should be kept.
2. Stop sampling: `sudo rm /etc/cron.d/sniffit-ng-perf`
3. Remove the root-owned script: `sudo rm /usr/local/sbin/sniffit-ng-perf.sh`
4. Remove logs and state (root-only, includes rotated files): `sudo rm -rf /var/log/sniffit-ng-perf`
5. Verify nothing remains: `ls /etc/cron.d/sniffit-ng-perf /usr/local/sbin/sniffit-ng-perf.sh /var/log/sniffit-ng-perf` should report "No such file or directory" for each.
6. Optional: delete `scripts/sniffit-ng-perf.sh` from this repo, or keep it for future runs.

Re-installing after a script change needs `sudo install -o root -g root -m 0755 scripts/sniffit-ng-perf.sh /usr/local/sbin/sniffit-ng-perf.sh`.
