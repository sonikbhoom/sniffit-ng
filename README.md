# Sniffit NG

Sniffit NG is a security-focused C successor to the legacy Sniffit monitor, developed in a separate source tree. It currently supports bounded Ethernet and Linux cooked v1 (SLL) IPv4 parsing, offline pcap replay, privilege-reduced live capture, flow summaries, and an ncurses monitor.

This repository currently has no license. Public visibility does not itself grant permission to reuse, modify, or redistribute the code.

In the live curses view, select a flow and press Enter to open its inspection pane on the right while leaving the flow list visible on the left. The pane appends bounded metadata records for TCP, generic UDP, ICMP, IGMP, VRRP, and SNMP over UDP. SNMP community strings and varbind values are never displayed. The header includes fixed service hints for common TCP/UDP ports; it does not derive labels from packet contents. ICMP Echo payload samples remain separately gated by the acknowledged inspection setting. The pane stays stable rather than repainting on idle polls; arrow keys or `j`/`k` switch the inspected flow, and other keys close the pane.

Flow masks affect which connections are shown, not which packets are captured or counted. Source and destination host/port masks are optional and combine as endpoint pairs; because each flow is bidirectional, either traffic direction can satisfy the pair. Setting a host mask to `all` or a port mask to `0` clears that individual mask.

## Build and test

Requirements: C17 compiler, CMake 3.16 or newer, pkg-config, libpcap, and ncursesw development files.

```sh
cmake -S . -B build -DSNIFFIT_NG_ENABLE_SANITIZERS=ON
cmake --build build
ctest --test-dir build --output-on-failure
./build/sniffit-ng --help
./build/sniffit-ng --read-pcap capture.pcap
sudo ./build/sniffit-ng --interface lo
```

The viewer supports offline Ethernet pcap replay and live capture with `--interface DEVICE`. Live mode defaults to non-promiscuous capture; `--promiscuous` must be explicitly requested. On Linux, install a protected, root-owned copy with `CAP_NET_RAW` in its permitted set to avoid running the full application through `sudo`:

```sh
sudo setcap cap_net_raw+p /usr/local/bin/sniffit-ng
getcap /usr/local/bin/sniffit-ng
/usr/local/bin/sniffit-ng --interface lo
```

The application makes only `CAP_NET_RAW` effective while opening pcap, then clears capabilities and sets `no_new_privs` before parsing packets, writing logs, or entering curses. A sudo invocation from a regular user is also supported when `SUDO_UID` and `SUDO_GID` are available. Do not set file capabilities on a developer-writable build artifact: any user able to execute that binary can capture traffic available to the process. Promiscuous mode may require additional privilege and is not granted by `CAP_NET_RAW` alone. The parser borrows pointers into the caller's capture buffer; those views are valid only until the next read from the source.

Payload persistence is disabled by default. To enable it for one offline replay, run `./build/sniffit-ng --read-pcap capture.pcap --payload-logging`; the program requires an interactive acknowledgment before opening the capture. It creates `sniffit-ng-payload.log` exclusively with owner-only permissions and writes validated payload bytes as hex. Use `--payload-log PATH` with `--payload-logging` to choose another new path; existing files and symlinks are not followed. Review the warning, confirm authorization and consent, protect the output, and delete it according to your retention policy. Without a controlling terminal, logging fails closed.

## ICMP Payload Inspection

Flow summaries and packet counters work without payload inspection. `--inspect-payloads` enables the Enter detail view to display sanitized ICMP Echo payload records. At most 16 recent records per flow are kept in memory, each with at most 64 payload bytes; new records append to the open scrolling pane. This feature does not write payload bytes to disk. To avoid repeating the ethical acknowledgment, place this exact active comment in the config file:

```ini
inspect_payloads = true
## User has acknowledged to behave ethically and inspect only authorized traffic.
```

By default, the config is read from `$XDG_CONFIG_HOME/sniffit-ng/config`, or `~/.config/sniffit-ng/config` when `XDG_CONFIG_HOME` is unset. Pass `--config FILE` to use another file. The `--inspect-payloads` switch can enable inspection for one run, but an acknowledgment in the loaded config is still required. If inspection is enabled in config, it is active for that run without the switch. The program prints a reminder that inspection must be authorized and handled ethically. Missing acknowledgment fails closed. The shipped [`sniffit-ng.conf.example`](sniffit-ng.conf.example) keeps inspection disabled and its acknowledgment line commented out.

This persisted acknowledgment applies only to in-memory ICMP Echo display. Persistent payload logging remains a separate feature and still requires the interactive per-run acknowledgment described above.
