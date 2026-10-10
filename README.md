# Sniffit NG

Sniffit NG is a security-focused C successor to the legacy Sniffit monitor. It is being developed separately from the original source tree.

This repository currently has no license. Public visibility does not itself grant permission to reuse, modify, or redistribute the code.

The initial slice is a non-privileged Ethernet/IPv4 parser with bounded views and unit tests. Live capture, ncurses UI, configuration, and output handling will be added in later stages described in [PLAN.md](PLAN.md).

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
