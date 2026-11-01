# One-Day Sniffit NG Resource Check

## Standard Procedure

The reusable workflow and sampler commands are documented in [docs/stability-testing.md](docs/stability-testing.md).

## Current Run Setup

- The user synced the new config format and selected run options. `~/.config/sniffit-ng/config` contains `ui_priority = 22/tcp,23/tcp`; the new process started successfully with this config.
- `getcap` confirmed `cap_net_raw=p` on `build/relocated-live/sniffit-ng` before capture.
- The capture runs in a regular VS Code terminal. The process and system samplers are detached with `nohup` so they do not depend on the chat-owned terminal or tmux.

## Run

- Date: 2026-10-11 (local time)
- Earlier run segment halted cleanly at approximately 15:57 to implement configurable priority ports. Its app and samplers stopped; output logs remain preserved under `/tmp`.
- Initial application: `build/live/sniffit-ng --interface ppp0`, PID `139469`.
- At approximately 15:36, PID `139469` was no longer running. No coredump record appeared in the query; the reason it exited is unknown. Its process sampler was stopped after the PID disappeared. Existing logs were preserved.
- Relaunched application: `/home/sonik/src/sniffit/sniffit-ng/build/relocated-live/sniffit-ng --interface ppp0`, PID `145703`.
- Capture capability: `cap_net_raw=p` on `build/relocated-live/sniffit-ng`.
- After rebuilding for configurable priority ports at approximately 16:01, `getcap build/relocated-live/sniffit-ng` returned no capability. `cap_net_raw=p` was reapplied and verified before the next live capture; rebuilding may clear file capabilities.
- In the earlier run segment, system monitoring began around 15:08 and the replacement process sampler around 15:37. Both were configured for eight hourly samples but stopped at approximately 15:57 before the first hourly sample completed; their projected completion times (23:09 and 23:37) were not reached.
- On restart, the UI reported `PAYLOAD DISPLAY ENABLED`; this existing setting was not changed.
- The relaunched PID `145703` was stopped from the main curses screen with `q` at approximately 15:57. The eight-hour process and system samplers were stopped before their first hourly sample completed; their logs contain headers/available baseline output, not an hourly trend series.
- At 16:12, after the chat-owned terminal ended, the process table contained no `sniffit-ng`, `pidstat`, or `sar` process. A launch attempt from `/home/sonik/src/sniffit` failed because the relative `./build/relocated-live/sniffit-ng` path was not present there.
- At approximately 16:13, a brief tmux-hosted capture (PID `156478`) was started, then stopped cleanly with `q` when the user requested a regular VS Code terminal. Its short sampler files are preserved and are not the active run.
- At 16:15, the current capture was started in the VS Code terminal as PID `156981`: `/home/sonik/src/sniffit/sniffit-ng/build/relocated-live/sniffit-ng --interface ppp0`. The UI showed `PAYLOAD DISPLAY ENABLED`, as configured by the user.
- Fresh process and system samplers began at approximately 16:15, each configured for eight hourly samples. Expected completion is approximately 00:15 on 2026-10-12 if the host remains up. Process log: `/tmp/sniffit-ng-pidstat-156981.log`. System text/binary logs: `/tmp/sniffit-ng-sar-20261011-1615.log` and `/tmp/sniffit-ng-sar-20261011-1615.bin`.
- The samplers read process/system counters only. They do not inspect captured packets or change the application's capture settings.

## Baseline

At approximately 15:08:

- `pidstat`: RSS `13,744 KiB`, VSZ `24,364 KiB`; CPU `0.00%` for the one-second sample.
- `ps` about 27 seconds later: RSS `13,836 KiB`, VSZ `24,364 KiB`, one thread, cumulative CPU `0.3%`.
- System memory: `17.26%` used, `54,347,036 KiB` available.
- System load averages: `1.16`, `0.97`, `1.04` on 12 CPUs.
- The one-second `sar` sample reported `ppp0` at about `25.99 KiB/s` receive and `95.77 KiB/s` transmit. `sar` records aggregate counters for all interfaces, not packet contents.

Relaunch baseline at approximately 15:37:

- PID `145703`: RSS `38,148 KiB`, VSZ `48,968 KiB`, one thread, CPU `1.00%` during the one-second `pidstat` sample.
- `pidstat` reported descriptor count as unavailable (`fd-nr=-1`).
- Process log: `/tmp/sniffit-ng-pidstat-145703.log`.

Current VS Code-terminal run baseline at approximately 16:15:

- PID `156981`: RSS `38,424 KiB`, VSZ `48,968 KiB`, one thread, CPU `0.5%` at 16:15:48. At 16:15:20, during startup, RSS was `14,348 KiB` and VSZ `24,812 KiB`; record this early increase without treating it alone as evidence of a leak.
- System memory at 16:15:49: `19.07%` used, `53,161,316 KiB` available; load averages `1.58`, `1.27`, `1.16` on 12 CPUs.
- The one-second `sar` sample reported `ppp0` at `2.47 KiB/s` receive and `97.89 KiB/s` transmit. Interface rates are aggregate counters, not packet contents.

Follow-up spot checks:

- At 15:10:39 and 15:11:13, RSS remained `37,516 KiB`, VSZ `47,992 KiB`, with one thread and under `0.5%` cumulative CPU. `/proc/PID/status` reports `28,876 KiB` anonymous RSS and `8,640 KiB` file-backed RSS. This is a notable increase from the initial sample, but the short stable interval is insufficient to classify it as a leak.
- Access to `/proc/139469/smaps_rollup` and `/proc/139469/fd` was denied for this user, so detailed mapping and descriptor counts are unavailable without elevated access. No privilege escalation was attempted; treat descriptor metrics as unavailable if `pidstat` cannot report them.

## Logs

- Process metrics (RSS, CPU, I/O, threads/descriptors): `/tmp/sniffit-ng-pidstat-139469.log`
- Relaunched process metrics for PID `145703`: `/tmp/sniffit-ng-pidstat-145703.log`
- Current process metrics for PID `156981`: `/tmp/sniffit-ng-pidstat-156981.log`
- System memory/load/interface metrics, text: `/tmp/sniffit-ng-sar-20261011.log`
- System metrics, sysstat binary data: `/tmp/sniffit-ng-sar-20261011.bin`
- Current system memory/load/interface metrics, text: `/tmp/sniffit-ng-sar-20261011-1615.log`
- Current system metrics, sysstat binary data: `/tmp/sniffit-ng-sar-20261011-1615.bin`

Review with:

```sh
cat /tmp/sniffit-ng-pidstat-139469.log
cat /tmp/sniffit-ng-pidstat-145703.log
cat /tmp/sniffit-ng-pidstat-156981.log
cat /tmp/sniffit-ng-sar-20261011.log
cat /tmp/sniffit-ng-sar-20261011-1615.log
sar -f /tmp/sniffit-ng-sar-20261011-1615.bin -r -q -n DEV
sar -f /tmp/sniffit-ng-sar-20261011.bin -r -q -n DEV
```

## If Sniffit NG Crashes

1. Do not restart the application or remove its build/log files until the evidence is copied and reviewed.
2. Preserve all process and system sampler files listed above. They are under `/tmp`; they should survive an application-only crash, but may be lost on reboot or a system-level failure. Copy them to persistent storage before rebooting if possible.
3. Check the last process samples for a sustained RSS increase, descriptor/thread growth, CPU or I/O changes. Compare them with the baseline; a single RSS increase is not by itself proof of a leak.
4. Check the matching `sar` times for system memory pressure, load changes, or unusual interface-counter rates.
5. Save the application's terminal output. If systemd captured a core, `coredumpctl list sniffit-ng` and `coredumpctl info PID` may provide additional crash evidence.

RSS sampling is a low-overhead trend check, not a definitive heap-leak detector. Valgrind was not attached to this live capture run because doing so would require an intrusive restart and distort its resource usage.
