# Stability Testing

## Standard Procedure

- Confirm the intended interface, config, executable, and capture capability before launch. Check for an existing Sniffit NG process first; do not create a duplicate capture when terminal state is uncertain.
- Run capture in a user-visible VS Code integrated terminal, in the foreground. Keep that terminal open for the run and use the app's normal `q` exit. Do not use tmux for this workflow.
- Record the capture PID and baseline before starting samplers. Use unique, date- and PID-stamped output files for every run.
- Sample process RSS, CPU, I/O, context switches, and related counters with `pidstat`; sample host memory, load, and interface counters with `sar`. Keep the binary `sar` data as well as its text output.
- Select the interval and sample count to match the planned duration. Eight hourly samples cover about eight hours; a full-day run needs 24 hourly samples. The first periodic output is expected only after the first interval.
- Record start time, PID, command, config/capability confirmation, interval/count, baseline RSS/VSZ/CPU/thread count, system memory/load, and relevant interface rates. Preserve earlier artifacts rather than overwriting them.
- Verify the app and both samplers are running and their output files exist. If the app stops or crashes, preserve logs and terminal output before investigating; compare trends instead of treating one RSS change as proof of a leak.
- Samplers collect process and host counters only. Do not use third-party traffic as a test source or record packet contents as part of a resource check.

## Example Samplers

Set `CAPTURE_PID`, `SAMPLES`, and `RUN_ID` for the current run, where `RUN_ID` is a fresh timestamp such as `20261011-1615`:

```sh
PROCESS_LOG="/tmp/sniffit-ng-pidstat-${CAPTURE_PID}-${RUN_ID}.log"
SAR_TEXT="/tmp/sniffit-ng-sar-${RUN_ID}.log"
SAR_BIN="/tmp/sniffit-ng-sar-${RUN_ID}.bin"

nohup pidstat -h -r -u -d -w -p "$CAPTURE_PID" 3600 "$SAMPLES" \
  > "$PROCESS_LOG" 2>&1 < /dev/null &
nohup sar -r -q -n DEV -o "$SAR_BIN" 3600 "$SAMPLES" \
  > "$SAR_TEXT" 2>&1 < /dev/null &
```

Capture a one-time baseline with `ps -p "$CAPTURE_PID" -o pid,stat,%cpu,rss,vsz,nlwp,etime,args`, `free -h`, `uptime`, and `sar -r -q -n DEV 1 1`.
