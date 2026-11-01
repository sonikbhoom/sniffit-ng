#!/usr/bin/env bash
# Samples every sniffit-ng process and host load/memory into a CSV; meant to run once per cron tick.
#
#   sniffit-ng-perf.sh [sample]   append one row per running instance (default)
#   sniffit-ng-perf.sh summary    min/avg/max per interface over the current log
#
# Cron example (every 5 minutes, as root so /proc/PID/fd is readable):
#   */5 * * * * root SNIFFIT_NG_PERF_DIR=/var/log/sniffit-ng-perf /usr/local/sbin/sniffit-ng-perf.sh >/dev/null 2>&1
#
# Environment:
#   SNIFFIT_NG_PID        space/comma-separated PIDs to monitor instead of finding "sniffit-ng" by name
#   SNIFFIT_NG_PERF_DIR   log/state directory (default ${XDG_STATE_HOME:-~/.local/state}/sniffit-ng-perf)
#   SNIFFIT_NG_PERF_MAX_BYTES  rotate the CSV past this size (default 10485760)
#   SNIFFIT_NG_PERF_KEEP  rotated files to keep (default 5)
#
# Read-only: never starts, signals, or attaches to a capture. The iface column comes from each
# process's --interface argument ("pcap" for --read-pcap). An interface seen before but no longer
# running logs running=0; delete $SNIFFIT_NG_PERF_DIR/state to forget retired interfaces.
set -u
umask 077

dir=${SNIFFIT_NG_PERF_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/sniffit-ng-perf}
max_bytes=${SNIFFIT_NG_PERF_MAX_BYTES:-10485760}
keep=${SNIFFIT_NG_PERF_KEEP:-5}
csv=$dir/perf.csv
state=$dir/state
seen=$state/seen-ifaces
header='timestamp,epoch,pid,iface,running,cpu_pct,rss_kb,vmhwm_kb,vsz_kb,threads,fds,load1,load5,load15,mem_avail_kb,swap_used_kb'

summary() {
    [[ -r $csv ]] || { echo "no log at $csv" >&2; return 1; }
    awk -F, '
        NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
        {
            key = $col["iface"]; if (key == "") key = "(none)"
            total[key]++
            if ($col["running"] != 1) next
            up[key]++
            split("cpu_pct rss_kb vmhwm_kb threads fds load1 mem_avail_kb", names, " ")
            for (k = 1; k <= 7; k++) {
                m = names[k]; v = $col[m]
                if (v == "") continue
                c[key, m]++; s[key, m] += v
                if (!((key, m) in mn) || v + 0 < mn[key, m] + 0) mn[key, m] = v
                if (!((key, m) in mx) || v + 0 > mx[key, m] + 0) mx[key, m] = v
            }
        }
        END {
            split("cpu_pct rss_kb vmhwm_kb threads fds load1 mem_avail_kb", names, " ")
            for (key in total) {
                printf "\n[%s] samples=%d running=%d down=%d\n", key, total[key], up[key], total[key] - up[key]
                printf "%-14s %12s %12s %12s\n", "metric", "min", "avg", "max"
                for (k = 1; k <= 7; k++) {
                    m = names[k]
                    if (c[key, m] > 0)
                        printf "%-14s %12s %12.2f %12s\n", m, mn[key, m], s[key, m] / c[key, m], mx[key, m]
                }
            }
        }' "$csv"
}

rotate() {
    local size i
    size=$(stat -c %s "$csv" 2>/dev/null || echo 0)
    (( size > max_bytes )) || return 0
    for (( i = keep - 1; i >= 1; i-- )); do
        [[ -e $csv.$i ]] && mv -f "$csv.$i" "$csv.$((i + 1))"
    done
    mv -f "$csv" "$csv.1"
}

find_pids() {
    local item
    if [[ -n ${SNIFFIT_NG_PID:-} ]]; then
        for item in ${SNIFFIT_NG_PID//,/ }; do
            [[ $item =~ ^[0-9]+$ ]] && echo "$item"
        done
        return 0
    fi
    pgrep -x sniffit-ng 2>/dev/null
}

iface_of() {
    local -a args
    local i
    mapfile -d '' -t args < "/proc/$1/cmdline" 2>/dev/null
    for (( i = 0; i < ${#args[@]}; i++ )); do
        case ${args[i]} in
            --interface) echo "${args[i + 1]:-?}"; return ;;
            --read-pcap) echo pcap; return ;;
        esac
    done
    echo '?'
}

emit() { # pid iface running cpu rss hwm vsz threads fds
    echo "$ts,$now,$1,$2,$3,$4,$5,$6,$7,$8,$9,$load1,$load5,$load15,$mem_avail,$swap_used" >> "$csv"
}

sample_pid() {
    local pid=$1 iface stat rest fields ticks start cpu='' rss hwm vsz threads fds
    [[ -r /proc/$pid/stat ]] || return 1
    stat=$(< "/proc/$pid/stat") || return 1
    iface=$(iface_of "$pid")
    rest=${stat##*) }
    read -ra fields <<< "$rest"
    # After the comm field: utime=[11] stime=[12] starttime=[19].
    ticks=$(( ${fields[11]:-0} + ${fields[12]:-0} ))
    start=${fields[19]:-0}

    local pfile=$state/pid-$pid
    if [[ -r $pfile ]]; then
        local p_start p_ticks p_epoch
        read -r p_start p_ticks p_epoch < "$pfile"
        if [[ $p_start == "$start" && ${p_epoch:-0} -lt $now ]]; then
            # Percent of one core over the interval since this PID's previous sample.
            cpu=$(awk -v d=$(( ticks - p_ticks )) -v hz="$hz" -v e=$(( now - p_epoch )) \
                'BEGIN { printf "%.2f", d * 100 / (hz * e) }')
        fi
    fi
    echo "$start $ticks $now" > "$pfile"

    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    vsz=$(awk '/^VmSize:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    threads=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    (( fds == 0 )) && fds=''

    emit "$pid" "$iface" 1 "$cpu" "$rss" "$hwm" "$vsz" "$threads" "$fds"
    live_ifaces+=("$iface")
    live_pids+=("$pid")
}

sample() {
    mkdir -p "$state" || exit 1
    [[ -s $csv && $(head -n 1 "$csv") != "$header" ]] && mv -f "$csv" "$csv.old-format.$(date +%s)"
    rotate
    [[ -s $csv ]] || echo "$header" > "$csv"

    now=$(date +%s)
    ts=$(date -Iseconds)
    hz=$(getconf CLK_TCK)

    local _
    read -r load1 load5 load15 _ < /proc/loadavg
    mem_avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    local swap_total swap_free
    swap_total=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
    swap_free=$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)
    swap_used=$(( ${swap_total:-0} - ${swap_free:-0} ))

    live_ifaces=()
    live_pids=()
    local pid
    while read -r pid; do
        [[ -n $pid ]] && sample_pid "$pid"
    done < <(find_pids)

    # Drop CPU state for PIDs that have exited.
    local f
    for f in "$state"/pid-*; do
        [[ -e $f ]] || continue
        [[ " ${live_pids[*]:-} " == *" ${f##*/pid-} "* ]] || rm -f "$f"
    done

    local label
    for label in "${live_ifaces[@]:-}"; do
        [[ -n $label ]] && ! grep -qxF -- "$label" "$seen" 2>/dev/null && echo "$label" >> "$seen"
    done
    if [[ -r $seen ]]; then
        while read -r label; do
            [[ " ${live_ifaces[*]:-} " == *" $label "* ]] || emit '' "$label" 0 '' '' '' '' '' ''
        done < "$seen"
    fi
    (( ${#live_pids[@]} == 0 )) && [[ ! -s $seen ]] && emit '' '' 0 '' '' '' '' '' ''
    return 0
}

case ${1:-sample} in
    sample)  sample ;;
    summary) summary ;;
    *) echo "usage: ${0##*/} [sample|summary]" >&2; exit 2 ;;
esac
