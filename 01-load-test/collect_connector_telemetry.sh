#!/usr/bin/env bash
# Pillar 1: connector telemetry collector - run ON the connector VM (started manually per host).
#
# Usage:
#   RUN_ID=<id> ROLE=<c1|c2> [RUN_START_EPOCH=<epoch>] collect_connector_telemetry.sh [duration_sec] [interval_sec] [output_dir]
#
# Collected with sar at the given interval (default 1 s):
#   CPU (-u ALL: %usr %sys %soft ...), memory (-r) and swap (-S), disk I/O (-d -p),
#   network interfaces (-n DEV), filesystem usage (-F, only if this sysstat supports it).
# Disk space is also captured with df at start and end. The binary sar file (-o) is kept for sadf.
#
# Coverage of this host's data (metadata "coverage", first matching rule wins):
#   invalid_sar_failed   sar exited non-zero without being interrupted by this script
#   partial_interrupted  the collector received INT/TERM/HUP and stopped sar before the end
#   partial_early_end    sar ended more than COVERAGE_TOLERANCE_SEC before samples x interval
#   partial_late_start   the collector started more than COVERAGE_TOLERANCE_SEC after
#                        RUN_START_EPOCH (e.g. C2 was powered off when the run began)
#   unknown_run_start    RUN_START_EPOCH not given; the start cannot be judged
#   full_from_run_start  none of the above
# All applicable reasons are listed in "coverage_reasons". "complete_time_series" is true only for
# full_from_run_start, null for unknown_run_start and false otherwise. Whether the collector also
# covered the END of the load run is not known here; compare collector_end_epoch with the run's end.
# RUN_START_EPOCH is the start of the whole measurement run (same value on every host).
#
# Output collisions: if any telemetry_<RUN_ID>_<ROLE>_<host>* file already exists in output_dir the
# script refuses to start (exit 2) and writes nothing; redirections run with noclobber as well.
# sar writes its binary -o file itself, so a file created between the check and the start of sar
# (another collector started at the same moment) is only guarded by that check (best effort).

set -u

DURATION=${1:-300}
INTERVAL=${2:-1}
OUT_DIR=${3:-.}
RUN_ID=${RUN_ID:-}
ROLE=${ROLE:-unknown}
TOLERANCE=${COVERAGE_TOLERANCE_SEC:-5}

fail() { echo "[!] $*" >&2; exit 2; }

[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || fail "RUN_ID is required (letters, digits, '.', '_', '-')"
[[ "$ROLE" =~ ^[A-Za-z0-9_-]{1,16}$ ]] || fail "invalid ROLE"
[[ "$DURATION" =~ ^[0-9]+$ && "$DURATION" -gt 0 ]] || fail "duration_sec must be a positive integer"
[[ "$INTERVAL" =~ ^[0-9]+$ && "$INTERVAL" -gt 0 ]] || fail "interval_sec must be a positive integer"
[[ "$TOLERANCE" =~ ^[0-9]+$ ]] || fail "COVERAGE_TOLERANCE_SEC must be a non-negative integer"
if [[ -n "${RUN_START_EPOCH:-}" ]]; then
    [[ "$RUN_START_EPOCH" =~ ^[0-9]+(\.[0-9]+)?$ ]] || fail "RUN_START_EPOCH must be a Unix epoch"
fi
command -v sar >/dev/null 2>&1 || fail "sar not found (install sysstat); nothing was collected"
mkdir -p "$OUT_DIR" || fail "cannot create $OUT_DIR"

COUNT=$(( DURATION / INTERVAL ))
(( COUNT > 0 )) || fail "duration_sec must be >= interval_sec"
EXPECTED_SEC=$(( COUNT * INTERVAL ))
HOST=$(hostname)
PREFIX="$OUT_DIR/telemetry_${RUN_ID}_${ROLE}_${HOST}"
EXISTING=$(ls -d "${PREFIX}"_* "${PREFIX}.sa" 2>/dev/null | head -n 3 | tr '\n' ' ')
[[ -z "$EXISTING" ]] || fail "telemetry files already exist (${EXISTING}); nothing was overwritten - use a new RUN_ID"
set -o noclobber

export LC_ALL=C S_TIME_FORMAT=ISO

SAR_ARGS=(-u ALL -r -S -d -p -n DEV)
FS_METRICS="not collected (sar -F unsupported)"
if sar -F 1 1 >/dev/null 2>&1; then
    SAR_ARGS+=(-F)
    FS_METRICS="sar -F"
fi

INTERRUPTED=""
SAR_PID=""
on_signal() {
    INTERRUPTED="$1"
    [[ -n "$SAR_PID" ]] && kill -TERM "$SAR_PID" 2>/dev/null
}
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM
trap 'on_signal HUP' HUP

START_EPOCH=$(date -u +%s.%N)
df -P -k > "${PREFIX}_df_start.txt" 2>&1
echo "[*] ${ROLE}@${HOST}: sar ${SAR_ARGS[*]} every ${INTERVAL}s x ${COUNT} -> ${PREFIX}_sar.txt"
# sar runs in the background so that a trapped signal interrupts "wait" immediately
sar "${SAR_ARGS[@]}" -o "${PREFIX}.sa" "$INTERVAL" "$COUNT" > "${PREFIX}_sar.txt" 2> "${PREFIX}_sar.err" &
SAR_PID=$!
wait "$SAR_PID"
SAR_EXIT=$?
if [[ -n "$INTERRUPTED" ]]; then
    # the first wait returned because of the signal; collect sar's own exit status
    wait "$SAR_PID" 2>/dev/null
    SAR_EXIT=$?
fi
END_EPOCH=$(date -u +%s.%N)
df -P -k > "${PREFIX}_df_end.txt" 2>&1

ELAPSED=$(awk -v s="$START_EPOCH" -v e="$END_EPOCH" 'BEGIN { printf "%.3f", e - s }')
REASONS=()
if [[ -n "${RUN_START_EPOCH:-}" ]]; then
    LAG=$(awk -v s="$START_EPOCH" -v r="$RUN_START_EPOCH" 'BEGIN { printf "%.3f", s - r }')
    awk -v l="$LAG" -v t="$TOLERANCE" 'BEGIN { exit !(l > t) }' && REASONS+=("late_start")
    RUN_START_JSON="$RUN_START_EPOCH"
    LAG_JSON="$LAG"
else
    REASONS+=("unknown_run_start")
    RUN_START_JSON=null
    LAG_JSON=null
fi
awk -v el="$ELAPSED" -v ex="$EXPECTED_SEC" -v t="$TOLERANCE" 'BEGIN { exit !(el + t < ex) }' \
    && REASONS+=("early_end")
[[ -n "$INTERRUPTED" ]] && REASONS+=("interrupted_by_SIG${INTERRUPTED}")
[[ -z "$INTERRUPTED" ]] && (( SAR_EXIT != 0 )) && REASONS+=("sar_exit_${SAR_EXIT}")

has() { [[ " ${REASONS[*]-} " == *" $1"* ]]; }
if has sar_exit_; then
    COVERAGE="invalid_sar_failed"
elif has interrupted_by_; then
    COVERAGE="partial_interrupted"
elif has early_end; then
    COVERAGE="partial_early_end"
elif has late_start; then
    COVERAGE="partial_late_start"
elif has unknown_run_start; then
    COVERAGE="unknown_run_start"
else
    COVERAGE="full_from_run_start"
fi
case "$COVERAGE" in
    full_from_run_start) COMPLETE=true ;;
    unknown_run_start) COMPLETE=null ;;
    *) COMPLETE=false ;;
esac
REASONS_JSON=""
for r in "${REASONS[@]+"${REASONS[@]}"}"; do
    REASONS_JSON+="${REASONS_JSON:+, }\"$r\""
done
if [[ -n "$INTERRUPTED" ]]; then INTERRUPTED_JSON="\"SIG${INTERRUPTED}\""; else INTERRUPTED_JSON=null; fi

cat > "${PREFIX}_meta.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "role": "${ROLE}",
  "hostname": "${HOST}",
  "interval_sec": ${INTERVAL},
  "requested_duration_sec": ${DURATION},
  "requested_samples": ${COUNT},
  "expected_sampling_sec": ${EXPECTED_SEC},
  "run_start_epoch": ${RUN_START_JSON},
  "collector_start_epoch": ${START_EPOCH},
  "collector_end_epoch": ${END_EPOCH},
  "collector_elapsed_sec": ${ELAPSED},
  "start_lag_sec": ${LAG_JSON},
  "coverage_tolerance_sec": ${TOLERANCE},
  "coverage": "${COVERAGE}",
  "coverage_reasons": [${REASONS_JSON}],
  "complete_time_series": ${COMPLETE},
  "interrupted_by": ${INTERRUPTED_JSON},
  "utc_offset": "$(date +%z)",
  "sar_exit_code": ${SAR_EXIT},
  "metrics": {
    "cpu": "sar -u ALL",
    "memory": "sar -r",
    "swap": "sar -S",
    "disk_io": "sar -d -p",
    "network": "sar -n DEV",
    "filesystem_usage": "${FS_METRICS}",
    "disk_space_snapshots": "df -P -k at start and end"
  },
  "note": "coverage refers to this host only; any partial_* or invalid_* data is not a complete time series of the run"
}
EOF

if [[ -n "$INTERRUPTED" ]]; then
    echo "[!] interrupted by SIG${INTERRUPTED}; data is partial (coverage: ${COVERAGE})" >&2
    exit 1
fi
if (( SAR_EXIT != 0 )); then
    echo "[!] sar exited with ${SAR_EXIT}; see ${PREFIX}_sar.err" >&2
    exit 1
fi
echo "[+] Done (coverage: ${COVERAGE}). Metadata: ${PREFIX}_meta.json"
