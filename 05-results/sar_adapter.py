#!/usr/bin/env python3
"""
Results: adapters for connector-VM CPU and memory samples exported with sysstat's sadf (one supported
format each).

Author: Slihoczki Richárd Alex (BME BSc Thesis)
Architecture: HPE Aruba SSE Cloud Edge with two-host VMware ESXi testbed.

SUPPORTED FORMATS (exactly these; anything else is rejected, never guessed)
  The binary file written by 01-load-test/collect_connector_telemetry.sh (telemetry_<run>_<role>_<host>.sa)
  exported ON THE VM with:
      sadf -d telemetry_<...>.sa -- -u ALL > telemetry_<...>_cpu_sadf.csv     (CPU)
      sadf -d telemetry_<...>.sa -- -r     > telemetry_<...>_mem_sadf.csv     (memory)
  sadf -d writes semicolon-separated records with a header line starting with "# hostname;interval;timestamp;"
  and timestamps in UTC ("YYYY-MM-DD HH:MM:SS UTC").

CPU (load_sadf_cpu); the aggregate CPU row is "-1" (or "all"). Accepted column sets:
      -u ALL : %usr %nice %sys %iowait %steal %irq %soft %guest %gnice %idle
      -u     : %user %nice %system %iowait %steal %idle   (%system then includes irq/softirq time;
                                                          irq_pct, soft_pct, guest_pct, gnice_pct stay NaN)
  Every component is kept under an explicit name (usr_pct, nice_pct, sys_pct, iowait_pct, steal_pct,
  irq_pct, soft_pct, guest_pct, gnice_pct, idle_pct). Two derived values with different formulas:
      cpu_not_idle_pct          = 100 - %idle             (the sar view: iowait counts as NOT idle)
      cpu_busy_excl_iowait_pct  = 100 - %idle - %iowait   (same FORMULA as the scaler's /proc/stat value,
                                                          which counts iowait as idle; the scaler samples
                                                          another interval with another tool, so the two
                                                          series are comparable, not identical)
  Temporal interpretation (ASSUMPTION awaiting a real export): a CPU record is an AVERAGE over the
  interval [t - interval, t], where t is the record's timestamp (sysstat stamps a record when it reads
  the counters at the end of the interval).

Memory (load_sadf_mem); no CPU column. Required columns kbmemfree, kbmemused, %memused; kbavail is
  used when present (sysstat versions without it give NaN plus an issue); other columns are ignored.
  Defined metrics:
      mem_used_pct      = %memused as computed by the installed sysstat (its definition of "used" differs
                          between sysstat versions; it is NOT re-derived here: record `sadf -V`)
      mem_available_kb  = kbavail (the kernel's MemAvailable estimate)
      mem_free_kb       = kbmemfree
  Temporal interpretation (ASSUMPTION awaiting a real export): a memory record is an INSTANTANEOUS
  reading at t (memory counters are levels, not averaged over the interval).

Both: records with an identical timestamp are duplicates; only the first is kept and the others are
reported. CPU records closer together than their interval overlap; they are reported here and
excluded from aggregation by derive.py (never counted twice).

NOT SUPPORTED: the human-readable sar text output (*_sar.txt). Its layout depends on the sysstat
version, locale and S_TIME_FORMAT, it carries only a time of day (date in the header, local time
zone) and interleaves several activities; it is rejected with an explanation.

OPEN DATA REQUIREMENT: these adapters were written from the documented sadf -d layout and tested on
synthetic files only. Real exports from a connector VM plus `sar -V` / `sadf -V` (sysstat version)
are needed to confirm the headers, value formats and the temporal interpretation above.
"""

import math
from datetime import datetime, timezone

COLUMN_SETS = {
    "u_all": ["%usr", "%nice", "%sys", "%iowait", "%steal", "%irq", "%soft", "%guest", "%gnice", "%idle"],
    "u": ["%user", "%nice", "%system", "%iowait", "%steal", "%idle"],
}
COMPONENT_NAMES = {"%usr": "usr_pct", "%user": "usr_pct", "%nice": "nice_pct", "%sys": "sys_pct",
                   "%system": "sys_pct", "%iowait": "iowait_pct", "%steal": "steal_pct", "%irq": "irq_pct",
                   "%soft": "soft_pct", "%guest": "guest_pct", "%gnice": "gnice_pct", "%idle": "idle_pct"}
CPU_COMPONENTS = ["usr_pct", "nice_pct", "sys_pct", "iowait_pct", "steal_pct", "irq_pct", "soft_pct",
                  "guest_pct", "gnice_pct", "idle_pct"]
CPU_DERIVED = {"cpu_not_idle_pct": "100 - %idle",
               "cpu_busy_excl_iowait_pct": "100 - %idle - %iowait (scaler formula: iowait counted as idle)"}
BASE_COLUMNS = ["hostname", "interval", "timestamp", "CPU"]
MEM_BASE_COLUMNS = ["hostname", "interval", "timestamp"]
MEM_REQUIRED = ["kbmemfree", "kbmemused", "%memused"]
MEM_DEFINITIONS = {"mem_used_pct": "%memused as computed by the installed sysstat (version dependent)",
                   "mem_available_kb": "kbavail (kernel MemAvailable estimate); NaN if the column is absent",
                   "mem_free_kb": "kbmemfree"}
SOURCE_LABEL = "sar (sysstat on the connector VM, sadf -d export)"
CPU_TEMPORAL = "interval average over [t - interval, t] (assumption, awaiting a real export)"
MEM_TEMPORAL = "instantaneous reading at t (assumption, awaiting a real export)"
NAN = float("nan")


class UnsupportedFormat(ValueError):
    pass


def _parse_ts(text):
    text = text.strip()
    if not text.endswith(" UTC"):
        raise UnsupportedFormat(f"timestamp {text!r} is not in UTC; export with plain sadf -d (no -t / -T)")
    return datetime.strptime(text[:-4], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def _lines(text, source_name):
    lines = [line.rstrip("\r\n") for line in (text or "").splitlines() if line.strip()]
    if not lines:
        raise UnsupportedFormat(f"{source_name}: empty file")
    if not lines[0].startswith("# hostname;"):
        hint = " (this looks like sar text output, which is not supported)" if "CPU" in lines[0] or "Linux" in lines[0] \
            else ""
        raise UnsupportedFormat(f"{source_name}: first line is not a sadf -d header{hint}")
    return lines, lines[0][2:].split(";")


def _dedup(rows, issues):
    """Sorts by time; keeps the first of records with an identical timestamp and reports the rest."""
    rows.sort(key=lambda r: r["utc"])
    out, dups = [], 0
    for r in rows:
        if out and r["utc"] == out[-1]["utc"]:
            dups += 1
            continue
        out.append(r)
    if dups:
        issues.append(f"{dups} duplicate record(s) with an identical timestamp; only the first of each kept")
    return out, dups


def _overlaps(rows):
    """CPU records whose interval [t - interval, t] starts before the previous record's end."""
    n = 0
    for prev, cur in zip(rows, rows[1:]):
        if (cur["utc"] - prev["utc"]).total_seconds() < cur["interval_sec"] - 1e-9:
            n += 1
    return n


def load_sadf_cpu(text, source_name="<text>"):
    """Returns {"host", "interval_sec", "column_set", "rows": [{utc, interval_sec, <components>,
    cpu_not_idle_pct, cpu_busy_excl_iowait_pct}], "issues", "duplicates", "overlaps", "temporal",
    "definitions"}. Raises UnsupportedFormat for anything that is not the supported format."""
    lines, header = _lines(text, source_name)
    if header[:4] != BASE_COLUMNS:
        raise UnsupportedFormat(f"{source_name}: unexpected leading columns {header[:4]}")
    cpu_cols = header[4:]
    column_set = next((k for k, v in COLUMN_SETS.items() if v == cpu_cols), None)
    if column_set is None:
        raise UnsupportedFormat(f"{source_name}: CPU columns {cpu_cols} are not a supported set "
                                f"({', '.join(' '.join(v) for v in COLUMN_SETS.values())})")
    rows, issues, hosts, intervals = [], [], set(), set()
    for no, line in enumerate(lines[1:], 2):
        if line.startswith("#"):
            if line[2:].split(";") != header:
                raise UnsupportedFormat(f"{source_name}: line {no}: a second, different header (several activities?)")
            continue
        fields = line.split(";")
        if len(fields) != len(header):
            issues.append(f"line {no}: {len(fields)} fields, expected {len(header)}; skipped")
            continue
        if fields[3].strip() not in ("-1", "all"):
            continue   # per-CPU rows are not used
        try:
            values = {c: float(v.replace(",", ".")) for c, v in zip(cpu_cols, fields[4:])}
            utc = _parse_ts(fields[2])
            interval = int(fields[1])
        except UnsupportedFormat:
            raise
        except ValueError as exc:
            issues.append(f"line {no}: unparseable value ({exc}); skipped")
            continue
        if interval <= 0:
            issues.append(f"line {no}: interval {interval} is not positive; skipped")
            continue
        if any(math.isnan(v) or v < 0 or v > 100.0001 for v in values.values()):
            issues.append(f"line {no}: percentage outside 0..100; skipped")
            continue
        hosts.add(fields[0])
        intervals.add(interval)
        row = {"utc": utc, "interval_sec": interval}
        row.update({name: NAN for name in CPU_COMPONENTS})
        row.update({COMPONENT_NAMES[c]: v for c, v in values.items()})
        row["cpu_not_idle_pct"] = round(100.0 - values["%idle"], 3)
        row["cpu_busy_excl_iowait_pct"] = round(100.0 - values["%idle"] - values["%iowait"], 3)
        rows.append(row)
    if len(hosts) > 1:
        raise UnsupportedFormat(f"{source_name}: several host names {sorted(hosts)} in one file")
    rows, dups = _dedup(rows, issues)
    overlaps = _overlaps(rows)
    if overlaps:
        issues.append(f"{overlaps} record(s) overlap the previous record's interval; excluded from aggregation")
    return {"host": next(iter(hosts), ""), "interval_sec": sorted(intervals), "column_set": column_set,
            "rows": rows, "issues": issues, "duplicates": dups, "overlaps": overlaps, "temporal": CPU_TEMPORAL,
            "definitions": CPU_DERIVED, "source_label": SOURCE_LABEL}


def load_sadf_mem(text, source_name="<text>"):
    """Returns {"host", "interval_sec", "columns", "rows": [{utc, interval_sec, mem_used_pct,
    mem_available_kb, mem_free_kb}], "issues", "duplicates", "temporal", "definitions"}."""
    lines, header = _lines(text, source_name)
    if header[:3] != MEM_BASE_COLUMNS or (len(header) > 3 and header[3] == "CPU"):
        raise UnsupportedFormat(f"{source_name}: not a sadf -d -r export (leading columns {header[:4]})")
    cols = header[3:]
    missing = [c for c in MEM_REQUIRED if c not in cols]
    if missing:
        raise UnsupportedFormat(f"{source_name}: memory columns {missing} missing (have {cols})")
    has_avail = "kbavail" in cols
    rows, issues, hosts, intervals = [], [], set(), set()
    if not has_avail:
        issues.append("column kbavail absent (older sysstat?): mem_available_kb is NaN")
    for no, line in enumerate(lines[1:], 2):
        if line.startswith("#"):
            if line[2:].split(";") != header:
                raise UnsupportedFormat(f"{source_name}: line {no}: a second, different header (several activities?)")
            continue
        fields = line.split(";")
        if len(fields) != len(header):
            issues.append(f"line {no}: {len(fields)} fields, expected {len(header)}; skipped")
            continue
        values = dict(zip(cols, fields[3:]))
        try:
            utc = _parse_ts(fields[2])
            interval = int(fields[1])
            used = float(values["%memused"].replace(",", "."))
            free = float(values["kbmemfree"].replace(",", "."))
            avail = float(values["kbavail"].replace(",", ".")) if has_avail else NAN
        except UnsupportedFormat:
            raise
        except ValueError as exc:
            issues.append(f"line {no}: unparseable value ({exc}); skipped")
            continue
        if interval <= 0:
            issues.append(f"line {no}: interval {interval} is not positive; skipped")
            continue
        if math.isnan(used) or not 0 <= used <= 100.0001 or free < 0 or (has_avail and avail < 0):
            issues.append(f"line {no}: value out of range; skipped")
            continue
        hosts.add(fields[0])
        intervals.add(interval)
        rows.append({"utc": utc, "interval_sec": interval, "mem_used_pct": used, "mem_available_kb": avail,
                     "mem_free_kb": free})
    if len(hosts) > 1:
        raise UnsupportedFormat(f"{source_name}: several host names {sorted(hosts)} in one file")
    rows, dups = _dedup(rows, issues)
    return {"host": next(iter(hosts), ""), "interval_sec": sorted(intervals), "columns": cols, "rows": rows,
            "issues": issues, "duplicates": dups, "temporal": MEM_TEMPORAL, "definitions": MEM_DEFINITIONS,
            "source_label": SOURCE_LABEL}
