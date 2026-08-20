# CLAUDE.md

## Overview

SpooNMAP is a Python 3.6+ wrapper that orchestrates masscan (fast port discovery) followed by nmap (service banner grabbing). Both external tools must be installed separately.

## Running the Tool

```bash
# Interactive mode (prompts for all options)
./spoonmap.py

# Config file mode (skip all prompts)
cp config.json.sample config.json
# Edit config.json, then:
./spoonmap.py
```

Run the test suite with:

```bash
uv run pytest tests/
uv run pytest tests/test_spoonmap.py::TestGenerateFindings  # single class
```

Pass `--cleanup [dir]` to remove prior scan output non-interactively (reads `output_path` from `config.json` if no directory is given).

## Architecture

### Host Discovery (Internal)

Internal discovery runs a single masscan sweep (no source-port override) followed by an optional concurrent nmap `-sn` sweep:

1. `_discover_internal_masscan()` — single masscan sweep across `DISCOVERY_MASSCAN_PORTS_INTERNAL` (10 ports: 22, 80, 135, 443, 445, 1433, 3306, 3389, 5985, 8080) with no `-g` flag. Rate is capped to `INTERNAL_DISCOVERY_MAX_RATE = 1000 pps`; at 1000 pps with a 60 s half-open timeout, state table entries peak at ~60 K. Uses `--retries 1`. Port list trimmed to 5 above `INTERNAL_DISCOVERY_STATE_CEILING = 262_144` (/14). `--wait` is adaptive: 1 s for 512 targets, 2 s for 4096, 3 s otherwise.
2. `_internal_host_discovery()` — for target counts at or below `HOST_DISCOVERY_NMAP_THRESHOLD = 65_536`, starts `_nmap_host_discovery()` in a background `threading.Thread` before the masscan sweep begins, then joins the thread after masscan returns. Returns masscan IPs union nmap IPs.

**Note**: The `-g 88` (Kerberos source port) bypass for Windows Firewall in AD environments is no longer attempted. The no-source-port sweep is used exclusively.

## Key Implementation Details

- **Shell injection prevention**: all subprocess calls use list form (`subprocess.Popen(cmd_list)`) not shell strings
- **IP deduplication**: uses Python `set()` in memory per port; also reads existing files on resume to avoid duplicates
- **Terminal state**: saves/restores `termios` state around each subprocess call; falls back to `stty sane`
- **Interrupt handling**: masscan raises `KeyboardInterrupt` and re-raises after cleanup; nmap uses `threading.Event` polling so all worker threads can be signaled cleanly
- **Resume behavior**: every resume gate goes through `_resume_cache_usable(output_file, baseline_mtime, description, is_xml=True)`, which requires the cached output to be present, no older than its baseline, **and** to contain usable results — XML must parse via `_parse_result_xml()`, plain-text host lists must be non-empty. A zero-length or truncated file (killed masscan/nmap) is rejected with a `re-running <description>: cached result was empty or unreadable` line instead of being cached as complete forever. mtimes are read through `_safe_mtime()` so a file removed between the `exists()` and `getmtime()` calls reads as stale rather than raising. `nmap_scan()` applies this to `nmap_results/portN.xml` (no mtime baseline). Discovery resume is additionally mtime-gated: `preprocess_targets()` writes `discovery/resolved_targets.txt` via `_write_if_changed()` (rewritten only when the resolved target set changes), and `_host_discovery()`, `mass_scan()`, `_nmap_port_discovery()`, and `_nmap_udp_discovery()` reuse cached output only when it is at least as new as `resolved_targets.txt`. So an unchanged `ranges.txt` skips discovery on resume; a changed one bumps the mtime and forces re-discovery of the affected phases.
- **Hostname support**: hostnames in the target file are resolved once at startup; nmap receives the original hostname (for SNI/vhost), masscan receives the resolved IP
- **Firewall state table safety**: internal discovery caps masscan at `INTERNAL_DISCOVERY_MAX_RATE = 1000 pps`; at that rate with a 60 s half-open timeout, concurrent state entries peak at ~60 K regardless of target range size; for ranges above `INTERNAL_DISCOVERY_STATE_CEILING = 262_144` hosts the port list is trimmed from 10 to 5 to keep total packet volume bounded
- **Honeypot/tarpit detection**: `mass_scan()` flags hosts open on ≥`HONEYPOT_OPEN_PORT_FRACTION` (90%) of scanned TCP ports (min sample `HONEYPOT_MIN_PORTS_SCANNED = 10`) as likely tarpits (LaBrea, portspoof) via `_flag_suspected_tarpits()`/`_report_suspected_tarpits()`, writing `discovery/suspected_tarpits.txt`. Separately, `_count_unmatched_service_ports()` reads `nmap_results/*.xml` and counts open ports whose `-sV` probe captured a `servicefp` (no signature match); `≥HONEYPOT_MIN_UNMATCHED_PORTS = 3` such ports on one host is consistent with decoys (e.g. Artillery) that return random data on full connect. Both signals surface as a single "Likely Honeypot / Decoy Host" MEDIUM finding in `generate_findings()`.
