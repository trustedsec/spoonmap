# SpooNMAP

[![CI](https://github.com/trustedsec/spoonmap/actions/workflows/ci.yml/badge.svg)](https://github.com/trustedsec/spoonmap/actions/workflows/ci.yml)

## Dependencies
This script is a wrapper for masscan and nmap. nmap handles host discovery and (for smaller scans) port discovery, service banner grabbing, and NSE scripts. Masscan is used for large-scale port discovery where raw speed matters. Install both from your favourite package manager or from source.

Python 3.6+ is required (uses f-strings).

## Usage
Simply executing the script will prompt you for all required options.

If you use [uv](https://docs.astral.sh/uv/), you can run without a separate virtual environment:

```bash
uv run spoonmap.py
```

Or invoke directly if the script is executable:

```
# ./spoonmap.py

________                   _____   _______  _________________
__  ___/______________________  | / /__   |/  /__    |__  __ \
_____ \___  __ \  __ \  __ \_   |/ /__  /|_/ /__  /| |_  /_/ /
____/ /__  /_/ / /_/ / /_/ /  /|  / _  /  / / _  ___ |  ____/
/____/ _  .___/\____/\____//_/ |_/  /_/  /_/  /_/  |_/_/
       /_/


Service Categories (comma-separated numbers, default: All)
	(1) Web          [80, 443, 7001, 7002, 8000, 8080, 8081, 8443, 8888, 9090, 10443]
	(2) Database     [1433, U:1434, 1521, 3306, 5432, 6379, 9200, 27017]
	(3) Remote Management  [22, 23, 3389, 5900, 5901, 6129, 1723, 5985, 5986]
	(4) Email        [25, 110, 143, 465, 587, 993, 995]
	(5) LDAP         [389, 636]
	(6) Network Infrastructure  [53, 179, U:500, U:161, U:623, U:631, U:1194, 1194]
	(7) File Transfer      [21, 111]
	(8) SMB          [445, 135, 139, U:137]
	(9) Specialized  [1090, 3300, 4786, 6970, 2375, 4243, 9100, 8530, 8531]
	(10) Containers & Debuggers  [2377, 10250, 8001, 9229, 2345, 5005, 61616, 8009, 6000]
	(11) Local LLM  [11434, 1234, 7860, 5000, 5001, 1337, 3000, 8000, 8080]
	(12) Full Port Scan  [1-65535, TCP only — no UDP]
	(c) Custom Port Scan  [enter your own comma-separated ports]

(The Full Port Scan number increments automatically with the number of categories.)

**Full Port Scan is TCP only.** It sweeps TCP 1-65535 and runs no UDP discovery at
all, so every `U:` port listed in the categories above — SNMP (U:161), IKE (U:500),
IPMI (U:623), IPP (U:631), OpenVPN (U:1194), NetBIOS (U:137), SQL Browser (U:1434) —
is skipped, along with the NSE scripts and findings that depend on them. It is
*wider* than All on TCP and *narrower* on UDP. For both, run All and Full as two
passes, or use the Custom option with the UDP ports appended
(e.g. `1-65535,U:161,U:500,U:623`).

Which categories would you like to scan (e.g. 1,3 — default: All)?

Would you like to enumerate service banners for any identified services (default: Yes)?

Would you like to run NSE security scripts on identified services (default: No)?

Target Scan
	(1) External
	(2) Internal

Is this an internal or external scan (default: External)?

How fast would you like to scan (default: 20000 packets/second)?

Please enter the full path for the file containing target hosts (default: /opt/spoonmap/ranges.txt):

Would you like to exclude any hosts? (default: No)

Run host discovery before port scanning (default: Yes)?

Tune advanced settings (nmap threads, masscan batch size, nmap work-unit threshold)? (default: No)
```

You can also create a `config.json` file (based on `config.json.sample`) to skip all prompts:

```json
{
    "scan_categories": ["Web", "Database", "Remote Management"],
    "banner_scan": "True",
    "script_scan": "False",
    "host_discovery": "True",
    "target_scan": "Internal",
    "max_rate": "2000",
    "target_file": "ranges.txt",
    "output_path": "./",
    "exclusions_file": "exclusions.txt",
    "nmap_threads": 5,
    "masscan_batch_size": 5,
    "nmap_threshold": 5000000
}
```

To scan all categories, set `"scan_categories": "All"`.
To scan all 65535 TCP ports, set `"scan_categories": "Full"` — note this is **TCP only** and performs no UDP discovery.
For a fully custom port list, omit `scan_categories` and use `"dest_ports": ["80","443","U:53"]` instead.
UDP ports are specified with a `U:` prefix (e.g. `"U:53"`).

When you answer the interactive prompts, the selected options are written to `config.json` before the scan begins. The generated file documents each editable field the same way `config.json.sample` does, and carries a `__generated_by_prompts__` marker key. This means an interrupted interactive scan can be resumed the same way as a config-driven one — just re-run with `--resume`, and all prompts are skipped.

If a previous scan's output is detected in `output_path`, the tool offers three choices: **[d]elete** (remove the prior output and start fresh), **[a]ppend** (keep the prior output but re-run all phases), or **[r]esume** (keep the prior output and skip already-completed work, exactly as the `--resume` flag does).

**Changing options on a re-run.** Picking **[d]elete** or **[a]ppend** re-asks every option, with the saved `config.json` values pre-filled as the defaults — so pressing Enter through the prompts reproduces the previous scan, and you can change just the ports, rate, or targets you care about. **[r]esume** skips the prompts, since it is continuing the same scan. The re-prompt applies only to a `config.json` the tool generated (one carrying `__generated_by_prompts__`); a config you wrote by hand keeps the strict skip-all-prompts behavior described above. Remove that key to opt out, or delete `config.json` entirely to start from scratch.

Re-answering the prompts rewrites `config.json`, **merging** rather than overwriting: any keys you added to the file by hand are preserved.

### Scanning a target without a file

To scan a single address (or a short list) without editing a target file, use `--target`:

```
./spoonmap.py --target 10.0.0.5
./spoonmap.py --target 10.0.0.0/24
./spoonmap.py --target 10.0.0.5,10.0.1.0/24,10.0.2.1-10.0.2.9
```

The value accepts anything a target file line accepts — bare IP, CIDR, `A-B` range, or `address netmask` — comma-separated. It is validated before the scan starts: a malformed or IPv6 address aborts with a non-zero exit naming the offending entry, rather than running cleanly over an empty target set.

`--target` takes precedence over both `config.json`'s `target_file` and the interactive prompt, so it also works in otherwise fully non-interactive runs. The addresses are written to `cli_targets.txt` in `output_path`; **`ranges.txt` is never modified**, so your engagement scope file stays intact and there is a record on disk of what each run actually targeted.

To resume an interrupted scan without any prompts, use the `--resume` flag:

```
./spoonmap.py --resume
# or
uv run spoonmap.py --resume
```

`--resume` reuses completed **host discovery** and **port discovery** whose output is newer than `resolved_targets.txt`, loads the pre-existing live host lists, and continues from where it left off. Because `resolved_targets.txt` is only rewritten when the resolved target set actually changes, resuming with an unchanged `ranges.txt` skips discovery entirely (no re-scan). If `ranges.txt` changed since the last run, `resolved_targets.txt` is rewritten with a newer timestamp and any discovery output that now pre-dates it — host and port — is automatically re-run so newly added ranges are not missed. nmap banner/script results are always resumed (existing `nmap_results/portN.xml` files are skipped unconditionally). Resume can also be enabled via `config.json` with `"resume": "True"`.

To remove scan data non-interactively, use the `--cleanup` flag:

```
# Path taken from output_path in config.json
./spoonmap.py --cleanup
# or
uv run spoonmap.py --cleanup

# Or specify the directory explicitly
./spoonmap.py --cleanup /path/to/output
```

## Target File (ranges.txt)

`ranges.txt` is committed to the repository as an empty placeholder and is marked `skip-worktree`, so git will never stage local edits to it. Fill it with your target ranges freely — they will never be accidentally committed.

To manage the skip-worktree flag manually:

```bash
# Stop tracking local changes (already set — no action needed on a fresh clone)
git update-index --skip-worktree ranges.txt

# Resume tracking (e.g. to intentionally commit changes)
git update-index --no-skip-worktree ranges.txt
```

## config.json Parameters

| Key | Values | Notes |
|-----|--------|-------|
| `scan_categories` | `"All"`, `"Full"`, or array of category names | `"Full"` scans all 65535 **TCP** ports and no UDP; e.g. `["Web","Database"]`; omit to use `dest_ports` |
| `dest_ports` | Array of port strings | Overrides `scan_categories`; use `U:` prefix for UDP |
| `banner_scan` | `"True"` / `"False"` | Runs nmap -sV against discovered hosts |
| `script_scan` | `"True"` / `"False"` | Runs NSE security scripts (implies `banner_scan`) |
| `host_discovery` | `"True"` / `"False"` | Run host discovery before port scanning to narrow the target set (default: True) |
| `target_scan` | `"External"` / `"Internal"` | Selects discovery port lists and NSE script sets; no source-port override is applied |
| `max_rate` | Packets/second string | See rate guidance below |
| `target_file` | Path | One IP, CIDR, or hostname per line; `ranges.txt` is committed as a blank placeholder (see below) |
| `output_path` | Path | Directory for all output; relative paths resolve to script dir |
| `exclusions_file` | Path | IPs/CIDRs to exclude; SpooNMAP pre-computes the set intersection with the target file and passes only the net target IPs to masscan (see below) |
| `nmap_threads` | Integer | Concurrent nmap processes (default: 5); prompted under "Tune advanced settings" |
| `masscan_batch_size` | Integer | Ports per masscan invocation (default: 5); prompted under "Tune advanced settings" |
| `nmap_threshold` | Integer | Work-unit threshold for tool selection (default: 5,000,000 — see below); prompted under "Tune advanced settings" |
| `resume` | `"True"` / `"False"` | Skip completed port discovery on restart (default: False) |
| `__generated_by_prompts__` | String | Present only in a config the prompts wrote. While it is present, **[d]elete**/**[a]ppend** re-ask the options using this file's values as defaults; remove it to keep them fixed |

Keys beginning and ending with `__` are documentation and are ignored by the loader, so you can annotate the file freely — a re-prompted run preserves them.

The three concurrency and tool-selection keys above are not asked about individually. The prompts end with a single **"Tune advanced settings?"** question (default: No); answering yes asks for all three, pre-filled with their current values.

### max_rate guidance
Rates that are too high can create a denial-of-service condition — use caution.

| Scan type | Default `max_rate` | Full scan cap |
|-----------|-------------------|---------------|
| External  | 20,000 pps        | 10,000 pps    |
| Internal  | 2,000 pps         | 1,000 pps     |

The adaptive probe phase and category/custom batched scans always use the full `max_rate`.
Full port scans (`-p 1-65535`) are capped to half the default to avoid saturation.

### Host discovery

#### Exclusion pre-filtering

Before running any discovery sweep, SpooNMAP computes the **set difference** between the target CIDRs and the exclusion CIDRs in Python and writes the result to `discovery/discovery_targets_filtered.txt`. Masscan receives this pre-filtered file instead of the original target file and no `--excludefile` argument.

Without pre-filtering, masscan builds its randomisation permutation over the full target address space and skips excluded IPs at send time, so the `--max-rate` applies to iterations rather than actual packets — severely degrading effective throughput when most IPs are excluded (e.g. 3.19 M targets with 2.96 M excluded → ~72 effective pps instead of 1,000). Pre-filtering ensures the permutation covers only the hosts masscan will actually probe.

The startup "Target Hosts" count reflects the **actual intersection** of target and exclusion ranges, not simple arithmetic subtraction. The exclusion file may accept CIDR notation, range notation (`A.B.C.D-E.F.G.H`), inline comments, and netmask notation (`A.B.C.D M.M.M.M`).

Live **masscan progress** (rate, % done, time remaining) is streamed to the terminal during discovery and updates in place on a single line.

#### External scans

External host discovery runs two sweeps and takes the union:

1. **masscan sweep** across `DISCOVERY_MASSCAN_PORTS_EXTERNAL` — a curated 17-port set chosen to maximise host visibility (`--retries 2`); `--wait` scales with target count (1–3 s)
2. **nmap -sn** with ICMP echo (`-PE`) only

#### Internal scans

Internal host discovery uses a single masscan sweep followed by an optional concurrent nmap `-sn` pass:

1. **masscan sweep** across `DISCOVERY_MASSCAN_PORTS_INTERNAL` (10 ports: 22, 80, 135, 443, 445, 1433, 3306, 3389, 5985, 8080) with no source-port override (`--retries 1`); `--wait` scales with target count
2. **nmap -sn** with ICMP echo (`-PE`) only — runs **concurrently** with masscan (target sets ≤ 65,536 hosts; skipped for larger ranges)

The masscan sweep rate is capped to **1,000 pps** regardless of `max_rate`. At 1,000 pps and a typical 60-second firewall half-open timeout, peak concurrent state entries stay at ~60,000 — safe for enterprise inline firewalls carrying production traffic. For very large ranges (> 262,144 hosts), the port list trims from 10 to 5 to keep total packet volume bounded.

> **Note:** The Windows Firewall Kerberos bypass (`--source-port 88`) used in earlier versions has been removed. The single no-source-port sweep is used for all internal scans.

### Intelligent tool selection: masscan vs nmap (port discovery)

SpooNMAP automatically selects the best port discovery tool for the job based on the size of the scan:

```
work_units = effective_host_count × port_count
```

- **nmap** is used when `work_units ≤ nmap_threshold` (default: 5,000,000)
- **masscan** is used for larger scans where its raw speed advantage matters

**Why?** Masscan's stateless TCP stack is unreliable for small target sets — it misses open ports that nmap's full 3-way handshake reliably finds. Internal masscan throughput is also capped at ~200 work-units/sec (1,000 pps ÷ 5 retries), while nmap -T4 handles ~10,000 work-units/sec across hosts in parallel.

| Scenario | Masscan (internal) | Nmap -T4 |
|---|---|---|
| 38 hosts × 65,535 ports | ~3.5 hours | ~4 min |
| 512 hosts × 65,535 ports | ~46 hours | ~56 min |
| 512 hosts × 50 ports | ~3.5 min | ~2.5 sec |
| 10,000 hosts × 50 ports | ~1.1 hr | ~50 sec |

The default threshold of 5,000,000 covers roughly 76 hosts × full-port scan or 5,000 hosts × 1,000 targeted ports. If you have a high-rate external setup (100k+ pps), lower this to ~500,000 so masscan's speed advantage kicks in sooner.

The tool selection is printed at scan time:

```
Work units (38 hosts × 65535 ports = 2,490,330) ≤ threshold (5,000,000): using nmap for port discovery
```

or:

```
Work units (50,000 hosts × 65535 ports = 3,276,750,000) > threshold (5,000,000): using masscan for port discovery
```

### Inter-scan wait (automatic)
When scanning small target ranges (e.g. a /24), each per-port masscan invocation completes in a fraction of a second, producing rapid back-to-back traffic bursts that can saturate the local network. SpooNMAP automatically passes `--wait N` to masscan so the process lingers after its last packet, acting as a natural cooldown between invocations.

The wait is derived from the target host count and the configured `max_rate`:

```
scan_duration  = host_count / max_rate   # rough seconds per port
wait_secs      = max(0, 30 - scan_duration)
```

| Target | Hosts | max_rate | wait_secs |
|--------|-------|----------|-----------|
| /24 | 256 | 2,000 pps (internal default) | 29 s |
| /20 | 4,096 | 2,000 pps | 27 s |
| /16 | 65,536 | 2,000 pps | 0 s (no wait needed) |
| /24 | 256 | 20,000 pps (external default) | 29 s |
| /16 | 65,536 | 20,000 pps | 26 s |

A message is printed when a non-zero wait is applied:

```
Inter-scan wait: 29s (target ~256 hosts)
```

## Output Structure

```
<output_path>/
  discovery/
    resolved_targets.txt            # resolved IPs/CIDRs (input to host discovery)
    ip_hostname_map.json            # hostname → resolved IP mapping
    discovery_targets_filtered.txt  # pre-filtered target CIDRs (targets minus exclusions)
    discovery_masscan_external.xml  # masscan TCP SYN sweep XML (external scans)
    discovery_masscan_internal.xml  # masscan TCP SYN sweep XML (internal scans)
    discovery_nmap.xml              # nmap -sn ICMP XML (external; internal sets ≤ 65,536 hosts)
    live_hosts_discovery.txt        # live IPs found by host discovery phase
    masscan_results/portN.xml   # raw masscan XML per port (masscan port discovery path)
    live_hosts/portN.txt        # deduplicated IPs per port
  nmap_results/portN.xml        # nmap banner (-sV) XML per port
  nmap_results/portN.gnmap      # nmap greppable (-oG) output per port
  nse_results/portN.xml         # nmap NSE script XML per port (script_scan only)
  all_live_hosts.txt            # union of all live IPs
  spoonmap_output.xml           # merged nmap XML (or masscan if no banner scan)
  spoonmap_output.json          # same data as JSON — list of host objects by IP
  spoonmap_output.gnmap         # merged greppable output, one line per host (banner scan only)
  findings.txt                  # severity-sorted findings report (script_scan only)
  findings.md                   # same report in Markdown table format
  findings.json                 # same report as a JSON array (script_scan only)
```

### Greppable output

`spoonmap_output.gnmap` is nmap's grepable format — one line per host — merged across every port scanned in the banner pass:

```
# SpooNMAP aggregated greppable output
Host: 10.0.0.5 (web01)	Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/tcp//http//nginx 1.18/
Host: 10.0.0.200 ()	Ports: 445/open/tcp//microsoft-ds///
# SpooNMAP done: 2 hosts
```

Because each port is scanned by its own nmap invocation, nmap writes one `nmap_results/portN.gnmap` per port and SpooNMAP merges them, so a host open on three ports is one line with three port entries rather than three lines — matching how `spoonmap_output.xml`/`.json` merge the same hosts, and keeping line counts usable as host counts. Hosts are in numeric IP order and port entries in numeric port order, so the file is stable across runs and diffable between scans.

Written for the banner scan only; a masscan-only run (`banner_scan` off) produces no grepable output. If a port has nmap XML but no `.gnmap` — a scan resumed from before this output existed — those ports are named in a warning rather than silently dropped from the aggregate.

`spoonmap_output.json` consolidates hosts across all per-port files, merging ports for the same IP:

```json
[
  {
    "ip": "10.0.0.1",
    "hostname": "host.example.com",
    "ports": [
      {"protocol": "tcp", "portid": "445", "state": "open",
       "service": "microsoft-ds", "product": "", "version": "", "scripts": {}}
    ],
    "hostscripts": {"smb2-security-mode": "Message signing enabled but not required"}
  }
]
```

`findings.json` is a flat array with one object per finding:

```json
[
  {"severity": "HIGH", "host": "10.0.0.1", "port": "tcp/22",
   "title": "Weak SSH Auth", "detail": "..."}
]
```

## NSE Script Scanning and Findings

When `script_scan` is enabled, nmap runs targeted NSE scripts against relevant ports. Scripts are chosen based on scan type (External vs Internal):

**External scans** run: `ftp-anon`, `ssh-auth-methods`, `ssh2-enum-algos`, `*-ntlm-info`, `ssl-cert`, `ms-sql-ntlm-info`, `rdp-ntlm-info`, `docker-version`, `snmp-brute`, `snmp-sysdescr`, `ajp-headers`, `x11-access`, `dameware-detect` (custom, 6129), `cucm-detect` (custom, 6970), `ipmi-version`, `ipmi-cipher-zero`, `ipmi-hashdump` (custom, U:623), `ike-version` (U:500), `openvpn-detect` (custom, U:1194/1194), `vnc-info`, `realvnc-auth-bypass`, `vnc-title` (5900, 5901), `ollama-detect` (custom, 11434), `openai-api-detect` (custom, 1234/1337/3000/8000), `gradio-detect` (custom, 7860), `koboldcpp-detect` (custom, 5001)

**Internal scans** run: `ftp-anon`, `rpcinfo`, `nfs-showmount`, `nfs-ls`, `smb-security-mode`, `smb2-security-mode`, `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-double-pulsar-backdoor`, `smb-vuln-cve-2017-7494`, `rmi-dumpregistry`, `ms-sql-info`, `docker-version`, `snmp-brute`, `snmp-sysdescr`, `ajp-headers`, `x11-access`, `jdwp-info` (5005), `http-title` (8001), `banner` (61616), `dameware-detect` (custom, 6129), `cucm-detect` (custom, 6970), `nodejs-inspector` (custom, 9229), `kubelet-anon-check` (custom, 10250), `delve-debugger` (custom, 2345), `ipmi-version`, `ipmi-cipher-zero`, `ipmi-hashdump` (custom, U:623), `ike-version` (U:500), `openvpn-detect` (custom, U:1194/1194), `vnc-info`, `realvnc-auth-bypass`, `vnc-title` (5900, 5901), `ollama-detect` (custom, 11434), `openai-api-detect` (custom, 1234/1337/3000/8000), `gradio-detect` (custom, 7860), `koboldcpp-detect` (custom, 5001)

Port 9100 (JetDirect raw printing protocol) is included in the Specialized category. Hosts with port 9100 open are identified as printers; SNMP default community string and anonymous FTP findings are suppressed for these hosts to reduce noise.

After scanning, `generate_findings()` parses all nmap XML results and produces severity-sorted `findings.txt`, `findings.md`, and `findings.json` reports. Findings include:

| Severity | Finding |
|----------|---------|
| CRITICAL | MS17-010 EternalBlue (CVE-2017-0143) |
| CRITICAL | MS08-067 NetAPI / Conficker (CVE-2008-4250) |
| CRITICAL | DoublePulsar backdoor active |
| CRITICAL | SambaCry (CVE-2017-7494) |
| CRITICAL | Unauthenticated Docker API (2375/4243, confirmed by `docker-version`) |
| CRITICAL | DameWare Mini Remote Control Detected (6129, confirmed by custom NSE — CVE-2019-3980) |
| CRITICAL | JDWP Java Debugger Exposed (5005, confirmed by `jdwp-info`) |
| CRITICAL | Node.js Inspector Port Exposed (9229, confirmed by custom NSE) |
| CRITICAL | Delve Go Debugger Exposed (2345, confirmed by custom NSE) |
| CRITICAL | Kubernetes Kubelet Anonymous Access (10250, confirmed by custom NSE) |
| CRITICAL | SNMP default or accepts-any community — read-write on a network device (router/switch/firewall) |
| CRITICAL | IPMI Cipher Zero Authentication Bypass |
| CRITICAL | VNC No Authentication Required (5900/5901, confirmed by `vnc-info`) |
| CRITICAL | Service Exposed Externally (Docker API, Swarm, debugger/container ports — external scan only) |
| HIGH | Weak SSH authentication (password/keyboard-interactive — external scan only) |
| HIGH | NTLM information disclosure (external scan only) |
| HIGH | SMBv1/SMBv2 signing not required |
| HIGH | NFS shares exposed |
| HIGH | DameWare Remote Control Detected (6129, banner fallback — NSE not conclusive) |
| HIGH | SAP Gateway detected (3300) |
| HIGH | Cisco Smart Install Vulnerable (4786, confirmed by custom NSE — CVE-2018-0171) |
| HIGH | Cisco CUCM TFTP Server Confirmed (6970, confirmed by custom NSE) |
| HIGH | AJP Connector exposed (8009, Ghostcat CVE-2020-1938) |
| HIGH | X11 Display accessible (6000, confirmed by `x11-access`) |
| HIGH | ActiveMQ broker exposed (61616, CVE-2023-46604) |
| HIGH | Ollama LLM API Unauthenticated (11434, custom NSE — external scan only at HIGH) |
| HIGH | OpenAI-Compatible LLM API Unauthenticated (1234/1337/3000/8000, custom NSE — external scan only at HIGH) |
| HIGH | Gradio LLM Web UI Accessible (7860, custom NSE — external scan only at HIGH) |
| HIGH | KoboldCpp LLM API Unauthenticated (5001, custom NSE — external scan only at HIGH) |
| HIGH | SNMP default or accepts-any community — read-write, non-network device (non-printer hosts only) |
| HIGH | Kubernetes Dashboard Accessible (8001, confirmed by `http-title`) |
| HIGH | IPMI RAKP Hash Disclosure (CVE-2013-4786) — offline cracking with hashcat mode 7300 |
| HIGH | IKE Aggressive Mode with Pre-Shared Key (U:500, confirmed by `ike-version`) |
| HIGH | RealVNC Authentication Bypass (CVE-2006-2369) (5900/5901, confirmed by `realvnc-auth-bypass`) |
| HIGH | Service Exposed Externally (databases, RDP, SMB, SNMP, WebLogic, VNC, WSUS 8530/8531, etc. — external scan only) |
| MEDIUM | SMBv1 protocol enabled |
| MEDIUM | Weak SSH algorithms (deprecated ciphers/MACs/KEX) |
| MEDIUM | Java RMI registry exposed |
| MEDIUM | Expired TLS certificate (external scan only) |
| MEDIUM | Possible Cisco CUCM TFTP (Unconfirmed) (6970 open, NSE did not confirm) |
| MEDIUM | Ollama LLM API Unauthenticated (11434, custom NSE — internal scan) |
| MEDIUM | OpenAI-Compatible LLM API Unauthenticated (1234/1337/3000/8000, custom NSE — internal scan) |
| MEDIUM | Gradio LLM Web UI Accessible (7860, custom NSE — internal scan) |
| MEDIUM | KoboldCpp LLM API Unauthenticated (5001, custom NSE — internal scan) |
| LOW | Anonymous FTP login (default LOW — review the share; escalate if it exposes sensitive data or is writable) |
| LOW | FTP exposed externally (plaintext protocol — credentials/data in cleartext; use FTPS/SFTP) |
| LOW | Telnet exposed externally (plaintext protocol — credentials/data in cleartext; use SSH) |
| LOW | SNMP default or accepts-any community — read-only (non-printer hosts only) |
| LOW | IPMI Service Detected |
| LOW | IKE/IPsec Service Detected (U:500) |
| LOW | OpenVPN Service Detected (U:1194/1194; identification only — VPN exposure is expected, no "exposed externally" finding is raised) |
| LOW | SQL Server instance discovered |
| LOW | WSUS Service Detected (8530/8531; identification only — review CVE-2025-59287 patch status) |
| LOW | VNC Desktop Name Disclosed (5900/5901, retrieved by `vnc-title` without credentials) |

On Internal scans, if `ms-sql-info` discovers SQL Server named instances on non-standard ports, nmap is automatically re-run against those ports.

On External scans, each externally-exposed sensitive service is additionally vulnerability-tested: curated per-protocol NSE scripts (e.g. `smb-vuln-ms17-010` for SMB, `rdp-vuln-ms12-020` for RDP, `ipmi-cipher-zero` for IPMI) plus nmap's broad `vuln`/`vulners` categories are run against it, and the result is embedded per host in the "Service Exposed Externally" finding (e.g. `Vuln check: smb-vuln-ms17-010: VULNERABLE (CVE-2017-0143)`, or `no known vulnerabilities detected`). This is heavier and noisier than a plain port check — the intentional trade-off for thoroughness.

## Potential Hacks to Look For

| Port(s) | Service | Notes |
|---------|---------|-------|
| 1090 | Java RMI | Auto-detected by `script_scan` |
| 2345 | Delve Go Debugger | Auto-detected by `script_scan`; arbitrary code execution |
| 2375, 4243 | Docker API | Unauthenticated access auto-detected by `script_scan` |
| 2377 | Docker Swarm | Cluster management; auto-detected by `script_scan` |
| 3300 | SAP Gateway | Auto-detected by `script_scan` |
| 4786 | Cisco Smart Install | Auto-detected by `script_scan` |
| 5005 | JDWP Java Debugger | Auto-detected by `script_scan`; arbitrary code execution on the JVM |
| 6000 | X11 Display | Auto-detected by `script_scan`; keystroke/screen capture |
| 6129 | Dameware Remote Control | Custom NSE confirms protocol handshake; CVE-2019-3980 unauthenticated RCE (CVSS 9.8) in versions ≤ 12.1.0.89 |
| 6379 | Redis | Unauthenticated access |
| 6970 | Cisco CUCM TFTP | Custom NSE probes `/ConfigFileCacheList.txt` and `/XMLDefault.cnf.xml` to confirm; phone configs often contain plaintext SIP/SCCP credentials |
| 7001, 7002 | Oracle WebLogic Server | Deserialization RCE |
| 8001 | Kubernetes Dashboard | Auto-detected by `script_scan`; cluster takeover |
| 8009 | AJP Connector (Ghostcat) | Auto-detected by `script_scan`; LFI/RCE if Tomcat <= 9.0.30 (CVE-2020-1938) |
| 8080 | Adobe ColdFusion BlazeDS | Deserialization RCE |
| 9229 | Node.js Inspector | Auto-detected by `script_scan`; arbitrary code execution via CDP |
| 10250 | Kubernetes Kubelet API | Auto-detected by `script_scan`; arbitrary pod exec |
| 61616 | Apache ActiveMQ | Auto-detected by `script_scan`; RCE via CVE-2023-46604 |
| U:500 | IKE/IPsec VPN | Aggressive Mode + PSK auto-detected (HIGH); ike-version identifies vendor/mode |
| U:1194, 1194 | OpenVPN | Custom NSE (`openvpn-detect`) completes the P_CONTROL_HARD_RESET handshake to confirm the protocol over UDP or TCP; identification only (LOW) — no version is disclosed pre-auth, and no "exposed externally" finding is raised since VPN reachability is expected. Servers using `tls-auth`/`tls-crypt` silently drop the probe and read as no match |
| U:623 | IPMI / BMC | Cipher Zero auth bypass auto-detected (CRITICAL); RAKP hash disclosure for offline crack (HIGH, CVE-2013-4786) |
| 5900, 5901 | VNC | No-auth auto-detected (CRITICAL); realvnc-auth-bypass checked (HIGH); desktop name retrieved via vnc-title (LOW) |
| 11434 | Ollama LLM Runtime | Custom NSE (`ollama-detect`) probes `/api/tags` and `/api/version`; unauthenticated access exposes model inventory and full inference API |
| 1234, 1337 | LM Studio / OpenAI-compat API | Custom NSE (`openai-api-detect`) probes `/v1/models`; unauthenticated access exposes models and inference |
| 3000, 8000 | OpenAI-compatible LLM API | Custom NSE (`openai-api-detect`) probes `/v1/models` with three-string fingerprint to avoid false positives on generic web apps |
| 7860 | Gradio / text-generation-webui | Custom NSE (`gradio-detect`) probes `/info` (fallback: `/`); unauthenticated access to LLM web UI |
| 5001 | KoboldCpp | Custom NSE (`koboldcpp-detect`) probes `/api/v1/model`; unauthenticated inference API exposes loaded model |
| 8530, 8531 | Microsoft WSUS | Custom NSE (`wsus-detect`) probes the WSUS web-service endpoints (e.g. `/ClientWebService/client.asmx`) to identify WSUS; detection only — review CVE-2025-59287 (unauth RCE, CVSS 9.8) patch status |

### References

- **Java RMI (1090)** — [Rapid7 module](https://www.rapid7.com/db/modules/exploit/multi/misc/java_rmi_server) · [Pentester's guide](https://medium.com/@afinepl/java-rmi-for-pentesters-structure-recon-and-communication-non-jmx-registries-a10d5c996a79)
- **Delve Go Debugger (2345)** — Arbitrary code execution; connect with `dlv connect <IP>:2345`
- **Docker API (2375/4243)** — [Rapid7 module](https://www.rapid7.com/db/modules/exploit/linux/http/docker_daemon_tcp)
- **Docker Swarm (2377)** — Cluster management; joining the swarm grants node-level access
- **SAP Gateway (3300)** — [SAP GW RCE exploit](https://github.com/chipik/SAP_GW_RCE_exploit)
- **JDWP (5005)** — Arbitrary code execution on the JVM; `jdb -attach <IP>:5005`
- **X11 (6000)** — [xspy](https://github.com/mnp/xspy) keystroke logger · `xterm -display <IP>:0`
- **Dameware (6129)** — [Tenable advisory](https://www.tenable.com/security/research/tra-2019-43) · [PoC](https://github.com/tenable/poc/blob/master/Solarwinds/Dameware/dwrcs_dwDrvInst_rce.py)
- **Redis (6379)** — [Rapid7 module](https://www.rapid7.com/db/modules/exploit/linux/redis/redis_replication_cmd_exec)
- **Cisco CUCM TFTP (6970)** — [SeeYouCM-Thief](https://github.com/trustedsec/SeeYouCM-Thief)
- **Oracle WebLogic (7001/7002)** — [WSAT RCE](https://www.rapid7.com/db/modules/exploit/multi/http/oracle_weblogic_wsat_deserialization_rce) · [AsyncResponseService RCE](https://www.rapid7.com/db/modules/exploit/multi/http/oracle_weblogic_deserialize_asyncresponseservice)
- **Kubernetes Dashboard (8001)** — Unauthenticated cluster takeover via `kubectl proxy`
- **AJP / Ghostcat (8009)** — [CVE-2020-1938 PoC](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi)
- **ColdFusion BlazeDS (8080)** — [Tenable plugin](https://www.tenable.com/plugins/nessus/99731)
- **Node.js Inspector (9229)** — Arbitrary code execution via Chrome DevTools Protocol; `node --inspect` · [PoC](https://github.com/nicowillis/node-inspector-rce)
- **Kubernetes Kubelet (10250)** — [Rapid7 module](https://www.rapid7.com/db/modules/exploit/multi/http/kubelet_exec_endpoint) · arbitrary pod exec
- **ActiveMQ (61616)** — [CVE-2023-46604 PoC](https://github.com/X1r0z/ActiveMQ-RCE) · [Rapid7 module](https://www.rapid7.com/db/modules/exploit/multi/misc/apache_activemq_rce_cve_2023_46604)
- **IKE/IPsec (U:500)** — [ike-version NSE](https://nmap.org/nsedoc/scripts/ike-version.html) · ike-scan --aggressive for hash capture · hashcat mode 5300 (IKEv1) / 5400 (IKEv2)
- **IPMI (U:623)** — [US-CERT TA13-207A](https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi) · [hashcat mode 7300](https://hashcat.net/wiki/doku.php?id=hashcat)
- **VNC (5900/5901)** — [CVE-2006-2369](https://nvd.nist.gov/vuln/detail/CVE-2006-2369) · [vnc-info NSE](https://nmap.org/nsedoc/scripts/vnc-info.html) · [vnc-title NSE](https://nmap.org/nsedoc/scripts/vnc-title.html)

## Development

Run the test suite with [uv](https://docs.astral.sh/uv/):

```bash
uv run pytest tests/
uv run pytest tests/test_spoonmap.py::TestGenerateFindings   # single class
```

Coverage is measured on every run and the suite fails below 95% (see
`[tool.pytest.ini_options]` in `pyproject.toml`).

`tests/test_nse_integration.py` binds real local ports and shells out to real
nmap, so it skips itself where nmap is absent, where a port it needs is already
in use, or (for the `-sU` cases) where the run is not root. A skip there is
always an environment conflict, never an NSE result.

### Continuous integration

`.github/workflows/ci.yml` runs on every pull request and on pushes to `main`,
with nmap installed on the Ubuntu jobs so the NSE integration tests actually
run:

- **`test`** — Python 3.10–3.13 on Ubuntu plus Python 3.12 on macOS, using the
  locked toolchain (`uv run --frozen`), and checking that `uv.lock` is in sync
  with `pyproject.toml`.
- **`test-legacy`** — Python 3.8 and 3.9, resolving pytest fresh outside the
  project (`uv run --isolated --no-project`).

The split exists because `pytest` only ships the fix for CVE-2025-71176 in
9.0.3+, which requires Python 3.10+. `uv.lock` therefore resolves for 3.10+
only (`[tool.uv] environments`), so no vulnerable version is locked, while
`requires-python` stays at `>=3.8` — `spoonmap.py` is dependency-free stdlib and
still runs on older interpreters, which the `test-legacy` jobs keep honest.
