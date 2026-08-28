# SNI/TLS-Certificate Hostname Discovery — Design

## Problem

SpooNMAP already resolves operator-supplied hostnames to IPs at the start of a
scan (`preprocess_targets()`) and threads that mapping through to nmap
invocations and the final report. It has no way to *discover* hostnames
during a scan itself. TLS services frequently reveal hostnames the operator
never typed in — via the certificate's `commonName` and
`subjectAltName` (SAN) entries — and those names are valuable both for the
report and for follow-up work (vhost enumeration, resuming with a wider
target list, etc.).

## Source

SpooNMAP already runs the `ssl-cert` NSE script on common TLS ports (443,
465, 636, 993, 995, 8443, 10443, ...; see `_SCRIPT_PORTS`-style table around
`spoonmap.py:2969`) for **External** scans only — `ssl-cert` is deliberately
excluded from the Internal script set (`spoonmap.py:3007`,
"not relevant for internal assessments"). This feature adds no new scanning;
it only parses `ssl-cert` output SpooNMAP already collects in
`nse_results/*.xml`.

## Extraction

New helper `_extract_ssl_cert_hostnames(ssl_cert_output)`:

- Reads `commonName=` off the `Subject:` line.
- Reads each `DNS:` entry off the `Subject Alternative Name:` line.
- Returns a deduped, order-preserved list — CN first, then SANs in the order
  nmap printed them.
- Names starting with `*.` (wildcards) are returned like any other name (the
  finding should report them) but are tagged so callers can exclude them from
  anything that feeds scanning — a wildcard is not a usable target.
- Missing/malformed input (no `Subject:` line, no matches) returns `[]`
  rather than raising; this mirrors the file's existing per-element-defensive
  XML/regex parsing convention (CLAUDE.md, "XML result parsing is per-element
  defensive").

## Merge into the hostname map

Right after `nmap_scan()` returns in `main()` (`spoonmap.py:6549`), and
*before* `_aggregate_result_dir()` is called (`spoonmap.py:6581`), a new step
`_merge_ssl_cert_hostnames(output_path, ip_to_hostname)`:

1. Walks `nse_results/*.xml` (the files `generate_findings()` already walks),
   extracts `ssl-cert` script output per host/port via the existing
   `_parse_result_xml()` path.
2. For each host, calls `_extract_ssl_cert_hostnames()` and takes the first
   non-wildcard name (CN preferred, else first non-wildcard SAN).
3. Merges that name into the in-memory `ip_to_hostname` dict **only for IPs
   that don't already have an entry** — an operator-supplied hostname (from
   the target file) is never overwritten by a cert-derived guess.
4. Writes the merged dict back to `discovery/ip_hostname_map.json` via
   `_atomic_write()` (the same file `preprocess_targets()` writes), so a
   later `--resume` sees the enriched map too.

Placing this before `_aggregate_result_dir()` means the combined
`spoonmap_output.json`/`.xml` and the gnmap merge pick up the cert-derived
hostname. Placing it before `generate_findings()` (`spoonmap.py:6592`, which
re-reads `ip_hostname_map.json` fresh at `spoonmap.py:3578-3585`) means
findings display it too. This does **not** retroactively change how *this
run's* nmap invocations targeted the host — hostname-based targeting
(`create_hostname_target_file()`) already happened earlier in the same run,
using whatever `ip_to_hostname` looked like at that time. The benefit is to
this run's reporting/output and to any future resume.

This step runs unconditionally after `nmap_scan()` (not gated on
`target_scan == 'External'` at the call site) — the External-only gate is
already enforced upstream by `ssl-cert` only ever being scheduled on External
scans, so an Internal scan's `nse_results/` simply has no `ssl-cert` entries
to find, and the walk is a no-op.

## Findings

New INFO-severity finding in `generate_findings()`, alongside the existing
expired-certificate check (same `'ssl-cert' in scripts and target_scan ==
'External'` gate at `spoonmap.py:3845`):

- **Title:** `TLS Certificate Hostname(s) Identified`
- **Body:** lists every name `_extract_ssl_cert_hostnames()` returned for
  that host/port (including wildcards — they're informative even though
  unused for targeting), e.g. `Certificate presents: example.corp,
  www.example.corp, *.example.corp`.
- One finding per host/port that has a non-empty extraction result; a cert
  with no parseable CN/SAN produces no finding (same "skip, don't fabricate"
  posture as the rest of `generate_findings()`).

## Testing

- `_extract_ssl_cert_hostnames()`: CN only, CN+SAN, SAN only, wildcard-only,
  duplicate names across CN/SAN, malformed/missing `Subject:` line, empty
  string input.
- `_merge_ssl_cert_hostnames()`: fills a gap for an IP with no prior entry;
  never overwrites an existing (operator-supplied) entry; no-op when
  `nse_results/` has no `ssl-cert` output (Internal scans); writes via
  `_atomic_write()` so a partial write can't corrupt `ip_hostname_map.json`.
- `generate_findings()`: new finding appears with the right hostname list on
  an External scan; does not appear on an Internal scan; does not appear when
  `ssl-cert` output has no parseable names.

## Out of scope

- No active hostname/vhost probing (e.g. supplying candidate SNI values and
  diffing responses) — this is passive extraction from certs SpooNMAP
  already retrieves.
- No change to how *this run's* nmap invocations target hosts — see "Merge
  into the hostname map" above.
- No reverse-DNS/PTR-based hostname discovery — out of scope per the
  clarifying question during brainstorming; SNI/cert-derived only.
