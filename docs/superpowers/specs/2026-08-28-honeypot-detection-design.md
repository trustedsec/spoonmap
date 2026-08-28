# Expanded Honeypot / Decoy Detection — Design

## Context

SpooNMAP already flags suspected honeypots/tarpits via two signals combined
into one flat MEDIUM finding (`_flag_suspected_tarpits()` +
`_count_unmatched_service_ports()`, wired together in `generate_findings()`):

1. A host open on ≥90% of scanned TCP ports (min sample 10 ports).
2. ≥3 open ports whose `-sV` probe got a `servicefp` (data came back but
   matched no signature).

This design adds four more signals, tiers severity by confidence instead of
one flat MEDIUM, and adds an operator-gated active confirmation probe. Two
signals considered and cut: uptime/lastboot correlation (requires `-O`, which
no existing nmap invocation passes, and adding it means new packets on every
scan just for this) and conflicting OS/CPE across ports (reverse proxies and
CDNs produce the same pattern — too many false positives to trust).

## Goals

- Warn the operator as early as possible — during masscan discovery, before
  `-sV`/NSE ever touches a suspected decoy — since the whole point is OPSEC,
  not just a report finding.
- Also emit a findings.md entry, tiered by confidence, for the deliverable.
- Never send extra packets without explicit, per-run operator acceptance.
- Reuse the existing tarpit-file/disclosure pattern rather than inventing a
  new mechanism.

## New Signals

All four are pure functions next to `_flag_suspected_tarpits()`, taking
already-parsed data structures and returning `{ip: reason}` or similar — no
I/O, independently testable.

### 1. TTL spread across a host's open ports (masscan-stage, free)

One host has one TCP/IP stack; nmap/masscan's `reason_ttl` should be
identical across every open port on a real host. More than one distinct
`reason_ttl` value across a host's ports means several emulated listeners
sit behind one address (honeyd, T-Pot's per-service Docker containers).

Confirmed available from masscan's own XML output format strings
(`reason_ttl="%u"` on every `<state>`) — no new packets, no nmap dependency.
Also present in nmap output, but only because the tool hardcodes `-sS`
(raw-packet SYN scan) on every invocation that could feed this; verified
locally that `-sT` (connect scan) reports `reason_ttl="0"` — the signal is
present *because of* an existing tool choice, not something to newly add.

**False-positive source:** NAT/load-balancing can present multiple backend
TTLs behind one IP. TTL spread alone must never reach HIGH — it's a
contributing signal, not standalone proof. Worth surfacing regardless, since
it reveals topology either way.

`_ttl_spread_by_host(port_ips)` — mirrors `_flag_suspected_tarpits()`'s input
shape (the `{port_key: {ip: ...}}`/reason_ttl-bearing structure already
threaded through `mass_scan()`). Returns `{ip: sorted list of distinct
reason_ttl values}` for hosts with more than one.

### 2. Named-product signature match (post-`-sV`)

A `HONEYPOT_SIGNATURES` table of `(pattern, product_name)` matched against
banners/service output already captured by `-sV`:

- Cowrie/Kippo's default, unconfigured SSH banner
  (`SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` is Kippo's well-known factory
  default before an operator changes it).
- Dionaea's FTP greeting and SMB native-OS string.
- Conpot's SNMP sysDescr for the default ICS templates
  (`Siemens, SIMATIC, S7-200`).

**These exact strings must be verified against current upstream honeypot
source/config before shipping** — they drift between versions and I'm
working from familiarity, not a fresh check of each project's current
defaults. Flagged as an explicit implementation task, not asserted as
correct here.

`_honeypot_signature_match(banner_text)` — returns product name or `None`.

### 3. Known honeypot port-profile match (post-masscan or post-`-sV`)

A `HONEYPOT_PORT_PROFILES` table of characteristic fixed port sets for
commercial/OSS deception products (Thinkst Canary, Artillery). Set
comparison against the ports found open on a host — no new signal
collection, just matching against data already gathered.

`_port_profile_match(open_ports)` — returns product name or `None`.

### 4. Silent-open ports (post-`-sV`, complements existing signal #2)

The existing `_count_unmatched_service_ports()` only counts ports where
nmap connected, read data back, and failed to match a signature
(`servicefp` set). That structurally misses tarpits that hold the
connection open and send nothing (classic LaBrea behavior) — those score
zero today.

`_count_silent_open_ports(output_path)` — same nmap_results/*.xml walk,
counts open ports with **no** `service` element product/version *and* no
`servicefp` (i.e., truly no data), separate from the existing unmatched-fp
count so the two can be reported and weighted independently.

## Two-Stage Flow

### Stage 1 — masscan discovery (OPSEC-first)

Right where `_report_suspected_tarpits()` already runs in `mass_scan()`:
add the TTL-spread check and (since masscan output already has port lists)
the port-profile check. Both are free at this point — before nmap `-sV` or
any NSE script touches the host.

Writes `discovery/suspected_honeypots.txt` (new file, mirrors
`suspected_tarpits.txt`'s format/append pattern) and warns on stdout,
identically in spirit to the existing tarpit warning.

### Stage 2 — after `-sV`, in `generate_findings()`

Adds the signature match and silent-open-ports checks, merges in whatever
Stage 1 already wrote for that host, and emits the tiered finding.

## Active Confirmation Probe

After the Stage 1 warning, the operator can request a definitive check: a
short burst of connection attempts against a handful of *closed* (per
masscan) high ports on the suspect host. If anything answers, the entire
host is fake — a real machine doesn't listen on ports masscan just reported
closed. Port choice is seeded from the target IP (not `random`/`time`) so
the probe set is reproducible and the code path is unit-testable without
mocking randomness.

**Consent, given config mode skips all prompts:**

- Interactive runs: a per-host prompt after the Stage 1 warning, default no.
- Config-file mode: gated on a new `honeypot_active_confirm` key, defaulting
  to **false**; an absent key means false. Same posture as
  `check_for_updates` — a courtesy/optional network-touching behavior that
  must never fire unless explicitly opted into, and for the same underlying
  reason (SpooNMAP runs from jumpboxes inside client networks; an
  unannounced probe against a possible client-deployed canary is exactly
  the kind of action that needs to be opt-in, not opt-out).
- `_maybe_confirm_honeypot()` follows the same testability shape as
  `_maybe_check_for_updates()`: a thin gate function, not inlined in
  `main()`, so "does config mode ever probe without the key set" is a
  directly testable question.
- The probe itself swallows connection errors the same way scan workers
  already do; a probe failure must never abort the run.

## Severity Tiering

Replaces the current single `add('MEDIUM', ...)` call:

- **HIGH** — a named-product signature match, OR a confirmed active probe
  (something answered on a masscan-closed port).
- **MEDIUM** — two or more heuristic signals present (e.g. TTL spread +
  90%-open-ports, or port-profile match + silent-open-ports).
- **LOW** — exactly one heuristic signal.

TTL spread alone is always capped at LOW/contributing — never HIGH by
itself, per the NAT false-positive risk above.

**Behavior change, called out explicitly:** a host that today trips only
the existing 90%-open-ports ratio will drop from MEDIUM to LOW once this
ships, since that's now "exactly one heuristic signal" under the new
tiering. Existing tests asserting MEDIUM for that case need updating as
part of this work — this is intentional, not a regression.

## Config

New key in `config.json` / `config.json.sample`:

```
"honeypot_active_confirm": false
```

Added to `_CONFIG_FIELD_ORDER` and `_build_interactive_config()` explicitly
(not left to the merge-with-existing-file fallback), matching the existing
`check_for_updates` precedent and its documented reasoning: the fallback
only carries a key forward if a config.json already has it set, and
silently drops it on first-ever regeneration otherwise.

## Testing

- Each new pure signal function: unit tests with synthetic XML/dicts,
  including the TTL-spread NAT false-positive case (confirm it never
  reaches HIGH alone).
- `_maybe_confirm_honeypot()`: mirrors `_maybe_check_for_updates()`'s test
  shape — assert the probe function is never called when
  `honeypot_active_confirm` is absent/false, and never called in config
  mode without the interactive prompt path being involved.
- Severity tiering: table-driven test over signal combinations → expected
  severity.
- Regression: update existing MEDIUM-severity honeypot test(s) for the new
  LOW-for-single-signal behavior.
- `tests/test_nse_integration.py`-style real-nmap test is not needed here —
  no new NSE script is added; the active probe is a plain socket connect,
  not nmap.

## Out of Scope (cut, not deferred)

- Uptime/lastboot correlation — needs `-O` on every nmap invocation, a
  scan-wide traffic increase to gain one signal.
- Conflicting OS/CPE across ports — reverse proxies and CDNs look
  identical to this; not trustworthy enough to include.
- Identical-banners-across-many-hosts — VM templates and load balancers
  produce the same pattern; cut for the same reason.
