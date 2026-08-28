# Expanded Honeypot / Decoy Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four new honeypot/decoy detection signals to SpooNMAP (TTL spread across a host's ports, known port-profile matching, named-product signature matching, and silent-open-port counting), tier the existing flat-MEDIUM finding into HIGH/MEDIUM/LOW by confidence, and add an operator-gated active confirmation probe.

**Architecture:** Every new signal is a pure function that re-parses XML SpooNMAP already writes to disk (`masscan_results/*.xml`, `nmap_results/*.xml`) or reuses the in-memory `port_ips` dict `mass_scan()` already builds — no new packets are sent for any heuristic signal. The one exception, the active confirmation probe, is a plain socket connect gated behind a new `honeypot_active_confirm` config key (default `false`, absent means `false`), mirroring the existing `check_for_updates` opt-in pattern exactly. Stage 1 (TTL spread + port profile) runs during `mass_scan()`, before nmap ever touches a suspect host; Stage 2 (signature match, silent-open-count, severity tiering) runs in `generate_findings()` as today.

**Tech Stack:** Python 3.8+ stdlib only (`xml.etree.ElementTree`, `socket`, `random`). No new dependencies.

## Global Constraints

- No new third-party dependencies — `spoonmap.py` stays dependency-free stdlib (per CLAUDE.md).
- All subprocess/socket calls must not introduce shell injection surface — N/A here (no new subprocess calls), but the active probe uses `socket.create_connection`, never a shell string.
- Every new file-write goes through `_atomic_write()`, matching every other durable write in this codebase.
- Every new XML walk must be per-element defensive (`.attrib.get(...)`, never bare `[...]` indexing or `findall(...)[0]`) — a malformed element must never abort the whole file's parse, per this codebase's established pattern.
- `honeypot_active_confirm` defaults to `false`; an absent key means `false`. No interactive prompt of its own — mirrors `check_for_updates`'s documented precedent exactly (a courtesy/opt-in network-touching behavior must never fire unless explicitly turned on, because SpooNMAP runs from client-network jumpboxes).
- **Deviation from the approved spec, discovered during planning:** the spec called for a live interactive per-host prompt after the Stage 1 warning. Verified against `main()`: every `input()` call in this codebase happens before any scan starts — `mass_scan()` and its callees never prompt mid-run (no precedent, and adding one would require threading terminal-state save/restore into the masscan progress-thread path for no other feature). The active probe is therefore **config-key-gated only**, exactly like `check_for_updates`, with no interactive prompt. This means an interactive run without a pre-existing `config.json` never gets a chance to opt in mid－scan — the operator would need to hand-edit `config.json` and re-run with `--resume` (`check_for_updates` has this same limitation today). Flagging this for user sign-off; it is the only substantive change from the approved spec.
- TTL spread alone must never reach HIGH severity (NAT/load-balancing produces the same pattern) — enforced structurally by `_honeypot_severity()`, not by a special case (see Task 6).
- The honeypot signature strings (`HONEYPOT_SIGNATURES`) and port profiles (`HONEYPOT_PORT_PROFILES`) are **placeholders pending verification** against current upstream defaults — each is written with an explicit code comment saying so, per the design doc's caveat. Do not present them as verified. The one exception is `_vnc_heralding_match()` (Task 3 Step 7): checked directly against `johnnykv/heralding`'s current `master` source and is not a placeholder.

---

## File Structure

All changes are in two files:

- **`spoonmap.py`** — all new functions, constants, and call-site wiring. No new files: this repo keeps its scan logic in one module by established convention (11k+ lines already), and every sibling feature (tarpit detection, update-check gating) lives here too.
- **`tests/test_spoonmap.py`** — all new tests, added to existing or new `Test*` classes near the code they cover, matching this file's existing organization.
- **`config.json.sample`** — one new key + doc line.
- **`CLAUDE.md`** — one new paragraph under "Honeypot/tarpit detection" documenting the expanded behavior, per this repo's convention of keeping CLAUDE.md as the durable record of *why*.

No new NSE scripts, no new nmap invocations, no new masscan invocations.

---

## Task 1: Shared XML walk + silent-open-port signal

Refactors `_count_unmatched_service_ports()`'s XML-walking logic into a shared generator so the new silent-open-ports check reuses the same per-element defensiveness (skip malformed XML, skip a host with no IPv4 address, skip UDP result files) instead of duplicating it. This is a pure refactor of existing, tested code plus one new function — verified against the *existing* test suite for `_count_unmatched_service_ports()` to confirm zero behavior change.

**Files:**
- Modify: `spoonmap.py:3481-3517` (`_count_unmatched_service_ports`)
- Test: `tests/test_spoonmap.py` (existing `TestCountUnmatchedServicePorts` class, ~line 1798; new `TestCountSilentOpenPorts` class)

**Interfaces:**
- Produces: `_iter_open_tcp_ports(output_path)` — generator yielding `(ip: str, service_elem: Element | None)` for every open TCP port found in `{output_path}/nmap_results/*.xml`. `service_elem` is `None` when nmap recorded no `<service>` element at all for that port.
- Produces: `_count_silent_open_ports(output_path) -> dict[str, int]` — `{ip: count}` of open TCP ports where nmap captured *no* service data whatsoever (no name, no product, no servicefp).
- Consumes: nothing new — same `xml.etree.ElementTree as etree` already imported at `spoonmap.py:30`.

- [ ] **Step 1: Write the failing test for the new silent-open-ports function**

Add to `tests/test_spoonmap.py`, right after the existing `TestCountUnmatchedServicePorts` class (after its last test, before `class TestGenerateFindingsHoneypot:`):

```python
class TestCountSilentOpenPorts:
    """Unit tests for _count_silent_open_ports()."""

    def _xml(self, ip, port, protocol='tcp', state='open', service_attrs=None):
        service_elem = ''
        if service_attrs is not None:
            attrs = ' '.join(f'{k}="{v}"' for k, v in service_attrs.items())
            service_elem = f'<service {attrs}/>'
        return (
            '<?xml version="1.0"?><nmaprun>'
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="{protocol}" portid="{port}">'
            f'<state state="{state}"/>{service_elem}'
            '</port></ports></host></nmaprun>'
        )

    def test_missing_dir_returns_empty(self, tmp_path):
        assert _count_silent_open_ports(str(tmp_path)) == {}

    def test_no_service_element_at_all_is_silent(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port9999.xml').write_text(self._xml('10.0.0.1', '9999', service_attrs=None))
        assert _count_silent_open_ports(str(tmp_path)) == {'10.0.0.1': 1}

    def test_service_with_no_name_product_or_fp_is_silent(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.2', '9999', service_attrs={})
        (nmap_results / 'port9999.xml').write_text(xml)
        assert _count_silent_open_ports(str(tmp_path)) == {'10.0.0.2': 1}

    def test_matched_service_not_silent(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.3', '22', service_attrs={'name': 'ssh', 'product': 'OpenSSH'})
        (nmap_results / 'port22.xml').write_text(xml)
        assert _count_silent_open_ports(str(tmp_path)) == {}

    def test_unmatched_fingerprint_not_silent(self, tmp_path):
        # servicefp means *something* came back -- this is
        # _count_unmatched_service_ports()'s signal, not this one's.
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.4', '9999', service_attrs={
            'name': 'unknown', 'servicefp': 'SF-Port9999-TCP:...',
        })
        (nmap_results / 'port9999.xml').write_text(xml)
        assert _count_silent_open_ports(str(tmp_path)) == {}

    def test_closed_port_not_counted(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.5', '9999', state='closed', service_attrs=None)
        (nmap_results / 'port9999.xml').write_text(xml)
        assert _count_silent_open_ports(str(tmp_path)) == {}

    def test_udp_files_skipped(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.6', '53', protocol='udp', service_attrs=None)
        (nmap_results / 'portU_53.xml').write_text(xml)
        assert _count_silent_open_ports(str(tmp_path)) == {}

    def test_malformed_xml_skipped(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port80.xml').write_text('<nmaprun><host>')
        assert _count_silent_open_ports(str(tmp_path)) == {}

    def test_multiple_silent_ports_same_host_aggregate(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        for port in ('2222', '3333', '4444'):
            (nmap_results / f'port{port}.xml').write_text(
                self._xml('10.0.0.7', port, service_attrs=None))
        assert _count_silent_open_ports(str(tmp_path)) == {'10.0.0.7': 3}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestCountSilentOpenPorts -v`
Expected: FAIL with `ImportError` or `NameError: name '_count_silent_open_ports' is not defined`

- [ ] **Step 3: Add the import**

In `tests/test_spoonmap.py`, in the `from spoonmap import (...)` block (starts ~line 21), add `_count_silent_open_ports,` alphabetically near the existing `_count_unmatched_service_ports,` (~line 42):

```python
    _count_silent_open_ports,
    _count_unmatched_service_ports,
```

- [ ] **Step 4: Refactor `_count_unmatched_service_ports()` and add `_count_silent_open_ports()`**

Replace `spoonmap.py:3481-3517` (the full `_count_unmatched_service_ports` function) with:

```python
def _iter_open_tcp_ports(output_path):
    """Yield (ip, service_elem) for every open TCP port in nmap_results/*.xml.

    service_elem is None when nmap recorded no <service> element at all.
    Shared by _count_unmatched_service_ports() and _count_silent_open_ports()
    so the XML-walk defensiveness (skip a host with no addr, skip malformed
    XML, skip UDP files) lives in one place instead of being duplicated.
    """
    nmap_dir = f'{output_path}/nmap_results'
    if not os.path.exists(nmap_dir):
        return
    for fname in sorted(os.listdir(nmap_dir)):
        if not fname.endswith('.xml') or fname.startswith('portU_'):
            continue
        try:
            root = etree.parse(f'{nmap_dir}/{fname}')
        except etree.ParseError:
            continue
        for host in root.findall('host'):
            # Skip a <host> whose IPv4 <address> has no addr= attribute.  The
            # KeyError escaped the `except etree.ParseError` above (it wraps only
            # the parse), aborting the honeypot heuristic for every remaining
            # result file rather than for the one unusable element.
            addr_elem = host.find("address[@addrtype='ipv4']")
            ip = addr_elem.attrib.get('addr') if addr_elem is not None else None
            if not ip:
                continue
            for port_elem in host.iter('port'):
                state_elem = port_elem.find('state')
                if state_elem is not None and state_elem.attrib.get('state') != 'open':
                    continue
                yield ip, port_elem.find('service')


def _count_unmatched_service_ports(output_path):
    """Return {ip: count} of open TCP ports whose nmap -sV probe captured data
    that matched none of nmap's service signatures.

    nmap only sets the service element's servicefp attribute when it connected,
    read data back, and failed to identify it against any known protocol —
    a strong tell for decoy tools (e.g. Artillery) that hand back a random
    string on every full connect instead of speaking a real protocol.
    """
    counts = {}
    for ip, service_elem in _iter_open_tcp_ports(output_path):
        if service_elem is not None and service_elem.attrib.get('servicefp'):
            counts[ip] = counts.get(ip, 0) + 1
    return counts


def _count_silent_open_ports(output_path):
    """Return {ip: count} of open TCP ports where nmap's -sV probe got
    nothing at all back — no service name, no product, no servicefp.

    Complements _count_unmatched_service_ports(), which only counts ports
    where nmap connected and read *some* data that failed to match a
    signature (servicefp set). A tarpit that holds the connection open and
    sends nothing back scores zero on that check but is exactly what this
    one is for.
    """
    counts = {}
    for ip, service_elem in _iter_open_tcp_ports(output_path):
        if service_elem is None:
            counts[ip] = counts.get(ip, 0) + 1
            continue
        attrib = service_elem.attrib
        if not attrib.get('name') and not attrib.get('product') and not attrib.get('servicefp'):
            counts[ip] = counts.get(ip, 0) + 1
    return counts
```

- [ ] **Step 5: Run both the new and existing tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py::TestCountSilentOpenPorts tests/test_spoonmap.py::TestCountUnmatchedServicePorts -v`
Expected: PASS, all tests in both classes (the refactor must not change `_count_unmatched_service_ports()`'s behavior)

- [ ] **Step 6: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "refactor: extract shared XML walk; add silent-open-ports honeypot signal"
```

---

## Task 2: TTL spread + port-profile signals (Stage 1, masscan-time)

Adds the two free, masscan-stage signals: TTL inconsistency across a host's open ports (re-parses `masscan_results/*.xml`, which is already fully written to disk at every call site by the time this runs) and known port-profile matching (reuses the in-memory `port_ips` dict `mass_scan()` already has, at zero extra I/O). Wires both into all three existing `_report_suspected_tarpits(_flag_suspected_tarpits(...))` call sites, writing a new `discovery/suspected_honeypots.txt` file that mirrors `suspected_tarpits.txt`'s append/warn shape.

**Files:**
- Modify: `spoonmap.py:2955-2957` (new constants, inserted after existing `HONEYPOT_*` constants)
- Modify: `spoonmap.py:1918-1919` (new functions, inserted after `_report_suspected_tarpits`)
- Modify: `spoonmap.py:1998, 2050, 2324` (the three `_report_suspected_tarpits(_flag_suspected_tarpits(...))` call sites)
- Test: `tests/test_spoonmap.py` (new `TestTtlSpreadByHost`, `TestPortProfileMatch`, `TestFlagHoneypotSignals`, `TestReportSuspectedHoneypots` classes, added after `TestReportSuspectedTarpits` ~line 8997)

**Interfaces:**
- Consumes: `_ip_sort_key` (existing, used by `_report_suspected_tarpits`), `_atomic_write` (existing), `_COLOR_ERROR`/`_COLOR_RESET` (existing).
- Produces: `_ttl_spread_by_host(masscan_dir) -> dict[str, list[int]]` — `{ip: sorted distinct reason_ttl values}` for hosts with more than one distinct TTL.
- Produces: `HONEYPOT_PORT_PROFILES: dict[str, frozenset[str]]` — product name → its characteristic TCP port set.
- Produces: `_port_profile_match(open_ports) -> str | None` — matching product name or `None`.
- Produces: `_flag_honeypot_signals(port_ips, masscan_dir) -> dict[str, dict[str, list[int] | str]]` — `{ip: {'ttl_spread': [...]}, {'port_profile': name}}`, either or both keys present.
- Produces: `_report_suspected_honeypots(flagged, disc) -> None` — writes `disc/suspected_honeypots.txt`, warns on stdout.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_spoonmap.py`, right after `class TestReportSuspectedTarpits:`'s last test (`test_write_leaves_no_temp_file_behind`, ~line 8996):

```python
class TestTtlSpreadByHost:
    """Unit tests for _ttl_spread_by_host()."""

    def _masscan_xml(self, ip, port, reason_ttl, protocol='tcp'):
        return (
            '<?xml version="1.0"?><nmaprun>'
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="{protocol}" portid="{port}">'
            f'<state state="open" reason="syn-ack" reason_ttl="{reason_ttl}"/>'
            '</port></ports></host></nmaprun>'
        )

    def test_missing_dir_returns_empty(self, tmp_path):
        assert _ttl_spread_by_host(str(tmp_path / 'nope')) == {}

    def test_consistent_ttl_not_flagged(self, tmp_path):
        (tmp_path / 'port22.xml').write_text(self._masscan_xml('10.0.0.1', '22', 64))
        (tmp_path / 'port80.xml').write_text(self._masscan_xml('10.0.0.1', '80', 64))
        assert _ttl_spread_by_host(str(tmp_path)) == {}

    def test_inconsistent_ttl_flagged_sorted(self, tmp_path):
        (tmp_path / 'port22.xml').write_text(self._masscan_xml('10.0.0.2', '22', 128))
        (tmp_path / 'port80.xml').write_text(self._masscan_xml('10.0.0.2', '80', 64))
        assert _ttl_spread_by_host(str(tmp_path)) == {'10.0.0.2': [64, 128]}

    def test_single_port_never_flagged(self, tmp_path):
        (tmp_path / 'port22.xml').write_text(self._masscan_xml('10.0.0.3', '22', 64))
        assert _ttl_spread_by_host(str(tmp_path)) == {}

    def test_udp_ports_ignored(self, tmp_path):
        (tmp_path / 'port22.xml').write_text(self._masscan_xml('10.0.0.4', '22', 64))
        (tmp_path / 'portU_53.xml').write_text(
            self._masscan_xml('10.0.0.4', '53', 200, protocol='udp'))
        assert _ttl_spread_by_host(str(tmp_path)) == {}

    def test_malformed_xml_skipped(self, tmp_path):
        (tmp_path / 'port80.xml').write_text('<nmaprun><host>')
        assert _ttl_spread_by_host(str(tmp_path)) == {}

    def test_host_without_ipv4_address_skipped(self, tmp_path):
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="00:11:22:33:44:55" addrtype="mac"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack" reason_ttl="64"/>'
            '</port></ports></host></nmaprun>'
        )
        (tmp_path / 'port22.xml').write_text(xml)
        assert _ttl_spread_by_host(str(tmp_path)) == {}

    def test_non_numeric_ttl_skipped(self, tmp_path):
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.5" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack" reason_ttl="not-a-number"/>'
            '</port></ports></host></nmaprun>'
        )
        (tmp_path / 'port22.xml').write_text(xml)
        assert _ttl_spread_by_host(str(tmp_path)) == {}


class TestPortProfileMatch:
    """Unit tests for _port_profile_match()."""

    def test_exact_profile_match(self):
        profile = next(iter(HONEYPOT_PORT_PROFILES.values()))
        assert _port_profile_match(profile) is not None

    def test_superset_still_matches(self):
        profile = next(iter(HONEYPOT_PORT_PROFILES.values()))
        assert _port_profile_match(profile | {'54321'}) is not None

    def test_subset_does_not_match(self):
        profile = next(iter(HONEYPOT_PORT_PROFILES.values()))
        partial = set(list(profile)[:-1]) if len(profile) > 1 else set()
        assert _port_profile_match(partial) is None

    def test_unrelated_ports_no_match(self):
        assert _port_profile_match({'12345'}) is None

    def test_empty_ports_no_match(self):
        assert _port_profile_match(set()) is None


class TestFlagHoneypotSignals:
    """Unit tests for _flag_honeypot_signals()."""

    def _masscan_xml(self, ip, port, reason_ttl):
        return (
            '<?xml version="1.0"?><nmaprun>'
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{port}">'
            f'<state state="open" reason="syn-ack" reason_ttl="{reason_ttl}"/>'
            '</port></ports></host></nmaprun>'
        )

    def test_ttl_spread_flagged(self, tmp_path):
        (tmp_path / 'port22.xml').write_text(self._masscan_xml('10.0.0.1', '22', 64))
        (tmp_path / 'port80.xml').write_text(self._masscan_xml('10.0.0.1', '80', 128))
        port_ips = {'22': {'10.0.0.1'}, '80': {'10.0.0.1'}}
        result = _flag_honeypot_signals(port_ips, str(tmp_path))
        assert result['10.0.0.1']['ttl_spread'] == [64, 128]

    def test_port_profile_flagged(self, tmp_path):
        profile = next(iter(HONEYPOT_PORT_PROFILES.items()))
        name, ports = profile
        port_ips = {p: {'10.0.0.2'} for p in ports}
        result = _flag_honeypot_signals(port_ips, str(tmp_path))
        assert result['10.0.0.2']['port_profile'] == name

    def test_udp_ports_excluded_from_profile_match(self, tmp_path):
        port_ips = {'U:22': {'10.0.0.3'}, 'U:80': {'10.0.0.3'}}
        result = _flag_honeypot_signals(port_ips, str(tmp_path))
        assert '10.0.0.3' not in result

    def test_no_signals_no_entry(self, tmp_path):
        port_ips = {'22': {'10.0.0.4'}}
        result = _flag_honeypot_signals(port_ips, str(tmp_path))
        assert result == {}

    def test_both_signals_combine_for_same_host(self, tmp_path):
        name, ports = next(iter(HONEYPOT_PORT_PROFILES.items()))
        ports = list(ports)
        (tmp_path / f'port{ports[0]}.xml').write_text(
            self._masscan_xml('10.0.0.5', ports[0], 64))
        (tmp_path / f'port{ports[1]}.xml').write_text(
            self._masscan_xml('10.0.0.5', ports[1], 128))
        port_ips = {p: {'10.0.0.5'} for p in ports}
        result = _flag_honeypot_signals(port_ips, str(tmp_path))
        assert result['10.0.0.5']['ttl_spread'] == [64, 128]
        assert result['10.0.0.5']['port_profile'] == name


class TestReportSuspectedHoneypots:
    """Unit tests for _report_suspected_honeypots()."""

    def test_writes_ttl_spread_line_and_warns(self, tmp_path, capsys):
        flagged = {'10.0.0.1': {'ttl_spread': [64, 128]}}
        _report_suspected_honeypots(flagged, str(tmp_path))
        content = (tmp_path / 'suspected_honeypots.txt').read_text()
        assert '10.0.0.1,ttl_spread,64|128' in content
        out = capsys.readouterr().out
        assert '10.0.0.1' in out

    def test_writes_port_profile_line(self, tmp_path):
        flagged = {'10.0.0.2': {'port_profile': 'Thinkst Canary'}}
        _report_suspected_honeypots(flagged, str(tmp_path))
        content = (tmp_path / 'suspected_honeypots.txt').read_text()
        assert '10.0.0.2,port_profile,Thinkst Canary' in content

    def test_both_signals_write_two_lines(self, tmp_path):
        flagged = {'10.0.0.3': {'ttl_spread': [64, 128], 'port_profile': 'Artillery'}}
        _report_suspected_honeypots(flagged, str(tmp_path))
        content = (tmp_path / 'suspected_honeypots.txt').read_text()
        assert content.count('10.0.0.3,') == 2

    def test_empty_flagged_writes_nothing(self, tmp_path):
        _report_suspected_honeypots({}, str(tmp_path))
        assert not (tmp_path / 'suspected_honeypots.txt').exists()
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestTtlSpreadByHost tests/test_spoonmap.py::TestPortProfileMatch tests/test_spoonmap.py::TestFlagHoneypotSignals tests/test_spoonmap.py::TestReportSuspectedHoneypots -v`
Expected: FAIL with `NameError`/`ImportError` (functions/constants don't exist yet)

- [ ] **Step 3: Add the imports**

In `tests/test_spoonmap.py`'s `from spoonmap import (...)` block, add these entries alphabetically:

```python
    _flag_honeypot_signals,
    _port_profile_match,
    _report_suspected_honeypots,
    _ttl_spread_by_host,
    HONEYPOT_PORT_PROFILES,
```

- [ ] **Step 4: Add the new constants**

Insert into `spoonmap.py` right after the existing `HONEYPOT_MIN_UNMATCHED_PORTS = 3` line (`spoonmap.py:2957`):

```python

# Port sets characteristic of known deception/decoy tooling default
# deployments. Superset match, not exact: an operator-customised deployment
# (an extra port, or unrelated services sharing the box) should still match
# on its known baseline.
#
# NOTE: these are placeholders pending verification against current upstream
# defaults before shipping -- both projects' default port lists can change
# between releases and installs are commonly customised. Verify against each
# project's current documentation/config before relying on this in a report.
HONEYPOT_PORT_PROFILES = {
    'Thinkst Canary': frozenset(['21', '22', '23', '80', '443', '445', '3389']),
    'Artillery':       frozenset(['21', '22', '23', '25', '80', '443', '3306', '3389', '8080']),
}
```

- [ ] **Step 5: Add `_ttl_spread_by_host()`, `_port_profile_match()`, `_flag_honeypot_signals()`, `_report_suspected_honeypots()`**

Insert into `spoonmap.py` right after `_report_suspected_tarpits()` ends (after the `_atomic_write(tarpit_file, ''.join(lines))` line, `spoonmap.py:1918`, before `def mass_scan(...)` at line 1921):

```python
def _ttl_spread_by_host(masscan_dir):
    """Return {ip: sorted distinct reason_ttl values} for hosts whose open
    TCP ports report more than one distinct TTL in masscan's own XML output.

    One host has one TCP/IP stack; every open port on a real host reports the
    same TTL. More than one value across a host's ports is characteristic of
    several emulated listeners behind one address (honeyd, T-Pot's per-service
    containers) rather than a single machine. NAT/load-balancing can also
    produce this pattern, so this signal alone is deliberately never enough to
    reach HIGH severity -- see _honeypot_severity().
    """
    ttls_by_ip = {}
    if not os.path.exists(masscan_dir):
        return {}
    for fname in sorted(os.listdir(masscan_dir)):
        if not fname.endswith('.xml'):
            continue
        try:
            root = etree.parse(os.path.join(masscan_dir, fname))
        except etree.ParseError:
            continue
        for host in root.findall('host'):
            addr_elem = host.find("address[@addrtype='ipv4']")
            ip = addr_elem.attrib.get('addr') if addr_elem is not None else None
            if not ip:
                continue
            ports_elem = host.find('ports')
            if ports_elem is None:
                continue
            port_elem = ports_elem.find('port')
            if port_elem is None or port_elem.attrib.get('protocol') == 'udp':
                continue
            state_elem = port_elem.find('state')
            if state_elem is None:
                continue
            ttl_text = state_elem.attrib.get('reason_ttl')
            if ttl_text is None:
                continue
            try:
                ttl = int(ttl_text)
            except ValueError:
                continue
            ttls_by_ip.setdefault(ip, set()).add(ttl)
    return {ip: sorted(ttls) for ip, ttls in ttls_by_ip.items() if len(ttls) > 1}


def _port_profile_match(open_ports):
    """Return the matching product name when open_ports is a superset of a
    known honeypot deployment's default port profile, else None."""
    port_set = set(open_ports)
    for name, profile in HONEYPOT_PORT_PROFILES.items():
        if profile <= port_set:
            return name
    return None


def _flag_honeypot_signals(port_ips, masscan_dir):
    """Return {ip: {'ttl_spread': [...], 'port_profile': name}} for hosts
    matching either the TTL-inconsistency or known-port-profile heuristic.

    TTL spread is read back from masscan_dir's XML files (reason_ttl is not
    threaded through port_ips's in-memory {port_key: {ips}} shape); port
    profile matching reuses port_ips directly since it already has the
    per-host open-port set this needs, at zero extra I/O.
    """
    flagged = {}

    for ip, ttls in _ttl_spread_by_host(masscan_dir).items():
        flagged.setdefault(ip, {})['ttl_spread'] = ttls

    hosts_ports = {}
    for port_key, ips in port_ips.items():
        if port_key.startswith('U:'):
            continue
        for ip in ips:
            hosts_ports.setdefault(ip, set()).add(port_key)
    for ip, ports in hosts_ports.items():
        match = _port_profile_match(ports)
        if match:
            flagged.setdefault(ip, {})['port_profile'] = match

    return flagged


def _report_suspected_honeypots(flagged, disc):
    """Persist TTL-spread/port-profile flagged hosts to
    disc/suspected_honeypots.txt and warn on stdout.

    One line per (ip, signal) pair -- a host can carry both signals -- so the
    format mirrors _report_suspected_tarpits() but is not a straight port:
    'ip,ttl_spread,64|128' or 'ip,port_profile,Thinkst Canary'.
    """
    if not flagged:
        return
    honeypot_file = os.path.join(disc, 'suspected_honeypots.txt')
    lines = []
    for ip in sorted(flagged, key=_ip_sort_key):
        signals = flagged[ip]
        if 'ttl_spread' in signals:
            ttl_str = '|'.join(str(t) for t in signals['ttl_spread'])
            lines.append(f'{ip},ttl_spread,{ttl_str}\n')
            print(_COLOR_ERROR
                  + f'Warning: {ip} returned inconsistent TTLs ({ttl_str}) across '
                  + 'scanned ports — possible multiple emulated services behind one '
                  + 'address.'
                  + _COLOR_RESET)
        if 'port_profile' in signals:
            product = signals['port_profile']
            lines.append(f'{ip},port_profile,{product}\n')
            print(_COLOR_ERROR
                  + f'Warning: {ip}\'s open ports match the known deployment profile '
                  + f'of {product} — possible decoy host.'
                  + _COLOR_RESET)
    _atomic_write(honeypot_file, ''.join(lines))


```

- [ ] **Step 6: Wire into the three `mass_scan()` call sites**

In `spoonmap.py`, replace each of these three occurrences of:

```python
        _report_suspected_tarpits(_flag_suspected_tarpits(full_results, 65535), disc)
```

(there are two identical instances of this exact line, at what were originally `spoonmap.py:1998` and `spoonmap.py:2050` — use `replace_all` or apply to both individually since the surrounding context differs) with:

```python
        _report_suspected_tarpits(_flag_suspected_tarpits(full_results, 65535), disc)
        _report_suspected_honeypots(_flag_honeypot_signals(full_results, f'{disc}/masscan_results'), disc)
```

And replace the third occurrence (originally `spoonmap.py:2324`):

```python
    _report_suspected_tarpits(_flag_suspected_tarpits(port_ips, len(tcp_ports)), disc)
```

with:

```python
    _report_suspected_tarpits(_flag_suspected_tarpits(port_ips, len(tcp_ports)), disc)
    _report_suspected_honeypots(_flag_honeypot_signals(port_ips, f'{disc}/masscan_results'), disc)
```

- [ ] **Step 7: Run the new tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py::TestTtlSpreadByHost tests/test_spoonmap.py::TestPortProfileMatch tests/test_spoonmap.py::TestFlagHoneypotSignals tests/test_spoonmap.py::TestReportSuspectedHoneypots -v`
Expected: PASS

- [ ] **Step 8: Run the full test suite to check for regressions**

Run: `uv run pytest tests/test_spoonmap.py -x -q`
Expected: PASS (existing `mass_scan()`-adjacent tests must be unaffected — the new calls are additive and `_report_suspected_honeypots` no-ops on empty input)

- [ ] **Step 9: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: add TTL-spread and port-profile honeypot signals (Stage 1, masscan-time)"
```

---

## Task 3: Named-product signature matching (Stage 2, post-`-sV`)

Adds signature matching against known default/unconfigured honeypot banners, using the `-sV` service data nmap already captured in `nmap_results/*.xml` — reuses `_iter_open_tcp_ports()` from Task 1, no new I/O.

**Files:**
- Modify: `spoonmap.py` (new constant + two new functions, placed after `_count_silent_open_ports()` from Task 1)
- Test: `tests/test_spoonmap.py` (new `TestHoneypotSignatureMatch`, `TestNamedHoneypotMatches` classes)

**Interfaces:**
- Consumes: `_iter_open_tcp_ports(output_path)` (Task 1).
- Produces: `HONEYPOT_SIGNATURES: tuple[tuple[str, str], ...]` — `(substring_to_match, product_name)` pairs.
- Produces: `_honeypot_signature_match(text) -> str | None`.
- Produces: `_named_honeypot_matches(output_path) -> dict[str, str]` — `{ip: product_name}`, first match wins per host.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_spoonmap.py`, right after the `TestCountSilentOpenPorts` class from Task 1:

```python
class TestHoneypotSignatureMatch:
    """Unit tests for _honeypot_signature_match()."""

    def test_known_signature_matches(self):
        needle, product = HONEYPOT_SIGNATURES[0]
        assert _honeypot_signature_match(f'prefix {needle} suffix') == product

    def test_unrelated_text_no_match(self):
        assert _honeypot_signature_match('OpenSSH 9.6p1 Ubuntu') is None

    def test_empty_text_no_match(self):
        assert _honeypot_signature_match('') is None


class TestNamedHoneypotMatches:
    """Unit tests for _named_honeypot_matches()."""

    def _xml(self, ip, port, product=None, version=None, extrainfo=None):
        attrs = []
        if product is not None:
            attrs.append(f'product="{product}"')
        if version is not None:
            attrs.append(f'version="{version}"')
        if extrainfo is not None:
            attrs.append(f'extrainfo="{extrainfo}"')
        service_elem = f'<service {" ".join(attrs)}/>' if attrs else ''
        return (
            '<?xml version="1.0"?><nmaprun>'
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{port}">'
            f'<state state="open"/>{service_elem}'
            '</port></ports></host></nmaprun>'
        )

    def test_missing_dir_returns_empty(self, tmp_path):
        assert _named_honeypot_matches(str(tmp_path)) == {}

    def test_signature_match_across_product_version_extrainfo(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        needle, product = HONEYPOT_SIGNATURES[0]
        parts = needle.split(' ', 1)
        prod_val = parts[0]
        rest = parts[1] if len(parts) > 1 else ''
        xml = self._xml('10.0.0.1', '22', product=prod_val, version=rest)
        (nmap_results / 'port22.xml').write_text(xml)
        assert _named_honeypot_matches(str(tmp_path)) == {'10.0.0.1': product}

    def test_no_service_element_no_match(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port22.xml').write_text(self._xml('10.0.0.2', '22'))
        assert _named_honeypot_matches(str(tmp_path)) == {}

    def test_unrelated_service_no_match(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.3', '22', product='OpenSSH', version='9.6p1')
        (nmap_results / 'port22.xml').write_text(xml)
        assert _named_honeypot_matches(str(tmp_path)) == {}

    def test_first_match_wins_per_host(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        needle, product = HONEYPOT_SIGNATURES[0]
        parts = needle.split(' ', 1)
        xml = self._xml('10.0.0.4', '22', product=parts[0],
                         version=parts[1] if len(parts) > 1 else '')
        (nmap_results / 'port22.xml').write_text(xml)
        xml2 = self._xml('10.0.0.4', '80', product='OpenSSH', version='9.6p1')
        (nmap_results / 'port80.xml').write_text(xml2)
        assert _named_honeypot_matches(str(tmp_path)) == {'10.0.0.4': product}
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestHoneypotSignatureMatch tests/test_spoonmap.py::TestNamedHoneypotMatches -v`
Expected: FAIL with `NameError`/`ImportError`

- [ ] **Step 3: Add the imports**

In `tests/test_spoonmap.py`'s import block, add alphabetically:

```python
    _honeypot_signature_match,
    _named_honeypot_matches,
    HONEYPOT_SIGNATURES,
```

- [ ] **Step 4: Add the constant and both functions**

Insert into `spoonmap.py` right after `_count_silent_open_ports()` (added in Task 1):

```python

# Well-known *default, unconfigured* banners of common honeypot/decoy
# products, matched against the concatenated product/version/extrainfo text
# nmap's -sV already captures.
#
# NOTE: these are placeholders pending verification against current upstream
# defaults before shipping -- both signature strings and default configs can
# drift between releases. Verify against each project's current source/docs
# before relying on this in a report.
HONEYPOT_SIGNATURES = (
    ('OpenSSH 6.0p1 Debian-4+deb7u2', 'Cowrie/Kippo SSH Honeypot'),
    ('Welcome to the ftp service', 'Dionaea FTP Honeypot'),
)


def _honeypot_signature_match(text):
    """Return the matching product name when text contains a known
    default/unconfigured honeypot banner, else None."""
    for needle, product in HONEYPOT_SIGNATURES:
        if needle in text:
            return product
    return None


def _named_honeypot_matches(output_path):
    """Return {ip: product_name} for hosts whose -sV service banner matches
    a known default honeypot signature. First match wins per host."""
    matches = {}
    for ip, service_elem in _iter_open_tcp_ports(output_path):
        if ip in matches or service_elem is None:
            continue
        attrib = service_elem.attrib
        text = ' '.join(filter(None, (
            attrib.get('product'), attrib.get('version'), attrib.get('extrainfo'))))
        if not text:
            continue
        product = _honeypot_signature_match(text)
        if product:
            matches[ip] = product
    return matches
```

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py::TestHoneypotSignatureMatch tests/test_spoonmap.py::TestNamedHoneypotMatches -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: add named honeypot signature matching (Stage 2, post-nmap)"
```

- [ ] **Step 7: Add the Heralding VNC honeypot signature**

Verified against upstream source (`johnnykv/heralding`, `heralding/capabilities/vnc.py`,
current `master`), not a placeholder: Heralding's VNC capability hardcodes
`RFB_VERSION = b'RFB 003.007\n'` — it unconditionally sends protocol version 3.7 to
every client, then requires the client's version reply to match those exact bytes or
it closes the session immediately, without ever sending a security-type list. Real RFB
servers negotiate/downgrade instead of hard-matching one exact version string. nmap's
`vnc-info` therefore reports protocol 3.7 with no `Security types` line at all against
a Heralding instance — a distinct shape from a real (if legacy) RFB 3.7 server, which
always completes the security-type exchange. `vnclowpot` was also checked and has no
equivalent standalone signature (it completes a normal 3.8 handshake offering only VNC
Authentication, indistinguishable from a legitimately hardened real VNC server), so it
is deliberately not included here.

This doesn't fit `_honeypot_signature_match()`'s shape: that function matches a single
substring in `-sV`'s product/version/extrainfo text (`nmap_results/*.xml`). The
Heralding tell is a compound condition (version present AND security-types absent) on
`vnc-info`'s own script output, which lives in `nse_results/*.xml`, not
`nmap_results/*.xml` — a separate walk is needed.

**Files:**
- Modify: `spoonmap.py` (new function, placed after `_named_honeypot_matches()`)
- Test: `tests/test_spoonmap.py` (new `TestVncHeraldingMatch` class)

**Interfaces:**
- Produces: `_vnc_heralding_match(output_path) -> dict[str, str]` — `{ip: 'Heralding VNC Honeypot'}`, walking `nse_results/*.xml` directly (its own XML walk, not `_iter_open_tcp_ports()`, since that generator only yields `<service>` elements, not `<script>` elements).
- Consumes: nothing new — same `xml.etree.ElementTree as etree` already imported at `spoonmap.py:30`.

Add to `tests/test_spoonmap.py`, right after `TestNamedHoneypotMatches`:

```python
class TestVncHeraldingMatch:
    """Unit tests for _vnc_heralding_match()."""

    def _xml(self, ip, port, vnc_info_output):
        return (
            '<?xml version="1.0"?><nmaprun>'
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{port}">'
            '<state state="open"/>'
            f'<script id="vnc-info" output="{vnc_info_output}"/>'
            '</port></ports></host></nmaprun>'
        )

    def test_missing_dir_returns_empty(self, tmp_path):
        assert _vnc_heralding_match(str(tmp_path)) == {}

    def test_heralding_shape_matches(self, tmp_path):
        nse_results = tmp_path / 'nse_results'
        nse_results.mkdir()
        xml = self._xml('10.0.0.1', '5900', 'Protocol version: 3.7')
        (nse_results / 'port5900.xml').write_text(xml)
        assert _vnc_heralding_match(str(tmp_path)) == {'10.0.0.1': 'Heralding VNC Honeypot'}

    def test_real_37_server_with_security_types_no_match(self, tmp_path):
        nse_results = tmp_path / 'nse_results'
        nse_results.mkdir()
        xml = self._xml('10.0.0.2', '5900',
                         'Protocol version: 3.7&#10;Security types: &#10;  VNC Authentication (2)')
        (nse_results / 'port5900.xml').write_text(xml)
        assert _vnc_heralding_match(str(tmp_path)) == {}

    def test_38_server_no_match(self, tmp_path):
        nse_results = tmp_path / 'nse_results'
        nse_results.mkdir()
        xml = self._xml('10.0.0.3', '5900', 'Protocol version: 3.8')
        (nse_results / 'port5900.xml').write_text(xml)
        assert _vnc_heralding_match(str(tmp_path)) == {}

    def test_no_vnc_info_script_no_match(self, tmp_path):
        nse_results = tmp_path / 'nse_results'
        nse_results.mkdir()
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.4" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="5900">'
            '<state state="open"/>'
            '</port></ports></host></nmaprun>'
        )
        (nse_results / 'port5900.xml').write_text(xml)
        assert _vnc_heralding_match(str(tmp_path)) == {}
```

Run: `uv run pytest tests/test_spoonmap.py::TestVncHeraldingMatch -v`
Expected: FAIL with `NameError`/`ImportError`

Add `_vnc_heralding_match,` to the test file's import block, alphabetically.

Implement in `spoonmap.py`, right after `_named_honeypot_matches()`:

```python

def _vnc_heralding_match(output_path):
    """Return {ip: 'Heralding VNC Honeypot'} for hosts whose vnc-info output
    matches Heralding's VNC capability: it hardcodes RFB protocol version 3.7
    and closes the connection before ever sending a security-type list,
    unlike any real RFB implementation (which always completes that
    exchange, even on legacy 3.7 servers). Verified against upstream source
    (johnnykv/heralding, heralding/capabilities/vnc.py)."""
    matches = {}
    nse_dir = f'{output_path}/nse_results'
    if not os.path.exists(nse_dir):
        return matches
    for fname in sorted(os.listdir(nse_dir)):
        if not fname.endswith('.xml') or fname.startswith('portU_'):
            continue
        try:
            root = etree.parse(f'{nse_dir}/{fname}')
        except etree.ParseError:
            continue
        for host in root.findall('host'):
            addr_elem = host.find("address[@addrtype='ipv4']")
            ip = addr_elem.attrib.get('addr') if addr_elem is not None else None
            if not ip or ip in matches:
                continue
            for port_elem in host.findall('.//port'):
                script_elem = port_elem.find("script[@id='vnc-info']")
                if script_elem is None:
                    continue
                out = script_elem.attrib.get('output', '')
                if '3.7' in out and 'Security types' not in out:
                    matches[ip] = 'Heralding VNC Honeypot'
                break
    return matches
```

Run: `uv run pytest tests/test_spoonmap.py::TestVncHeraldingMatch -v`
Expected: PASS

Commit:

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: add Heralding VNC honeypot signature (vnc-info protocol 3.7 tell)"
```

---

## Task 4: Active confirmation probe (operator-gated)

Adds a plain-socket connect probe against high, never-scanned ports on a flagged host, gated entirely behind `honeypot_active_confirm` (parameter here; config wiring happens in Task 5). Mirrors `_maybe_check_for_updates()`'s thin-gate-function shape so "does a default run ever probe" is directly testable.

**Files:**
- Modify: `spoonmap.py` (add `import random`; new functions after Task 2's additions; new `honeypot_active_confirm` parameter on `mass_scan()`; wire into the same three call sites)
- Test: `tests/test_spoonmap.py` (new `TestSelectConfirmProbePorts`, `TestActiveConfirmProbe`, `TestMaybeConfirmHoneypot`, `TestReportConfirmedHoneypots` classes)

**Interfaces:**
- Consumes: `socket` (already imported at `spoonmap.py:19`), `_ip_sort_key`, `_atomic_write`, `_COLOR_ERROR`/`_COLOR_RESET`.
- Produces: `_select_confirm_probe_ports(ip, scanned_ports, count=3) -> list[str]`.
- Produces: `_active_confirm_probe(ip, probe_ports, timeout=2, connector=None) -> bool`.
- Produces: `_maybe_confirm_honeypot(enabled, ip, probe_ports, connector=None) -> bool`.
- Produces: `_report_confirmed_honeypots(confirmed_ips, disc) -> None` — writes `disc/confirmed_honeypots.txt`.
- Produces: `_confirm_flagged_honeypots(flagged, enabled, dest_ports, disc) -> None` — orchestrates the above three across every host `_flag_honeypot_signals()` flagged.
- `mass_scan()` gains a new keyword parameter `honeypot_active_confirm=False`, appended after the existing `target_scan='Internal'` parameter.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_spoonmap.py`, right after the `TestReportSuspectedHoneypots` class from Task 2:

```python
class TestSelectConfirmProbePorts:
    """Unit tests for _select_confirm_probe_ports()."""

    def test_returns_requested_count(self):
        ports = _select_confirm_probe_ports('10.0.0.1', [], count=3)
        assert len(ports) == 3

    def test_ports_are_in_ephemeral_range(self):
        ports = _select_confirm_probe_ports('10.0.0.1', [], count=5)
        assert all(49152 <= int(p) <= 65535 for p in ports)

    def test_excludes_scanned_ports(self):
        scanned = [str(p) for p in range(49152, 49152 + 100)]
        ports = _select_confirm_probe_ports('10.0.0.1', scanned, count=3)
        assert not (set(ports) & set(scanned))

    def test_deterministic_for_same_ip(self):
        a = _select_confirm_probe_ports('10.0.0.1', [], count=3)
        b = _select_confirm_probe_ports('10.0.0.1', [], count=3)
        assert a == b

    def test_different_ips_can_differ(self):
        a = _select_confirm_probe_ports('10.0.0.1', [], count=3)
        b = _select_confirm_probe_ports('10.0.0.2', [], count=3)
        assert a != b

    def test_udp_scanned_ports_do_not_shrink_candidate_pool(self):
        # 'U:49200'-style keys must not be compared against bare int ports.
        scanned = [f'U:{p}' for p in range(49152, 49200)]
        ports = _select_confirm_probe_ports('10.0.0.1', scanned, count=3)
        assert len(ports) == 3


class TestActiveConfirmProbe:
    """Unit tests for _active_confirm_probe()."""

    def test_returns_true_when_any_port_connects(self):
        def connector(addr, timeout):
            if addr[1] == 50000:
                raise OSError('refused')
            return contextlib.nullcontext()
        assert _active_confirm_probe('10.0.0.1', ['50000', '50001'], connector=connector) is True

    def test_returns_false_when_nothing_connects(self):
        def connector(addr, timeout):
            raise OSError('refused')
        assert _active_confirm_probe('10.0.0.1', ['50000', '50001'], connector=connector) is False

    def test_empty_probe_ports_returns_false(self):
        def connector(addr, timeout):
            raise AssertionError('must not be called with no ports')
        assert _active_confirm_probe('10.0.0.1', [], connector=connector) is False


class TestMaybeConfirmHoneypot:
    """Unit tests for _maybe_confirm_honeypot()."""

    def test_disabled_never_probes(self):
        def connector(addr, timeout):
            raise AssertionError('must not be called when disabled')
        result = _maybe_confirm_honeypot(False, '10.0.0.1', ['50000'], connector=connector)
        assert result is False

    def test_enabled_runs_probe(self):
        def connector(addr, timeout):
            return contextlib.nullcontext()
        result = _maybe_confirm_honeypot(True, '10.0.0.1', ['50000'], connector=connector)
        assert result is True


class TestReportConfirmedHoneypots:
    """Unit tests for _report_confirmed_honeypots()."""

    def test_writes_file_and_warns(self, tmp_path, capsys):
        _report_confirmed_honeypots({'10.0.0.1'}, str(tmp_path))
        content = (tmp_path / 'confirmed_honeypots.txt').read_text()
        assert content.strip() == '10.0.0.1'
        assert '10.0.0.1' in capsys.readouterr().out

    def test_empty_confirmed_writes_nothing(self, tmp_path):
        _report_confirmed_honeypots(set(), str(tmp_path))
        assert not (tmp_path / 'confirmed_honeypots.txt').exists()

    def test_multiple_hosts_sorted(self, tmp_path):
        _report_confirmed_honeypots({'10.0.0.10', '10.0.0.2'}, str(tmp_path))
        content = (tmp_path / 'confirmed_honeypots.txt').read_text()
        assert content.splitlines() == ['10.0.0.2', '10.0.0.10']
```

Note: `contextlib` is already imported in `tests/test_spoonmap.py` (check with `grep -n '^import contextlib' tests/test_spoonmap.py`; if absent, add `import contextlib` near the top with the other stdlib imports).

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestSelectConfirmProbePorts tests/test_spoonmap.py::TestActiveConfirmProbe tests/test_spoonmap.py::TestMaybeConfirmHoneypot tests/test_spoonmap.py::TestReportConfirmedHoneypots -v`
Expected: FAIL with `NameError`/`ImportError`

- [ ] **Step 3: Add the imports**

In `tests/test_spoonmap.py`'s import block, add alphabetically:

```python
    _active_confirm_probe,
    _maybe_confirm_honeypot,
    _report_confirmed_honeypots,
    _select_confirm_probe_ports,
```

Confirm `import contextlib` exists near the top of the file; add it if missing.

- [ ] **Step 4: Add `import random` to `spoonmap.py`**

In `spoonmap.py`, insert `import random` right after `from queue import Queue` (`spoonmap.py:27`), before `import urllib.error`:

```python
from queue import Queue
import random
import urllib.error
```

- [ ] **Step 5: Add the four new functions**

Insert into `spoonmap.py` right after `_report_suspected_honeypots()` (added in Task 2), before `def mass_scan(...)`:

```python
def _select_confirm_probe_ports(ip, scanned_ports, count=3):
    """Return `count` deterministic high ports, seeded from ip, that were
    never part of this run's scanned port set.

    Deterministic (seeded from the target IP, not global randomness) so the
    probe is reproducible and testable without mocking random state. Ports
    are drawn from the ephemeral range (49152-65535) specifically because a
    legitimate host is unlikely to run a fixed service there, so an answer
    is a strong tell rather than a false positive from a real service the
    scan happened not to cover.
    """
    scanned = {p for p in scanned_ports if not p.startswith('U:')}
    rng = random.Random(ip)
    candidates = [p for p in range(49152, 65536) if str(p) not in scanned]
    return [str(p) for p in rng.sample(candidates, min(count, len(candidates)))]


def _active_confirm_probe(ip, probe_ports, timeout=2, connector=None):
    """Return True if a raw TCP connect succeeds on any of probe_ports.

    A real host has no reason to answer on an unscanned, unrelated ephemeral
    port; a decoy that accepts every connection will. connector defaults to
    socket.create_connection and is injectable for testing.
    """
    connect = connector or socket.create_connection
    for port in probe_ports:
        try:
            with connect((ip, int(port)), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _maybe_confirm_honeypot(enabled, ip, probe_ports, connector=None):
    """Run the active confirmation probe only if the operator opted in.

    Mirrors _maybe_check_for_updates(): a thin, directly-testable gate so
    "does a default run ever send an unrequested probe" is a real test, not
    something buried inside mass_scan().
    """
    if not enabled:
        return False
    return _active_confirm_probe(ip, probe_ports, connector=connector)


def _report_confirmed_honeypots(confirmed_ips, disc):
    """Persist actively-confirmed decoy hosts to disc/confirmed_honeypots.txt
    and warn on stdout."""
    if not confirmed_ips:
        return
    confirmed_file = os.path.join(disc, 'confirmed_honeypots.txt')
    lines = []
    for ip in sorted(confirmed_ips, key=_ip_sort_key):
        lines.append(f'{ip}\n')
        print(_COLOR_ERROR
              + f'Warning: {ip} answered a connection on a port never scanned open '
              + 'during this run — confirmed decoy/honeypot host.'
              + _COLOR_RESET)
    _atomic_write(confirmed_file, ''.join(lines))


def _confirm_flagged_honeypots(flagged, enabled, dest_ports, disc):
    """Run the active probe (if enabled) against every host
    _flag_honeypot_signals() flagged, and persist whichever ones answer."""
    if not flagged:
        return
    confirmed = set()
    for ip in flagged:
        probe_ports = _select_confirm_probe_ports(ip, dest_ports)
        if _maybe_confirm_honeypot(enabled, ip, probe_ports):
            confirmed.add(ip)
    _report_confirmed_honeypots(confirmed, disc)


```

- [ ] **Step 6: Add the `honeypot_active_confirm` parameter to `mass_scan()` and wire the three call sites**

In `spoonmap.py`, change the `mass_scan()` signature (was `spoonmap.py:1921`, now shifted down by Task 1-3's insertions — locate by the unique signature text):

```python
def mass_scan(scan_type, dest_ports, source_port, max_rate, target_file, exclusions_file, batch_size=1, resume=False, discovery_file=None, target_scan='Internal'):
```

to:

```python
def mass_scan(scan_type, dest_ports, source_port, max_rate, target_file, exclusions_file, batch_size=1, resume=False, discovery_file=None, target_scan='Internal', honeypot_active_confirm=False):
```

Then, at each of the three call sites touched in Task 2 Step 6, add a `_confirm_flagged_honeypots(...)` call right after the `_report_suspected_honeypots(...)` line. The two identical Full-scan-path occurrences:

```python
        _report_suspected_tarpits(_flag_suspected_tarpits(full_results, 65535), disc)
        _report_suspected_honeypots(_flag_honeypot_signals(full_results, f'{disc}/masscan_results'), disc)
```

become:

```python
        _report_suspected_tarpits(_flag_suspected_tarpits(full_results, 65535), disc)
        honeypot_flags = _flag_honeypot_signals(full_results, f'{disc}/masscan_results')
        _report_suspected_honeypots(honeypot_flags, disc)
        _confirm_flagged_honeypots(honeypot_flags, honeypot_active_confirm, dest_ports, disc)
```

And the batch-loop occurrence:

```python
    _report_suspected_tarpits(_flag_suspected_tarpits(port_ips, len(tcp_ports)), disc)
    _report_suspected_honeypots(_flag_honeypot_signals(port_ips, f'{disc}/masscan_results'), disc)
```

becomes:

```python
    _report_suspected_tarpits(_flag_suspected_tarpits(port_ips, len(tcp_ports)), disc)
    honeypot_flags = _flag_honeypot_signals(port_ips, f'{disc}/masscan_results')
    _report_suspected_honeypots(honeypot_flags, disc)
    _confirm_flagged_honeypots(honeypot_flags, honeypot_active_confirm, dest_ports, disc)
```

- [ ] **Step 7: Run the new tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py::TestSelectConfirmProbePorts tests/test_spoonmap.py::TestActiveConfirmProbe tests/test_spoonmap.py::TestMaybeConfirmHoneypot tests/test_spoonmap.py::TestReportConfirmedHoneypots -v`
Expected: PASS

- [ ] **Step 8: Run the full test suite to check for regressions**

Run: `uv run pytest tests/test_spoonmap.py -x -q`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: add operator-gated active honeypot confirmation probe"
```

---

## Task 5: Config wiring (`honeypot_active_confirm`)

Wires the new config key through `_CONFIG_FIELD_ORDER`, `_CONFIG_DOCS`, `_build_interactive_config()`, `_load_config()`, `main()`'s variable threading into `mass_scan()`, and `config.json.sample` — mirroring `check_for_updates`'s existing wiring at every one of these sites exactly.

**Files:**
- Modify: `spoonmap.py:5461-5488` (`_CONFIG_DOCS['check_for_updates']` entry — add sibling entry)
- Modify: `spoonmap.py:5492-5496` (`_CONFIG_FIELD_ORDER`)
- Modify: `spoonmap.py:5500-5559` (`_build_interactive_config`)
- Modify: `spoonmap.py:5792-5893` (`_load_config`)
- Modify: `spoonmap.py:6114, 6151, 6456-6461, 6539-6545` (`main()`)
- Modify: `config.json.sample`
- Test: `tests/test_spoonmap.py` (extend existing config-related test classes)

**Interfaces:**
- Consumes: `_config_bool(key, value, default)` (existing).
- Produces: `_load_config(...)['honeypot_active_confirm']` — new key in the returned dict.
- Produces: `_build_interactive_config(..., honeypot_active_confirm=False)` — new keyword parameter.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_spoonmap.py`, right after `class TestUpdateCheckIsOptIn:`'s last test (`test_load_config_defaults_the_key_to_false`, ~line 12799):

```python

class TestHoneypotActiveConfirmIsOptIn:
    """The active honeypot confirmation probe is off unless explicitly enabled.

    Mirrors TestUpdateCheckIsOptIn: an unrequested probe against a suspected
    client-deployed decoy is exactly the kind of action that must be opt-in.
    """

    def test_load_config_defaults_the_key_to_false(self):
        cfg = _config_dict()
        assert 'honeypot_active_confirm' not in cfg
        assert _load_config(cfg, '/t')['honeypot_active_confirm'] is False

    def test_load_config_respects_explicit_true(self):
        cfg = _config_dict(honeypot_active_confirm=True)
        assert _load_config(cfg, '/t')['honeypot_active_confirm'] is True

    def test_build_interactive_config_defaults_to_false(self):
        config = _build_interactive_config(
            'All', [], 'All', True, True, 'Internal', '2000', '/t/targets.txt',
            '/t/out', None, 5, 5, 5_000_000, True,
        )
        assert config['honeypot_active_confirm'] is False

    def test_build_interactive_config_written_explicitly(self):
        config = _build_interactive_config(
            'All', [], 'All', True, True, 'Internal', '2000', '/t/targets.txt',
            '/t/out', None, 5, 5, 5_000_000, True,
            honeypot_active_confirm=True,
        )
        assert config['honeypot_active_confirm'] is True

    def test_field_order_includes_the_key(self):
        assert 'honeypot_active_confirm' in _CONFIG_FIELD_ORDER
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestHoneypotActiveConfirmIsOptIn -v`
Expected: FAIL — `_load_config` returns no such key, `_build_interactive_config` doesn't accept the parameter

- [ ] **Step 3: Add the `_CONFIG_DOCS` entry**

In `spoonmap.py`, right after the existing `'check_for_updates': [...]` block ends (`spoonmap.py:5461-5466`, before `'target_scan': [...]`), add:

```python
    'honeypot_active_confirm': [
        ('__honeypot_active_confirm_note__',
         'Optional. When true, SpooNMAP attempts a small number of raw TCP connects '
         'against unscanned high ports on any host flagged as a suspected honeypot, '
         'to confirm it. Default false, and absent means false: the tool sends no '
         'traffic beyond the scan itself unless you turn this on. A confirmed host '
         'answered a port that was never part of this scan, which is a strong tell '
         'that it accepts every connection rather than running a real service.'),
    ],
```

- [ ] **Step 4: Add the key to `_CONFIG_FIELD_ORDER`**

Change (`spoonmap.py:5492-5496`):

```python
_CONFIG_FIELD_ORDER = (
    'scan_categories', 'dest_ports', 'masscan_batch_size', 'banner_scan',
    'script_scan', 'host_discovery', 'resume', 'check_for_updates', 'target_scan', 'max_rate',
    'nmap_threads', 'nmap_threshold', 'target_file', 'output_path',
    'exclusions_file',
)
```

to:

```python
_CONFIG_FIELD_ORDER = (
    'scan_categories', 'dest_ports', 'masscan_batch_size', 'banner_scan',
    'script_scan', 'host_discovery', 'resume', 'check_for_updates',
    'honeypot_active_confirm', 'target_scan', 'max_rate',
    'nmap_threads', 'nmap_threshold', 'target_file', 'output_path',
    'exclusions_file',
)
```

- [ ] **Step 5: Add the parameter to `_build_interactive_config()`**

Change the function signature (`spoonmap.py:5500-5504`):

```python
def _build_interactive_config(scan_categories, dest_ports, scan_type, banner_scan,
                              script_scan, target_scan, max_rate, target_file,
                              output_path, exclusions_file, nmap_threads,
                              masscan_batch_size, nmap_threshold, host_discovery,
                              check_for_updates=False):
```

to:

```python
def _build_interactive_config(scan_categories, dest_ports, scan_type, banner_scan,
                              script_scan, target_scan, max_rate, target_file,
                              output_path, exclusions_file, nmap_threads,
                              masscan_batch_size, nmap_threshold, host_discovery,
                              check_for_updates=False, honeypot_active_confirm=False):
```

And add `'honeypot_active_confirm': bool(honeypot_active_confirm),` to the `values` dict, right after `'check_for_updates': bool(check_for_updates),` (`spoonmap.py:5541`).

- [ ] **Step 6: Add the read in `_load_config()`**

In `spoonmap.py`, right after the existing block (`spoonmap.py:5863-5865`):

```python
    # Absent means off, and absent is the normal case. This is the only way to
    # enable a launch-time network call; see _check_for_updates().
    check_for_updates = _config_bool(
        'check_for_updates', config_parser.get('check_for_updates', False), False)
```

add:

```python
    # Same posture as check_for_updates: absent means off, and this is the
    # only way to enable the active probe. See _maybe_confirm_honeypot().
    honeypot_active_confirm = _config_bool(
        'honeypot_active_confirm', config_parser.get('honeypot_active_confirm', False), False)
```

And add `'honeypot_active_confirm': honeypot_active_confirm,` to the function's returned dict, right after `'check_for_updates': check_for_updates,` (`spoonmap.py:5893`).

- [ ] **Step 7: Thread the value through `main()`**

In `spoonmap.py`, at line 6114, right after:

```python
        check_for_updates = False  # no interactive prompt; only set via config.json
```

add:

```python
        honeypot_active_confirm = False  # no interactive prompt; only set via config.json
```

At line 6151, right after:

```python
            check_for_updates  = cfg['check_for_updates']
```

add:

```python
            honeypot_active_confirm = cfg['honeypot_active_confirm']
```

At the `_build_interactive_config(...)` call (`spoonmap.py:6456-6461`), change:

```python
            interactive_config = _build_interactive_config(
                scan_categories, dest_ports, scan_type, banner_scan, script_scan,
                target_scan, max_rate, target_file, output_path, exclusions_file,
                nmap_threads, masscan_batch_size, nmap_threshold, host_discovery,
                check_for_updates,
            )
```

to:

```python
            interactive_config = _build_interactive_config(
                scan_categories, dest_ports, scan_type, banner_scan, script_scan,
                target_scan, max_rate, target_file, output_path, exclusions_file,
                nmap_threads, masscan_batch_size, nmap_threshold, host_discovery,
                check_for_updates, honeypot_active_confirm,
            )
```

At the `mass_scan(...)` call (`spoonmap.py:6539-6545`), change:

```python
            status_summary = mass_scan(
                scan_type, dest_ports, source_port, max_rate,
                masscan_target_file,                   # full range; mass_scan() narrows to discovery_file
                exclusions_file, masscan_batch_size,
                resume=resume, discovery_file=discovery_file,
                target_scan=target_scan,
            )
```

to:

```python
            status_summary = mass_scan(
                scan_type, dest_ports, source_port, max_rate,
                masscan_target_file,                   # full range; mass_scan() narrows to discovery_file
                exclusions_file, masscan_batch_size,
                resume=resume, discovery_file=discovery_file,
                target_scan=target_scan,
                honeypot_active_confirm=honeypot_active_confirm,
            )
```

- [ ] **Step 8: Update `config.json.sample`**

Add a new entry right after the existing `"check_for_updates": false,` line:

```json
    "__honeypot_active_confirm_note__": "Optional. When true, SpooNMAP attempts a small number of raw TCP connects against unscanned high ports on any host flagged as a suspected honeypot, to confirm it. Default false, and absent means false: the tool sends no traffic beyond the scan itself unless you turn this on. A confirmed host answered a port that was never part of this scan, which is a strong tell that it accepts every connection rather than running a real service.",
    "honeypot_active_confirm": false,
```

- [ ] **Step 9: Run the new tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py::TestHoneypotActiveConfirmIsOptIn -v`
Expected: PASS

- [ ] **Step 10: Run the full test suite to check for regressions**

Run: `uv run pytest tests/test_spoonmap.py -x -q`
Expected: PASS — existing `_build_interactive_config`/`_load_config` callers must still work since the new parameter/key both default to `False`/absent-safe

- [ ] **Step 11: Commit**

```bash
git add spoonmap.py config.json.sample tests/test_spoonmap.py
git commit -m "feat: wire honeypot_active_confirm through config.json and main()"
```

---

## Task 6: Severity tiering + `generate_findings()` integration

Replaces the existing flat-MEDIUM honeypot finding block with tiered severity combining every signal: the two original (ratio, unmatched-fp), the two new heuristics from Task 2 (read back from `suspected_honeypots.txt`), the new silent-open-ports count from Task 1, the named-signature match from Task 3, and the confirmed-probe result from Task 4. This is the task that changes existing test expectations — done deliberately, per the spec's documented behavior change.

**Files:**
- Modify: `spoonmap.py` (new `_honeypot_severity()` function; replace `spoonmap.py:3597-3637`, the existing tarpit/unmatched finding block in `generate_findings()`)
- Modify: `tests/test_spoonmap.py:1918-1926` (`test_tarpit_file_flags_host` — severity assertion changes from MEDIUM to LOW) and `tests/test_spoonmap.py:1949-1961` (`test_both_signals_combine_in_one_finding` — still MEDIUM, two signals)
- Test: `tests/test_spoonmap.py` (new `TestHoneypotSeverity` class; new tests in `TestGenerateFindingsHoneypot` for the four new signal sources)

**Interfaces:**
- Consumes: `_count_unmatched_service_ports`, `_count_silent_open_ports` (Task 1), `_named_honeypot_matches`, `_vnc_heralding_match` (Task 3), `_ip_sort_key` (existing), `HONEYPOT_MIN_UNMATCHED_PORTS` (existing).
- Produces: `_honeypot_severity(signals, named_match=False, confirmed=False) -> str | None` — `'HIGH'`/`'MEDIUM'`/`'LOW'`/`None`.

- [ ] **Step 1: Write the failing severity-tiering tests**

Add to `tests/test_spoonmap.py`, right before `class TestGenerateFindingsHoneypot:` (~line 1905):

```python
class TestHoneypotSeverity:
    """Unit tests for _honeypot_severity()."""

    def test_no_signals_no_match_no_confirm_returns_none(self):
        assert _honeypot_severity(set()) is None

    def test_single_heuristic_signal_is_low(self):
        assert _honeypot_severity({'ratio'}) == 'LOW'

    def test_two_heuristic_signals_is_medium(self):
        assert _honeypot_severity({'ratio', 'unmatched_fp'}) == 'MEDIUM'

    def test_ttl_spread_alone_is_low_never_high(self):
        assert _honeypot_severity({'ttl_spread'}) == 'LOW'

    def test_ttl_spread_plus_one_other_is_medium_not_high(self):
        assert _honeypot_severity({'ttl_spread', 'port_profile'}) == 'MEDIUM'

    def test_named_match_alone_is_high(self):
        assert _honeypot_severity(set(), named_match=True) == 'HIGH'

    def test_confirmed_alone_is_high(self):
        assert _honeypot_severity(set(), confirmed=True) == 'HIGH'

    def test_named_match_overrides_signal_count(self):
        assert _honeypot_severity({'ratio', 'unmatched_fp'}, named_match=True) == 'HIGH'
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_spoonmap.py::TestHoneypotSeverity -v`
Expected: FAIL with `NameError: name '_honeypot_severity' is not defined`

- [ ] **Step 3: Add the import**

In `tests/test_spoonmap.py`'s import block, add `_honeypot_severity,` alphabetically.

- [ ] **Step 4: Implement `_honeypot_severity()`**

Insert into `spoonmap.py` right after the `HONEYPOT_MIN_UNMATCHED_PORTS = 3` line and its associated comment block (i.e., right before the `HONEYPOT_PORT_PROFILES` constant added in Task 2):

```python

def _honeypot_severity(signals, named_match=False, confirmed=False):
    """Return 'HIGH'/'MEDIUM'/'LOW', or None when nothing is flagged.

    HIGH requires near-certainty: a named-product signature match or an
    active probe confirmation. Two or more independent heuristic signals
    ('ratio', 'unmatched_fp', 'silent', 'ttl_spread', 'port_profile')
    together are MEDIUM; any single heuristic signal alone is LOW. This
    structurally keeps TTL spread -- which NAT/load-balancing can also
    produce -- from ever reaching HIGH on its own: it can only ever be one
    signal among the set, never named_match or confirmed.
    """
    if named_match or confirmed:
        return 'HIGH'
    if len(signals) >= 2:
        return 'MEDIUM'
    if len(signals) == 1:
        return 'LOW'
    return None
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run pytest tests/test_spoonmap.py::TestHoneypotSeverity -v`
Expected: PASS

- [ ] **Step 6: Write the failing/updated `generate_findings()` integration tests**

First, update the two existing tests whose expectations change. In `tests/test_spoonmap.py`, change `test_tarpit_file_flags_host` (~line 1918-1926):

```python
    def test_tarpit_file_flags_host(self, nmap_dir):
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'suspected_tarpits.txt').write_text('10.0.0.1,19,20\n')
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['severity'] == 'MEDIUM'
        assert hp[0]['host'] == '10.0.0.1'
        assert '19/20' in hp[0]['detail']
```

to:

```python
    def test_tarpit_file_flags_host(self, nmap_dir):
        # A single heuristic signal is now LOW, not MEDIUM -- see
        # _honeypot_severity() and TestHoneypotSeverity. Two-plus signals
        # (test_both_signals_combine_in_one_finding, below) still reach MEDIUM.
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'suspected_tarpits.txt').write_text('10.0.0.1,19,20\n')
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['severity'] == 'LOW'
        assert hp[0]['host'] == '10.0.0.1'
        assert '19/20' in hp[0]['detail']
```

Then add new tests for the four new signal sources, appended at the end of `class TestGenerateFindingsHoneypot:` (after `test_absent_tarpit_file_no_crash`, ~line 1987):

```python
    def test_silent_open_ports_flag_host(self, nmap_dir):
        nmap_results = nmap_dir / 'nmap_results'
        nmap_results.mkdir()
        for port in ('2222', '3333', '4444'):
            xml = (
                '<?xml version="1.0"?><nmaprun>'
                f'<host><address addr="10.0.0.20" addrtype="ipv4"/>'
                f'<ports><port protocol="tcp" portid="{port}">'
                '<state state="open"/>'
                '</port></ports></host></nmaprun>'
            )
            (nmap_results / f'port{port}.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['host'] == '10.0.0.20'
        assert 'returned no data at all' in hp[0]['detail']
        assert hp[0]['severity'] == 'LOW'

    def test_suspected_honeypots_file_ttl_spread_flags_host(self, nmap_dir):
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'suspected_honeypots.txt').write_text(
            '10.0.0.21,ttl_spread,64|128\n')
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['host'] == '10.0.0.21'
        assert hp[0]['severity'] == 'LOW'
        assert 'inconsistent TTLs' in hp[0]['detail']

    def test_suspected_honeypots_file_port_profile_flags_host(self, nmap_dir):
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'suspected_honeypots.txt').write_text(
            '10.0.0.22,port_profile,Thinkst Canary\n')
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['host'] == '10.0.0.22'
        assert 'Thinkst Canary' in hp[0]['detail']

    def test_named_signature_match_is_high_severity(self, nmap_dir):
        nmap_results = nmap_dir / 'nmap_results'
        nmap_results.mkdir()
        needle, product = HONEYPOT_SIGNATURES[0]
        parts = needle.split(' ', 1)
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.23" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="open"/>'
            f'<service product="{parts[0]}" version="{parts[1] if len(parts) > 1 else ""}"/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_results / 'port22.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['severity'] == 'HIGH'
        assert product in hp[0]['detail']

    def test_confirmed_honeypot_is_high_severity(self, nmap_dir):
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'confirmed_honeypots.txt').write_text('10.0.0.24\n')
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['severity'] == 'HIGH'
        assert 'active confirmation probe' in hp[0]['detail']

    def test_all_signals_combine_into_one_finding(self, nmap_dir):
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'suspected_tarpits.txt').write_text('10.0.0.25,20,20\n')
        (nmap_dir / 'discovery' / 'suspected_honeypots.txt').write_text(
            '10.0.0.25,ttl_spread,64|128\n')
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert len(hp) == 1
        assert hp[0]['severity'] == 'MEDIUM'
        assert '20/20' in hp[0]['detail']
        assert 'inconsistent TTLs' in hp[0]['detail']

    def test_unreadable_suspected_honeypots_file_degrades_to_no_data(self, nmap_dir):
        (nmap_dir / 'discovery' / 'suspected_honeypots.txt').mkdir(parents=True)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        assert not [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']

    def test_unreadable_confirmed_honeypots_file_degrades_to_no_data(self, nmap_dir):
        (nmap_dir / 'discovery' / 'confirmed_honeypots.txt').mkdir(parents=True)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        assert not [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
```

Add `HONEYPOT_SIGNATURES,` to the test file's import block if not already added in Task 3 (it was — no action needed if Task 3 ran first).

- [ ] **Step 7: Run the new/updated tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestGenerateFindingsHoneypot -v`
Expected: FAIL — `test_tarpit_file_flags_host` fails on the old MEDIUM-emitting code (asserts LOW now); the six new tests fail because `generate_findings()` doesn't yet read the new files/signals

- [ ] **Step 8: Replace the honeypot finding block in `generate_findings()`**

In `spoonmap.py`, replace the entire block from `spoonmap.py:3597` (`# ── suspected honeypot / tarpit hosts ─...`) through `spoonmap.py:3637` (the closing `'deprioritizing further enumeration of this host and manually validating '` / `'before trusting other findings collected from it.')` call) — i.e. everything from:

```python
    # ── suspected honeypot / tarpit hosts ─────────────────────────────────────
    tarpit_hosts = {}   # {ip: (open_count, total_scanned)}
```

through:

```python
        add('MEDIUM', ip, 'multiple', 'Likely Honeypot / Decoy Host',
            '; '.join(reasons) + '. Consistent with tarpit/decoy tooling (e.g. LaBrea, '
            'portspoof, Artillery) rather than a genuine service host. Recommend '
            'deprioritizing further enumeration of this host and manually validating '
            'before trusting other findings collected from it.')
```

with:

```python
    # ── suspected honeypot / decoy hosts ──────────────────────────────────────
    disc = _disc(output_path)
    signals_by_ip = {}   # {ip: {signal_name, ...}}
    reasons_by_ip = {}   # {ip: [human-readable reason, ...]}

    def _add_signal(ip, name, reason):
        signals_by_ip.setdefault(ip, set()).add(name)
        reasons_by_ip.setdefault(ip, []).append(reason)

    tarpit_file = f'{disc}/suspected_tarpits.txt'
    if os.path.exists(tarpit_file):
        # _report_suspected_tarpits() writes this file line by line, not
        # atomically, so an interrupt or a full disk can leave a partial final
        # line ('10.0.0.1,5,') that has three comma-separated parts but does
        # not parse as two ints. A corrupt state file must degrade to "no
        # tarpit data", never take down the findings phase — which is the last
        # thing to run, so a crash here loses all three findings files and
        # recurs on every later run until something rewrites the file.
        try:
            with open(tarpit_file) as fh:
                for line in fh:
                    parts = line.strip().split(',')
                    if len(parts) == 3:
                        ip, open_count, total = parts
                        try:
                            oc, total_i = int(open_count), int(total)
                        except ValueError:
                            continue
                        _add_signal(ip, 'ratio',
                                    f'{oc}/{total_i} scanned TCP ports responded open')
        except OSError:
            pass

    unmatched_counts = _count_unmatched_service_ports(output_path)
    for ip, count in unmatched_counts.items():
        if count >= HONEYPOT_MIN_UNMATCHED_PORTS:
            _add_signal(ip, 'unmatched_fp',
                        f'{count} open ports returned data matching no known service signature')

    silent_counts = _count_silent_open_ports(output_path)
    for ip, count in silent_counts.items():
        if count >= HONEYPOT_MIN_UNMATCHED_PORTS:
            _add_signal(ip, 'silent',
                        f'{count} open ports accepted a connection and returned no data at all')

    honeypot_file = f'{disc}/suspected_honeypots.txt'
    if os.path.exists(honeypot_file):
        try:
            with open(honeypot_file) as fh:
                for line in fh:
                    parts = line.strip().split(',', 2)
                    if len(parts) == 3:
                        ip, sig_type, value = parts
                        if sig_type == 'ttl_spread':
                            _add_signal(ip, 'ttl_spread',
                                        f'TCP responses observed with inconsistent TTLs '
                                        f'({value}) across scanned ports on one host')
                        elif sig_type == 'port_profile':
                            _add_signal(ip, 'port_profile',
                                        f'open port set matches the known deployment '
                                        f'profile of {value}')
        except OSError:
            pass

    named_matches = _named_honeypot_matches(output_path)  # {ip: product_name}
    named_matches.update(_vnc_heralding_match(output_path))  # merge in the vnc-info-based signal

    confirmed_ips = set()
    confirmed_file = f'{disc}/confirmed_honeypots.txt'
    if os.path.exists(confirmed_file):
        try:
            with open(confirmed_file) as fh:
                confirmed_ips = {line.strip() for line in fh if line.strip()}
        except OSError:
            pass

    all_flagged_ips = set(signals_by_ip) | set(named_matches) | confirmed_ips
    for ip in sorted(all_flagged_ips, key=_ip_sort_key):
        signals = signals_by_ip.get(ip, set())
        named = named_matches.get(ip)
        confirmed = ip in confirmed_ips
        severity = _honeypot_severity(signals, named_match=bool(named), confirmed=confirmed)
        if severity is None:
            continue
        reasons = list(reasons_by_ip.get(ip, []))
        if named:
            reasons.insert(0, f'service fingerprint matches known honeypot product {named}')
        if confirmed:
            reasons.append('active confirmation probe: host answered on a port never '
                            'scanned open, consistent with a decoy accepting all connections')
        add(severity, ip, 'multiple', 'Likely Honeypot / Decoy Host',
            '; '.join(reasons) + '. Consistent with tarpit/decoy tooling (e.g. LaBrea, '
            'portspoof, Cowrie, Dionaea, Artillery, Thinkst Canary) rather than a genuine '
            'service host. Recommend deprioritizing further enumeration of this host and '
            'manually validating before trusting other findings collected from it.')
```

Note: `disc = _disc(output_path)` — check whether `generate_findings()` already defines a `disc` local earlier in the function (it references `_disc(output_path)` inline at the original `tarpit_file` line, so no prior `disc` local exists at this point); if a later part of the function already assigns `disc = _disc(output_path)` independently, keep both assignments as-is — they're idempotent and harmless to duplicate here since it's a cheap string join, not I/O.

- [ ] **Step 9: Run the tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py::TestGenerateFindingsHoneypot tests/test_spoonmap.py::TestHoneypotSeverity -v`
Expected: PASS, all tests including the updated `test_tarpit_file_flags_host` (now LOW) and `test_both_signals_combine_in_one_finding` (still MEDIUM)

- [ ] **Step 10: Run the full test suite and coverage check**

Run: `uv run pytest tests/`
Expected: PASS, coverage floor met (95%, enforced by `pyproject.toml` `addopts`)

- [ ] **Step 11: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: tier honeypot finding severity by confidence across all signals"
```

---

## Task 7: Documentation, lint/SAST, and final verification

Documents the expanded behavior in CLAUDE.md (this repo's durable-reasoning record), runs the full local gate the CI would run, and removes the planning docs per this repo's established convention (commit `9ea2bb3`) before the branch is ready for review.

**Files:**
- Modify: `CLAUDE.md` (extend the existing "Honeypot/tarpit detection" paragraph)
- Delete: `docs/superpowers/specs/2026-08-28-honeypot-detection-design.md`, `docs/superpowers/plans/2026-08-28-honeypot-detection.md` (this file)

- [ ] **Step 1: Extend the CLAUDE.md paragraph**

Find the existing paragraph beginning `**Honeypot/tarpit detection**:` in `CLAUDE.md` (under "## Key Implementation Details"). Append after its final sentence (which ends `...and printed as 'Hosts Found on Port U_53'.`):

```
 Four more signals feed the same finding, each combined and tiered by
`_honeypot_severity()` rather than emitted as separate findings: TTL
inconsistency across a host's open ports (`_ttl_spread_by_host()`, read back
from `masscan_results/*.xml` at Stage 1, since one TCP/IP stack always
reports one TTL — several differing values means several emulated listeners
behind one address, though NAT/load-balancing can produce the same pattern,
which is why this signal alone is capped at LOW and can never alone reach
HIGH); known port-profile matching against `HONEYPOT_PORT_PROFILES`
(Thinkst Canary, Artillery — placeholders pending verification against
current upstream defaults); named-product signature matching against
`HONEYPOT_SIGNATURES` (Cowrie/Kippo, Dionaea default banners — same
verification caveat) via the -sV service data already captured; a
source-verified Heralding VNC honeypot tell (`_vnc_heralding_match()`,
Task 3 Step 7 — vnc-info reporting RFB protocol 3.7 with no security-type
list, since Heralding's VNC capability hardcodes that exact version and
drops the connection on any client mismatch, unlike a real RFB server)
read from `nse_results/*.xml` rather than `nmap_results/*.xml`; and
silent-open-port counting (`_count_silent_open_ports()`), which complements
the existing unmatched-fingerprint count by catching a tarpit that holds a
connection open and sends nothing back — `servicefp` is only set when *some*
data came back and failed to match, so a LaBrea-style silent host previously
scored zero on that check alone. `_iter_open_tcp_ports()` is the shared,
per-element-defensive XML walk both nmap-side counters and the signature
matcher use, factored out of what was originally
`_count_unmatched_service_ports()`'s own walk. Severity is HIGH for a named
signature match or an active-probe confirmation, MEDIUM for two or more
heuristic signals together, LOW for exactly one — a behavior change from the
single flat MEDIUM this finding used to emit unconditionally. An optional
active confirmation probe (`_active_confirm_probe()`) attempts a raw TCP
connect against a handful of high, never-scanned ports
(`_select_confirm_probe_ports()`, deterministic per-IP via a seeded
`random.Random(ip)` rather than global randomness, so it is reproducible and
testable) on any flagged host; a real host has no reason to answer on an
ephemeral port outside the scan, so an answer is treated as confirmation.
This is the one signal that sends new traffic, so it is gated behind
`honeypot_active_confirm` in config.json — default false, absent means
false, no interactive prompt of its own — mirroring `check_for_updates`'s
existing precedent exactly and for the same reason: SpooNMAP runs from
client-network jumpboxes, and an unrequested probe against a possible
client-deployed decoy must never fire without the operator explicitly
turning it on. (An earlier design considered a live per-host prompt after
the Stage 1 warning instead; every `input()` call in this codebase happens
in `main()` before any scan starts, and `mass_scan()` never prompts
mid-run, so the config-only gate was used instead to stay consistent with
that pattern.) `discovery/suspected_honeypots.txt` (Stage 1: TTL spread and
port-profile hits, one line per `(ip, signal)` pair) and
`discovery/confirmed_honeypots.txt` (Stage 2: active-probe confirmations)
are new sibling files to the existing `discovery/suspected_tarpits.txt`,
read back the same defensively-parsed way in `generate_findings()`.
```

- [ ] **Step 2: Run the full test suite, lint, and SAST locally**

Run:
```bash
uv run pytest tests/
uv run ruff check spoonmap.py tests/
uv run bandit -c pyproject.toml -r spoonmap.py --baseline .bandit-baseline.json
```
Expected: all PASS. If bandit reports a new finding on `_active_confirm_probe()`'s `socket.create_connection` call (unlikely — it is not a subprocess/shell/eval call bandit's ruleset flags — but check), do not add an inline `# nosec`; regenerate `.bandit-baseline.json` deliberately and justify the addition in the commit message, per this repo's documented convention.

- [ ] **Step 3: Remove the planning docs and commit CLAUDE.md**

```bash
cd /tmp/spoonmap-honeypot-detect
git rm docs/superpowers/specs/2026-08-28-honeypot-detection-design.md docs/superpowers/plans/2026-08-28-honeypot-detection.md
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
docs: document expanded honeypot detection in CLAUDE.md; drop planning docs

Following this repo's precedent (9ea2bb3): spec/plan docs stay out of
the public repo long-term, with durable reasoning folded into CLAUDE.md
instead.
EOF
)"
```

- [ ] **Step 4: Final full-suite verification**

Run: `uv run pytest tests/ -q`
Expected: PASS, no skips other than the documented port-conflict/root-gated ones

---

## Self-Review Notes

- **Spec coverage:** all four new signals (TTL spread, port-profile, named-signature, silent-open) plus the source-verified Heralding VNC honeypot signature (`_vnc_heralding_match()`, Task 3 Step 7) are implemented (Tasks 1-3), severity tiering is implemented (Task 6), the active probe is implemented and config-gated (Tasks 4-5), and the behavior-change/placeholder-signature caveats from the spec are carried into code comments and CLAUDE.md (Task 7). Uptime/lastboot correlation, OS/CPE-conflict detection, and a standalone vnclowpot signature (checked, no reliable tell found) remain explicitly out of scope, as agreed.
- **Deviation flagged prominently:** the interactive-prompt-vs-config-only-gate change is called out in Global Constraints, in Task 4's design, and in the CLAUDE.md paragraph — not buried.
- **Type/name consistency checked:** `_flag_honeypot_signals()` (Task 2) is consumed by `_confirm_flagged_honeypots()` (Task 4) and by nothing else; `_iter_open_tcp_ports()` (Task 1) is consumed by `_count_unmatched_service_ports()`, `_count_silent_open_ports()` (Task 1), and `_named_honeypot_matches()` (Task 3) — all three call sites use the same `(ip, service_elem)` tuple shape. `_vnc_heralding_match()` (Task 3 Step 7) deliberately does *not* reuse `_iter_open_tcp_ports()` — that generator only yields `<service>` elements from `nmap_results/*.xml`, not the `<script id="vnc-info">` elements in `nse_results/*.xml` this signal needs — and merges into `named_matches` (a plain `dict.update()`, both returning the same `{ip: product_name}` shape) rather than a fifth parallel dict threaded through `_honeypot_severity()`. `mass_scan()`'s new `honeypot_active_confirm` parameter name matches the config key name and the `main()` local variable name throughout Task 5.
