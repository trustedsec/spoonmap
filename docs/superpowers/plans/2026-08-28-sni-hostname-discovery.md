# SNI/TLS-Certificate Hostname Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract hostnames from `ssl-cert` NSE output (commonName/SAN) already collected on External scans, merge non-wildcard names into the operator hostname map, and surface all names as a new LOW-severity finding.

**Architecture:** Two small pure/near-pure functions added to `spoonmap.py` — `_extract_ssl_cert_hostnames()` (regex extraction from one script's text) and `_merge_ssl_cert_hostnames()` (walks `nse_results/*.xml`, fills gaps in `ip_to_hostname`, persists to `ip_hostname_map.json`) — plus one new block in `generate_findings()`'s existing per-port loop and one new call site in `main()`. No new scanning, no new dependencies.

**Tech Stack:** Python 3.8+ stdlib only (`re`, `xml.etree.ElementTree` as `etree`, `json`), pytest.

## Global Constraints

- Python 3.8+ compatible syntax throughout (repo's `requires-python` floor; no walrus-in-comprehension tricks or 3.10+-only syntax).
- No new third-party dependencies — `spoonmap.py` is stdlib-only by design (CLAUDE.md, Release Versioning section).
- Every `etree.parse()` site must guard the parse (`except Exception: continue`) and use `.attrib.get(...)` rather than bare subscripting, matching the file's existing per-element-defensive XML parsing convention (CLAUDE.md, "XML result parsing is per-element defensive").
- Durable writes (`ip_hostname_map.json`) go through `_write_if_changed()` (which itself uses `_atomic_write()`), never a bare `open(...).write()`.
- 95% coverage floor is enforced by pytest's `addopts` — new code needs tests exercising it, not just the happy path.
- Target branch/PR base is `nightly`, not `main` (repo convention: nightly cuts release candidates; confirmed `origin/main` and `origin/nightly` are at the same commit as of this plan).

---

### Task 1: `_extract_ssl_cert_hostnames()` helper

**Files:**
- Modify: `spoonmap.py` — insert new function immediately after `resolve_hostname()` ends (currently `spoonmap.py:581`), before `_write_if_changed()` (currently `spoonmap.py:583`).
- Test: `tests/test_spoonmap.py` — new `TestExtractSslCertHostnames` class (place near other standalone-helper test classes, e.g. above `class TestGenerateFindings:` at `tests/test_spoonmap.py:1154`).

**Interfaces:**
- Produces: `_extract_ssl_cert_hostnames(ssl_cert_output: str) -> list[str]` — deduped, order-preserved list of hostnames found in one `ssl-cert` script's output text (module-level function on `spoonmap`). CN first, then each `Subject Alternative Name` `DNS:` entry in printed order. Wildcard names (`*.example.com`) are included in the returned list — callers that need to exclude them do so themselves. Empty/malformed input returns `[]`.

- [ ] **Step 1: Write the failing tests**

Add near the top of `tests/test_spoonmap.py`, in whatever import block already imports other module-level helpers from `spoonmap` (e.g. alongside `resolve_hostname`, `is_hostname`), add `_extract_ssl_cert_hostnames` to the import list if the test file imports names individually; otherwise reference as `spoonmap._extract_ssl_cert_hostnames` matching the file's existing convention for private helpers (check how e.g. `_fname_port` or `_ip_sort_key` are referenced in existing tests and mirror that exactly).

```python
class TestExtractSslCertHostnames:
    def test_cn_only(self):
        out = (
            'Subject: commonName=example.corp\n'
            'Issuer: commonName=Example CA\n'
            'Not valid before: 2021-01-01T00:00:00\n'
            'Not valid after:  2099-01-01T00:00:00\n'
        )
        assert _extract_ssl_cert_hostnames(out) == ['example.corp']

    def test_cn_plus_san(self):
        out = (
            'Subject: commonName=example.corp\n'
            'Subject Alternative Name: DNS:example.corp, DNS:www.example.corp\n'
            'Issuer: commonName=Example CA\n'
        )
        assert _extract_ssl_cert_hostnames(out) == ['example.corp', 'www.example.corp']

    def test_san_only_no_cn(self):
        out = 'Subject Alternative Name: DNS:api.example.corp, DNS:cdn.example.corp\n'
        assert _extract_ssl_cert_hostnames(out) == ['api.example.corp', 'cdn.example.corp']

    def test_wildcard_included_in_result(self):
        out = (
            'Subject: commonName=example.corp\n'
            'Subject Alternative Name: DNS:example.corp, DNS:*.example.corp\n'
        )
        assert _extract_ssl_cert_hostnames(out) == ['example.corp', '*.example.corp']

    def test_does_not_pick_up_issuer_common_name(self):
        # Issuer's commonName must never be mistaken for the subject's hostname.
        out = (
            'Subject: commonName=example.corp\n'
            'Issuer: commonName=DigiCert TLS RSA SHA256 2020 CA1\n'
        )
        assert _extract_ssl_cert_hostnames(out) == ['example.corp']

    def test_duplicate_name_in_cn_and_san_not_repeated(self):
        out = (
            'Subject: commonName=example.corp\n'
            'Subject Alternative Name: DNS:example.corp, DNS:www.example.corp\n'
        )
        result = _extract_ssl_cert_hostnames(out)
        assert result == ['example.corp', 'www.example.corp']
        assert result.count('example.corp') == 1

    def test_malformed_output_returns_empty_list(self):
        assert _extract_ssl_cert_hostnames('garbage, no useful fields here') == []

    def test_empty_string_returns_empty_list(self):
        assert _extract_ssl_cert_hostnames('') == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestExtractSslCertHostnames -v`
Expected: FAIL — `AttributeError` / `NameError` (`_extract_ssl_cert_hostnames` does not exist yet).

- [ ] **Step 3: Implement**

Insert into `spoonmap.py` right after `resolve_hostname()` (after its closing `return None` at line 581, before the blank line and `def _write_if_changed` at line 583):

```python
def _extract_ssl_cert_hostnames(ssl_cert_output):
    """Extract hostnames from ssl-cert NSE script output (CN + SAN).

    Returns a deduped, order-preserved list: the certificate's commonName
    first, then each Subject Alternative Name DNS: entry in the order nmap
    printed them.  Wildcard names (e.g. '*.example.com') are returned like
    any other name -- callers that feed a scan target must filter those out
    themselves.  Anchored to the 'Subject:' line specifically (not
    'Issuer:'), since ssl-cert output carries a commonName for both and only
    the subject's identifies the host being scanned.
    """
    hostnames = []
    seen = set()

    cn_match = re.search(r'^Subject:.*?commonName=([^\s/,]+)', ssl_cert_output, re.MULTILINE)
    if cn_match:
        cn = cn_match.group(1).strip()
        if cn and cn not in seen:
            hostnames.append(cn)
            seen.add(cn)

    san_match = re.search(r'^Subject Alternative Name:\s*(.+)$', ssl_cert_output, re.MULTILINE)
    if san_match:
        for entry in san_match.group(1).split(','):
            entry = entry.strip()
            if entry.startswith('DNS:'):
                name = entry[len('DNS:'):].strip()
                if name and name not in seen:
                    hostnames.append(name)
                    seen.add(name)

    return hostnames
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py::TestExtractSslCertHostnames -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: add ssl-cert CN/SAN hostname extraction helper"
```

---

### Task 2: `_merge_ssl_cert_hostnames()` and wiring into `main()`

**Files:**
- Modify: `spoonmap.py` — insert new function immediately after `preprocess_targets()` ends (currently `spoonmap.py:945`, `return masscan_file, ip_to_hostname`), before `_get_scripts_for_port()` (currently `spoonmap.py:947`).
- Modify: `spoonmap.py` — `main()`, inside the `if banner_scan or script_scan:` block, immediately after the `snmp_any_validated` assignment (currently `spoonmap.py:6566-6568`) and before the `# Combine all live hosts into one file` comment (currently `spoonmap.py:6570`).
- Test: `tests/test_spoonmap.py` — new `TestMergeSslCertHostnames` class (place near `TestGenerateFindings`, since both consume `nse_results/*.xml`).

**Interfaces:**
- Consumes: `_extract_ssl_cert_hostnames(ssl_cert_output: str) -> list[str]` (Task 1). `_disc(output_path) -> str` (existing, `spoonmap.py:1518`). `_write_if_changed(path, content)` (existing, `spoonmap.py:583`). `etree` = `xml.etree.ElementTree` (already imported module-wide as `etree`).
- Produces: `_merge_ssl_cert_hostnames(output_path: str, ip_to_hostname: dict) -> dict` — returns a new dict equal to `ip_to_hostname` plus any IP that had no entry and does have a non-wildcard cert-derived name. Persists the merged dict to `<output_path>/discovery/ip_hostname_map.json` via `_write_if_changed()`. Never mutates the `ip_to_hostname` argument in place (callers rebind: `ip_to_hostname = _merge_ssl_cert_hostnames(output_path, ip_to_hostname)`).

- [ ] **Step 1: Write the failing tests**

```python
class TestMergeSslCertHostnames:
    def test_fills_gap_for_ip_with_no_prior_entry(self, tmp_path):
        (tmp_path / 'nse_results').mkdir()
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Subject: commonName=example.corp\n'})
        (tmp_path / 'nse_results' / 'port443.xml').write_text(xml)

        result = _merge_ssl_cert_hostnames(str(tmp_path), {})

        assert result == {'1.2.3.4': 'example.corp'}

    def test_never_overwrites_operator_supplied_entry(self, tmp_path):
        (tmp_path / 'nse_results').mkdir()
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Subject: commonName=cert-name.corp\n'})
        (tmp_path / 'nse_results' / 'port443.xml').write_text(xml)

        result = _merge_ssl_cert_hostnames(str(tmp_path), {'1.2.3.4': 'operator-name.corp'})

        assert result == {'1.2.3.4': 'operator-name.corp'}

    def test_wildcard_only_cert_does_not_fill_gap(self, tmp_path):
        (tmp_path / 'nse_results').mkdir()
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Subject Alternative Name: DNS:*.example.corp\n'})
        (tmp_path / 'nse_results' / 'port443.xml').write_text(xml)

        result = _merge_ssl_cert_hostnames(str(tmp_path), {})

        assert result == {}

    def test_cn_preferred_over_wildcard_san(self, tmp_path):
        (tmp_path / 'nse_results').mkdir()
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': (
                            'Subject: commonName=example.corp\n'
                            'Subject Alternative Name: DNS:*.example.corp, DNS:example.corp\n'
                        )})
        (tmp_path / 'nse_results' / 'port443.xml').write_text(xml)

        result = _merge_ssl_cert_hostnames(str(tmp_path), {})

        assert result == {'1.2.3.4': 'example.corp'}

    def test_no_op_when_nse_results_missing(self, tmp_path):
        result = _merge_ssl_cert_hostnames(str(tmp_path), {'9.9.9.9': 'kept.corp'})
        assert result == {'9.9.9.9': 'kept.corp'}

    def test_no_op_when_no_ssl_cert_script_present(self, tmp_path):
        (tmp_path / 'nse_results').mkdir()
        xml = _nmap_xml('1.2.3.4', 'tcp', '445',
                        scripts={'smb2-security-mode': 'Message signing enabled but not required'})
        (tmp_path / 'nse_results' / 'port445.xml').write_text(xml)

        result = _merge_ssl_cert_hostnames(str(tmp_path), {})

        assert result == {}

    def test_writes_merged_map_to_disk(self, tmp_path):
        (tmp_path / 'nse_results').mkdir()
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Subject: commonName=example.corp\n'})
        (tmp_path / 'nse_results' / 'port443.xml').write_text(xml)

        _merge_ssl_cert_hostnames(str(tmp_path), {})

        import json as _json
        on_disk = _json.loads((tmp_path / 'discovery' / 'ip_hostname_map.json').read_text())
        assert on_disk == {'1.2.3.4': 'example.corp'}

    def test_ignores_unparseable_xml_file(self, tmp_path):
        (tmp_path / 'nse_results').mkdir()
        (tmp_path / 'nse_results' / 'port443.xml').write_text('not valid xml <<<')

        result = _merge_ssl_cert_hostnames(str(tmp_path), {})

        assert result == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py::TestMergeSslCertHostnames -v`
Expected: FAIL — `_merge_ssl_cert_hostnames` does not exist yet.

- [ ] **Step 3: Implement**

Insert into `spoonmap.py` right after `preprocess_targets()`'s `return masscan_file, ip_to_hostname` (line 945), before `def _get_scripts_for_port(dest_port, target_scan):` (line 947):

```python
def _merge_ssl_cert_hostnames(output_path, ip_to_hostname):
    """Fill gaps in ip_to_hostname from ssl-cert CN/SAN data in nse_results/.

    Never overwrites an existing (operator-supplied) entry -- a name typed
    into the target file always wins over a cert-derived guess.  For an IP
    with no prior entry, prefers the certificate's commonName; falls back to
    the first non-wildcard Subject Alternative Name.  A host whose only
    names are wildcards gets no entry, since a wildcard is not a usable
    scan target.  Returns a new dict; persists it to
    <output_path>/discovery/ip_hostname_map.json via _write_if_changed().
    """
    nse_dir = f'{output_path}/nse_results'
    merged = dict(ip_to_hostname)

    if os.path.isdir(nse_dir):
        for fname in sorted(os.listdir(nse_dir)):
            if not fname.endswith('.xml'):
                continue
            try:
                root = etree.parse(f'{nse_dir}/{fname}')
            except Exception:
                continue

            for host in root.findall('host'):
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find('address')
                ip = addr_elem.attrib.get('addr') if addr_elem is not None else None
                if not ip or ip in merged:
                    continue

                for port_elem in host.iter('port'):
                    scripts = {s.attrib['id']: s.attrib.get('output', '')
                               for s in port_elem.findall('script') if s.attrib.get('id')}
                    ssl_out = scripts.get('ssl-cert')
                    if not ssl_out:
                        continue
                    for name in _extract_ssl_cert_hostnames(ssl_out):
                        if not name.startswith('*.'):
                            merged[ip] = name
                            break
                    if ip in merged:
                        break

    mapping_file = os.path.join(_disc(output_path), 'ip_hostname_map.json')
    os.makedirs(_disc(output_path), exist_ok=True)
    _write_if_changed(mapping_file, json.dumps(merged, indent=2))

    return merged
```

Then wire it into `main()`. In the `if banner_scan or script_scan:` block, change:

```python
            snmp_any_validated = {}
            if script_scan:
                snmp_any_validated = _validate_snmp_any_community(output_path, target_scan)
```

to:

```python
            snmp_any_validated = {}
            if script_scan:
                snmp_any_validated = _validate_snmp_any_community(output_path, target_scan)
                ip_to_hostname = _merge_ssl_cert_hostnames(output_path, ip_to_hostname)
```

This runs before `_aggregate_result_dir(result_dir, ip_to_hostname)` (line 6581) and before `generate_findings(...)` (line 6592), so both pick up the merged map — `_aggregate_result_dir` via the rebound local, `generate_findings` via its own fresh read of `ip_hostname_map.json` off disk (`spoonmap.py:3578-3585`). Gated on `script_scan` because `nse_results/` (and therefore any `ssl-cert` output) only exists when `script_scan` is True — see `spoonmap.py:2661` (`if script_scan and not interrupt_event.is_set():`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py::TestMergeSslCertHostnames -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Run the full suite to confirm no regressions in `main()`**

Run: `uv run pytest tests/ -x -q`
Expected: all existing tests still pass (the `main()` change only adds a call inside an existing `if script_scan:` branch; no signature changes).

- [ ] **Step 6: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: merge ssl-cert-derived hostnames into the operator hostname map"
```

---

### Task 3: `TLS Certificate Hostname(s) Identified` finding

**Files:**
- Modify: `spoonmap.py` — `generate_findings()`, insert new block immediately after the existing `# ── ssl-cert — expired (External only) ───` block (currently `spoonmap.py:3844-3852`), inside the same `for port_elem in host.iter('port'):` loop.
- Modify: `spoonmap.py` — `_FINDING_REPRO` dict (currently ends `spoonmap.py:4766`), add a new entry for the new title, modeled on the existing `'Expired TLS Certificate'` entry (`spoonmap.py:4473-4480`).
- Test: `tests/test_spoonmap.py` — add methods to the existing `# ── TLS certificate expiry ──` section of `TestGenerateFindings` (near `test_expired_cert_flagged` / `test_valid_cert_not_flagged`, `tests/test_spoonmap.py:1422-1436`).

**Interfaces:**
- Consumes: `_extract_ssl_cert_hostnames(ssl_cert_output: str) -> list[str]` (Task 1). Existing `add(sev, host, port, title, detail='')` closure inside `generate_findings()` (`spoonmap.py:3529`).
- Produces: nothing consumed by later tasks — this is the terminal, user-visible deliverable.

- [ ] **Step 1: Write the failing tests**

```python
    def test_ssl_cert_hostnames_flagged_on_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': (
                            'Subject: commonName=example.corp\n'
                            'Subject Alternative Name: DNS:example.corp, DNS:www.example.corp\n'
                        )})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'TLS Certificate Hostname(s) Identified' in txt
        assert 'example.corp' in txt
        assert 'www.example.corp' in txt

    def test_ssl_cert_hostnames_includes_wildcard_in_detail(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': (
                            'Subject: commonName=example.corp\n'
                            'Subject Alternative Name: DNS:example.corp, DNS:*.example.corp\n'
                        )})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert '*.example.corp' in txt

    def test_ssl_cert_hostnames_not_flagged_on_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.2', 'tcp', '443',
                        scripts={'ssl-cert': 'Subject: commonName=internal.corp\n'})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'TLS Certificate Hostname(s) Identified' not in (nmap_dir / 'findings.txt').read_text()

    def test_ssl_cert_no_parseable_names_no_finding(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Not valid after:  2099-01-01T00:00:00\n'})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'TLS Certificate Hostname(s) Identified' not in (nmap_dir / 'findings.txt').read_text()

    def test_ssl_cert_hostname_finding_is_low_severity(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Subject: commonName=example.corp\n'})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        import json as _json
        records = _json.loads((nmap_dir / 'findings.json').read_text())
        matches = [r for r in records if r['title'] == 'TLS Certificate Hostname(s) Identified']
        assert len(matches) == 1
        assert matches[0]['severity'] == 'LOW'
```

Check `findings.json`'s exact record key names before assuming `'severity'`/`'title'` — open `tests/test_spoonmap.py` around `test_anonymous_ftp_detected_rated_low_with_review_note` (`tests/test_spoonmap.py:1157-1168`) and match whatever keys that existing test reads. `SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']` (`spoonmap.py:3336`) has no `INFO` tier — `findings.sort()` calls `SEVERITY_ORDER.index(f[0])`, which raises `ValueError` on an unlisted severity and would take down the whole findings phase. Use `'LOW'`, matching the precedent of other informational findings like "SQL Server Instance Discovered" (`spoonmap.py:3564`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_spoonmap.py -k ssl_cert_hostname -v`
Expected: FAIL — no matching finding produced yet.

- [ ] **Step 3: Implement**

In `generate_findings()`, immediately after the existing block:

```python
                # ── ssl-cert — expired (External only) ───────────────────
                if 'ssl-cert' in scripts and target_scan == 'External':
                    out = scripts['ssl-cert']
                    m = re.search(r'Not valid after:\s+(\d{4}-\d{2}-\d{2})', out)
                    if m:
                        expiry = datetime.date.fromisoformat(m.group(1))
                        if expiry < datetime.date.today():
                            add('MEDIUM', ip, port_str, 'Expired TLS Certificate',
                                f'Certificate expired on {expiry}.')
```

add:

```python
                # ── ssl-cert — hostnames from CN/SAN (External only) ─────
                if 'ssl-cert' in scripts and target_scan == 'External':
                    cert_hostnames = _extract_ssl_cert_hostnames(scripts['ssl-cert'])
                    if cert_hostnames:
                        add('LOW', ip, port_str, 'TLS Certificate Hostname(s) Identified',
                            f'Certificate presents: {", ".join(cert_hostnames)}.')
```

In `_FINDING_REPRO`, immediately after the existing `'Expired TLS Certificate'` entry (`spoonmap.py:4473-4480`):

```python
    'TLS Certificate Hostname(s) Identified': {
        'flags': '--script ssl-cert',
        'sample': (
            'PORT    STATE SERVICE\n'
            '443/tcp open  https\n'
            '| ssl-cert: Subject: commonName=example.corp\n'
            '|_Subject Alternative Name: DNS:example.corp, DNS:www.example.corp'
        ),
    },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_spoonmap.py -k ssl_cert_hostname -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest tests/ -x -q`
Expected: all tests pass, coverage still at/above the 95% floor.

- [ ] **Step 6: Commit**

```bash
git add spoonmap.py tests/test_spoonmap.py
git commit -m "feat: report TLS certificate CN/SAN hostnames as a LOW-severity finding"
```

---

### Task 4: Documentation

**Files:**
- Modify: `CLAUDE.md` — add a short subsection describing the feature, matching the file's existing documentation depth for related subsystems (e.g. the "Hostname support" bullet under **Key Implementation Details**, and the "Honeypot/tarpit detection" bullet immediately above it, as the closest precedent for a self-contained detection feature documented in one bullet).

**Interfaces:**
- Consumes: nothing — pure documentation, written after Tasks 1-3 land so line/behavior references are accurate.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Add a bullet to `CLAUDE.md`'s "Key Implementation Details" section**

Insert a new bullet immediately after the existing **Hostname support** bullet (`CLAUDE.md`, search for `**Hostname support**:`):

```markdown
- **TLS certificate hostname discovery**: on External scans, `_extract_ssl_cert_hostnames()` parses the `ssl-cert` NSE output SpooNMAP already collects (commonName off the `Subject:` line, each `DNS:` entry off `Subject Alternative Name:`) and reports every name found as a LOW-severity `TLS Certificate Hostname(s) Identified` finding, wildcards included. Separately, `_merge_ssl_cert_hostnames()` runs right after the NSE script pass (gated on `script_scan`, since that's the only time `nse_results/` exists) and fills gaps in `ip_to_hostname` with the first non-wildcard name per host — never overwriting an operator-supplied hostname from the target file — then rewrites `discovery/ip_hostname_map.json`. It runs before `_aggregate_result_dir()` and `generate_findings()` (which re-reads that file fresh) so `spoonmap_output.*` and the findings report both reflect the merged map for the current run. It does not retroactively change what *this* run's nmap invocations targeted — hostname-based targeting via `create_hostname_target_file()` already happened earlier in the same run using whatever `ip_to_hostname` looked like at that point; the benefit is to this run's reporting and to a future `--resume`.
```

- [ ] **Step 2: Verify the doc references are accurate**

Run: `grep -n "_extract_ssl_cert_hostnames\|_merge_ssl_cert_hostnames" spoonmap.py` and confirm both function names match exactly what Tasks 1-2 implemented (no drift from renames during review).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document SNI/TLS-certificate hostname discovery"
```

---

## Post-plan: PR target

Per this plan's Global Constraints, open the PR against `nightly`, not `main` — confirm `origin/nightly`'s tip hasn't diverged from `origin/main` since this plan was written (`git rev-parse origin/main origin/nightly`); if it has, rebase onto `origin/nightly` before opening the PR.
