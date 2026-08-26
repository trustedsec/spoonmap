# CLAUDE.md

## Overview

SpooNMAP is a Python 3.8+ wrapper that orchestrates masscan (fast port discovery) followed by nmap (service banner grabbing). Both external tools must be installed separately.

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

`tests/test_nse_integration.py` binds real local ports and shells out to real `nmap`, so its results depend on the machine. A class names the port it needs with a `required_tcp_port` / `required_udp_port` attribute and `pytest_runtest_setup()` in `tests/conftest.py` skips it if that port is occupied — checked immediately before each test, not at import, because a port free during collection can be taken by the time the test runs (that race produced spurious failures). A skip there always means a port conflict or missing root, never an NSE result; the assertions themselves are unconditional.

CI (`.github/workflows/ci.yml`) runs that same suite on every pull request and on
pushes to `main`, with nmap installed on every job that needs it — `apt` on
Ubuntu, `brew` on macOS, since the tool is developed on macOS and until that
install was added there too, all 26 NSE integration tests silently skipped on
that platform. Each such job also asserts `shutil.which('nmap')` is not `None`
before running, so a broken install fails the job instead of quietly turning
those assertions into skips. Two jobs cover the suite itself, because the test
toolchain and the tool have different Python floors: `test` covers 3.10–3.13 on
Ubuntu plus 3.12 on macOS against `uv.lock` (`uv run --frozen`), and
`test-legacy` covers 3.8/3.9 with pytest resolved fresh outside the project
(`uv run --isolated --no-project`). `uv.lock` is deliberately scoped to 3.10+ via
`[tool.uv] environments` so it can hold a pytest patched for CVE-2025-71176
(fixed in 9.0.3, which needs Python 3.10+) instead of pinning a vulnerable 8.x
for 3.8/3.9; `requires-python` stays `>=3.8` because `spoonmap.py` itself is
dependency-free stdlib. The 95% coverage floor is enforced by pytest's `addopts`,
so every job inherits it without restating it. Both jobs pass `-rs` to pytest so
a test that starts skipping shows up in the log instead of vanishing into a
bare count. `uv lock --check` runs exactly once, in the `lint` job, rather than
once per `test` matrix leg — the lock file's freshness doesn't vary by
interpreter version, so five copies of the check were five copies of the same
answer.

A dedicated `nse-root` job runs only `tests/test_nse_integration.py`, as root,
via `sudo -E env "PATH=$PATH" uv run --frozen pytest ... --no-cov`:
`TestOpenvpnDetectNseUdp`, the `-sU` NSE path, is gated on `os.geteuid() == 0`
and is skipped everywhere else, so this is the only job that actually exercises
it. `sudo` resets `PATH`, dropping the `uv` that `setup-uv` had just installed,
hence the explicit re-injection rather than relying on `sudo`'s own (`uv`-less)
`secure_path`. Coverage is disabled for this job specifically — the 95% floor
in `pyproject.toml` applies to the whole suite and a single-module run can't
meet it — without touching the floor itself; the rest of the suite is already
covered, with coverage, by `test` and `test-legacy`. The job's load-bearing
step is not the pytest run itself but a `--junitxml` parse afterward: a pytest
skip is not a failure, so "N passed, M skipped" would exit 0 even if sudo, the
`PATH` re-injection, or `uv` resolution silently broke and the root-gated
class never ran at all — that is exactly the failure this job exists to catch,
and a plain pass/fail summary can't distinguish it from `tests/conftest.py`'s
unrelated, legitimate port-conflict skip. The parse asserts *positively*: that
`TestOpenvpnDetectNseUdp` produced at least one result in the junit report and
that none of its results were skipped, for any reason. Because it doesn't key
on the skip *text*, it survives that reason string being reworded, the class
being renamed, or the whole module skipping itself (e.g. `nmap` missing) —
all of which would defeat a check that only searched for one specific skip
message.

Three more jobs guard style, security, and the workflow directory itself.
`lint` runs `ruff check spoonmap.py tests/` against a narrow `E4`/`E7`/`E9`/`F`
ruleset with ruff exact-pinned in the `dev` group (a linter that grows an
opinion should not fail an unrelated PR). `bandit` runs SAST against the
committed `.bandit-baseline.json` via `uv run --frozen bandit`; `bandit[toml]`
is exact-pinned in the `dev` group too (same reasoning as ruff — a bare `uvx
--from` pin on bandit itself let its transitive dependencies float). `ruff
format` is deliberately **not** adopted — reformatting the module and the
11k-line test file would bury every future diff, and `E501` alone flags 288
existing lines. The bandit baseline holds 32 reviewed findings (list-form
`subprocess` calls, `xml.etree` parsing of masscan/nmap output we invoked
ourselves), so only a *new* finding fails; regenerate it deliberately and
justify additions in the commit message rather than adding inline `# nosec`
suppressions. `workflow-lint` runs `actionlint` (YAML/expression errors) and
`zizmor` (Actions-specific security auditing — unpinned actions, script
injection, credential persistence) against the whole `.github/workflows/`
directory, not just `ci.yml`, so a future workflow file is covered without an
edit here (`.github/dependabot.yml` is deliberately excluded from both — it
isn't a workflow file and neither tool parses it). This job installs `uv` via
`setup-uv`, same as every other job, since it invokes both tools through
`uvx` and `uv` is not preinstalled on the runner — its absence here once meant
both `uvx` steps failed at "command not found" on every real run while
passing in local verification, where `uv` was already on the developer's PATH.

A `build` job (added for wheel/sdist packaging; see the job itself and
`pyproject.toml`'s `[tool.hatch.build.targets.*]`) builds both artifacts and
asserts on their actual contents rather than trusting the config says what it
means, including that the wheel's `spoonmap_nse/` and the sdist's `nse/` each
match the local `nse/` directory by exact set, not mere inclusion — `nse/` is
directory-wide in both `include` (sdist) and `force-include` (wheel), so
without set equality an operator's own script left in that directory
mid-engagement would ship to every install silently. The sdist assertion also
checks a positive floor — every entry `pyproject.toml`'s own `include` list
names must actually be present — since a gutted `include` list previously
still passed as "clean" against the banned-substrings check alone.

Every job declares `timeout-minutes`, generous but bounded, instead of relying
on the 6-hour default: this suite exercises `work_queue.join()`,
`threading.Event` polling, and `KeyboardInterrupt` handling, and a past bug in
that area failed as a hang rather than a clean failure. `.github/dependabot.yml`
proposes weekly bumps for the SHA-pinned actions and for the `uv`-managed `dev`
group, since a hand-maintained pin only gets a security fix if something
proposes the bump. Actions are pinned to commit SHAs with the tag in a trailing
comment, and every checkout sets `persist-credentials: false`. The
`concurrency` group's `cancel-in-progress` is scoped to `pull_request` events
only, so a fast follow-up merge to `main` can no longer cancel the previous
commit's in-progress run and erase its green check.

Pass `--cleanup [dir]` to remove prior scan output non-interactively (reads `output_path` from `config.json` if no directory is given).

## Operator Path Resolution

Every operator-facing path — `config.json`, `exclusions.txt`, the default
output location, relative `target_file`/`output_path`/`exclusions_file`
values read out of `config.json`, and `--cleanup`'s search for a config to
read `output_path` from — resolves against the current working directory the
command was run from, via `_operator_dir()` (a thin wrapper around
`os.getcwd()`, kept as its own module-level helper so it is testable outside
`main()`'s `# pragma: no cover` region). An operator's config and scan output
belong in the directory they ran the engagement from, not wherever the
program happens to be installed — those are frequently different places, and
this is true independent of how (or whether) the tool is installed.

This is a behaviour change from resolving against `os.path.dirname(os.path.realpath(__file__))`:
invoking by absolute path from another directory (`cd /tmp &&
/opt/spoonmap/spoonmap.py`) previously read `/opt/spoonmap/config.json` and
wrote output there; it now resolves against `/tmp`. The documented invocation
— running `./spoonmap.py` or `uv run spoonmap.py` from inside the checkout —
is unaffected, since CWD and checkout are the same directory there.

This is a different anchor from `_DIR`/`_NSE_DIR` (`spoonmap.py:2459`), which
stay `__file__`-relative on purpose: the bundled NSE scripts under `nse/` are
program data that ships with SpooNMAP itself, not operator data, and must
resolve identically regardless of the caller's CWD. `_operator_dir()` and
`_DIR` are deliberately two separate anchors — do not collapse them into one.

The wheel built by `pyproject.toml`'s hatch config is a supported consumption
path (`uv tool install git+https://github.com/trustedsec/spoonmap`; see
README.md for the end-user walkthrough), so a change here must keep
`config.json.sample` and every bundled `nse/` script landing in the wheel —
the `build` CI job asserts this.

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
- **Interrupt handling**: masscan raises `KeyboardInterrupt` and re-raises after cleanup; nmap uses `threading.Event` polling so all worker threads can be signaled cleanly. Every process handle a `except KeyboardInterrupt` handler dereferences (`proc`, `masscan_process`) is pre-initialised to `None` before its `try`, alongside `progress_thread`, and the handler guards on it: Ctrl-C during a scan is routine, and if SIGINT lands inside `Popen()` itself (the fork/exec window) the name was never bound, so `proc.kill()` replaced the interrupt with an `UnboundLocalError` while `finally: restore_terminal_state(...)` still had to run. In `nmap_worker()`, `work_queue.task_done()` fires **exactly once per successful `get()`**, tracked by a `task_done_called` flag: the inner `finally` and the outer `except Exception` both called it, so an exception raised *inside* one of the inner handlers over-decremented the queue's unfinished counter and made `work_queue.join()` return as though every port had been scanned — a silently incomplete scan instead of a visible hang.
- **Resume behavior**: every resume gate goes through `_resume_cache_usable(output_file, baseline_mtime, description, *, target_file, exclusions_file, is_xml=True)`, which requires the cached output to be present, no older than its baseline, to contain usable results, **and** to carry a coverage record spanning this run's targets and exclusions (see **Resume target coverage** below) — XML must parse via `_parse_result_xml()`, plain-text host lists must be non-empty. A zero-length or truncated file (killed masscan/nmap) is rejected with a `re-running <description>: cached result was empty or unreadable` line instead of being cached as complete forever. mtimes are read through `_safe_mtime()` so a file removed between the `exists()` and `getmtime()` calls reads as stale rather than raising. `nmap_scan()` applies this to both `nmap_results/portN.xml` (banner pass) and `nse_results/portN.xml` (script pass) with no mtime baseline — those two rely on the coverage record instead, since their `-iL` grows across runs rather than being rewritten. Because masscan writes **nothing** to `-oX` when a batch finds no open ports, `_run_masscan_batch()` stamps `_EMPTY_RESULT_XML` (`<nmaprun></nmaprun>`) over a zero-length output via `_atomic_write()` **on its success path only** — a non-zero exit or a `KeyboardInterrupt` never gets a placeholder. That keeps "completed, found nothing" (common on internal segmentation tests, where most batches are empty) distinguishable from "killed before writing", so the former is skipped on resume and only the latter is redone. The placeholder parses to zero `<host>` elements, so `_run_masscan_batch()` still returns `{}` and `_aggregate_result_dir()` is unaffected. nmap needs no equivalent: it always writes a complete XML document on a normal exit, so a zero-length or unterminated nmap file genuinely means it was killed. It does, however, need the converse: a non-zero nmap exit can leave a *valid* XML holding zero or partial hosts (whole-target resolution failure, missing privileges), which the gate would accept forever, so `nmap_worker()`'s failure path calls `_quarantine_failed_output()` to rename it to `portN.xml.failed` — the gate then rejects it and the port is re-scanned, while the data stays on disk for inspection. The `.xml.failed` suffix is invisible to every consumer, all of which require an `.xml` extension or an exact filename. Discovery resume is additionally mtime-gated: `preprocess_targets()` writes `discovery/resolved_targets.txt` via `_write_if_changed()` (rewritten only when the resolved target set changes), and `_host_discovery()`, `mass_scan()`, `_nmap_port_discovery()`, and `_nmap_udp_discovery()` reuse cached output only when it is at least as new as `resolved_targets.txt`. So an unchanged `ranges.txt` skips discovery on resume; a changed one bumps the mtime and forces re-discovery of the affected phases. The rate-calibration probe inside `mass_scan()` is deliberately **not** resume-gated — it is cheap and its whole purpose is to measure *this* run's packet loss — so it re-runs every time; its per-port results are therefore **unioned** with the existing `live_hosts/portN.txt` rather than overwriting it, exactly as the batch phase does. Overwriting was a silent data-loss bug: the probe runs against the narrower `probe_target` and at a rate whose loss varies run to run, so a re-probe routinely finds fewer hosts than the cached file, and the difference vanished from `live_hosts/portN.txt`, `all_live_hosts.txt`, and the nmap banner phase's input. Those retained cached hosts are also folded into `live_hosts_combined.txt`, the `-iL` target for the remaining port batches, so a host that is *kept* is also *scanned* for the remaining ports — retaining it without scanning it produced output asserting coverage the scan never performed, reachable whenever `host_discovery` is False and there is no `discovery_file` to widen the combined target. The fold is filtered through `_parse_target_ranges()`/`_ip_in_ranges()` against the current `target_file` and is never applied blind: nothing prunes `live_hosts/` when `ranges.txt` narrows (a `--resume` run deletes no prior output, and the mtime gate only forces phases to re-run), so a cached file can still hold hosts from a previous, wider engagement scope. An out-of-scope cached host keeps its place in `live_hosts/portN.txt` but never becomes a masscan target — scanning outside the current authorisation is worse than under-scanning. An unparseable target file yields no ranges and folds nothing. Because those out-of-scope hosts *are* still retained, `_report_out_of_scope_retained()` discloses them: at the end of `mass_scan()` (and on the Full-scan resume path, which reads its results straight back off disk) it warns with a count and a few example IPs, stating that they are present in the output but outside the current scope and were not scanned this run. Disclosure, not deletion — `all_live_hosts.txt` and `spoonmap_output.*` feed engagement deliverables, so an unannounced out-of-scope host is one an operator may report on or pivot to believing it was authorised, but pruning it would destroy a completed scan's results. The warning never prompts, exits, rewrites `live_hosts/`, or filters what gets written. Deletion is exclusively operator-initiated: either by selecting `[d]elete` when re-running with prior results present, or by running `--cleanup`.
- **Durable state writes**: every file a later phase depends on is written through `_atomic_write()` (temp file in the same directory + `os.replace`), so a partial write can never be read as complete. That includes `discovery/live_hosts_combined.txt`, which is the masscan `-iL` target for every remaining port batch: an `OSError` there is caught and the remaining batches fall back to the full `target_file` with a warning, because raising would unwind `mass_scan()` and `main()` and lose the whole run's aggregation, while a silent truncation would narrow the target set and under-scan.
- **masscan target selection**: no masscan invocation inside `mass_scan()` targets `target_file` unconditionally. The rate-calibration probe and the single `1-65535` **Full** sweep both target `discovered_target` (the `discovery_file` when host discovery produced one, else the full `target_file`); the port batches target the usually-wider `batch_target` (`live_hosts_combined.txt`, discovery ∪ probe hits ∪ folded in-scope cached hosts), falling back to `target_file` only when there is nothing to narrow to or its atomic write failed. The Full sweep was the exception and it was a bug: 65535 ports against every address in the range rather than the discovered live hosts is the same scan multiplied by the range's dead space, and because `full_scan_rate` is capped (1000 pps Internal / 10000 External) the operator cannot rate their way out of it. On a /16 narrowed to a few hundred live hosts that is the difference between hours and weeks, and the only visible symptom was masscan's own `Scanning <range size> hosts` line and a wildly long ETA — `main()`'s work-unit threshold decision and `_calc_scan_wait()` both already used the *discovered* count, so every SpooNMAP-printed number looked right. Unlike the cached-host fold into `live_hosts_combined.txt`, the Full sweep needs no `_ip_in_ranges()` scope filter: `discovery_file` is mtime-gated against `resolved_targets.txt` both here and in `_host_discovery()`'s own resume gate, so a narrowed scope invalidates the discovery cache rather than leaving it to carry a host from a wider one. Narrowing the sweep also made its `live_hosts/portN.txt` write a **union** rather than an overwrite, mirroring the probe and batch phases: the sweep can now legitimately find fewer hosts on a port than an earlier, wider run recorded, and overwriting deleted the difference out of `live_hosts/`, `all_live_hosts.txt`, the nmap banner input, and `spoonmap_output.*` — reachable without `--resume` via two Full runs into one `output_path` answering `[k]eep`. Because it therefore retains cached hosts, this path calls `_report_out_of_scope_retained()` too, on the same disclosure-not-deletion grounds as the resume path. Because the sweep's target is now run-dependent rather than a static file, its resume gate is target-coverage-checked as well — see **Resume target coverage** below.
- **Resume target coverage**: an mtime baseline records *when* a file changed, never *what the cached scan covered*, so it cannot catch a target set that changes without its baseline file being rewritten. Every phase therefore records what it covered in a single JSON sidecar beside its output — `<output>.coverage`, holding the normalised target and exclusion line sets, written by `_stamp_target_coverage()` — and `_resume_cache_usable(output_file, baseline_mtime, description, *, target_file, exclusions_file, is_xml=True)` rejects the cache unless that record spans what this run would scan. The two coverage inputs are **keyword-only with no default**: omitting one is a `TypeError`, not a silently skipped check (an earlier optional-keyword form had already cost it at two of three sites that left it out), and the call sites read as `exclusions_file=None` rather than a bare trailing `None`. All seven phases are covered — `_host_discovery()`, the Full sweep, the port batches, `_nmap_port_discovery()`, `_nmap_udp_discovery()`, and `nmap_scan()`'s banner and NSE passes. `target_file` is never None (every phase scans something); `exclusions_file` is None only for the two nmap passes, which add no `--excludefile` at all. Three under-scans this closes, each of which reported a narrow scan as a complete one: (1) toggling `host_discovery` off on a `--resume` run widens the target from the discovery file to the whole range while nothing rewrites `resolved_targets.txt`; (2) the port batches, with **no config change** — `live_hosts_combined.txt` is rebuilt every run from a probe that is deliberately not resume-gated, so a host run 2's probe found but run 1's missed reached `live_hosts/` and `all_live_hosts.txt` yet was never scanned for the already-cached batches' ports; (3) the banner and NSE passes, whose `-iL` is `live_hosts/portNN.txt` — written as a union by the probe, the batch phase and the Full sweep, so it grows across runs and a cached `portN.xml` that merely parses is no evidence it covered the hosts now in it. That third one is why the masscan-side fix alone was not enough: masscan decides what reaches `live_hosts/`, but a banner scan is how the tool is normally run, so the newly-masscanned host still got no service data. Those two passes record against the IP list even though `nmap_worker()` may hand nmap the `portNN_hostnames.txt` variant — that file is a pure derivation of the IP list, regenerated every run, and does not exist yet when the gate runs.
- **The two halves are compared in opposite directions**, because a phase's effective coverage is `targets − exclusions`. Targets: accept when `current ⊆ stamped`. Equality was the first shape and it was wrong — the batch phase's target moves in *both* directions between runs, since the iterative single-port probe stops at the first port that finds hosts, so which cached ports get folded in varies with probe luck; under equality an ordinary difference in packet loss re-scanned every completed batch against a *narrower* target than the cache it discarded, i.e. `--resume` stopped resuming. Exclusions: accept when `current ⊇ stamped`. Excluding *more* now means a strictly smaller scan set the cache still covers, while excluding *fewer* (narrowing `exclusions.txt` because a host was cleared for testing) brings something previously skipped into scope with nothing else on disk changing — `--excludefile` never enters the `-iL` file, so without its own record that edit was invisible to every gate. Both comparisons are over normalised **lines**, not addresses: `10.0.0.0/24` and an explicit list of its hosts differ, and un-excluding an entry the targets never covered still re-scans. Deliberate — line comparison can over-scan but never over-accept, whereas address arithmetic would import the whole parsing surface into a resume gate. Rejections name the offending entries.
- **When the record is written and dropped**: on **success paths only**, exactly as `_EMPTY_RESULT_XML` is — a record on a killed scan would assert coverage that never happened. A `KeyboardInterrupt`, a missing binary and a non-zero exit all leave none; `_nmap_udp_discovery()` needs an explicit `proc.returncode == 0` guard for the last of those, because unlike `_nmap_port_discovery()` it does not treat a non-zero exit as fatal and a failing nmap can still leave parseable partial XML. Each phase also calls `_discard_coverage_record()` **before it scans**, not only on failure: a run killed outright never reaches the stamp, and the previous run's record would otherwise sit beside output that run had already replaced. The hazard is specifically a record that covered *more* than the output now on disk, since a subset test accepts it — a narrower leftover can only cause a redundant re-scan. Both halves live in one file written by a single `_atomic_write` for the same reason: as two sidecars written in sequence, a `KeyboardInterrupt` between them (a `BaseException`, so `except Exception` missed it) left a fresh target list beside a stale exclusion list and the gate accepted the pair as an exclusion-free scan. Neither an unreadable input nor a failed write raises on its own account — the scan already succeeded, so unwinding would discard real results — but every failure path, including an interrupt, deletes the record first. A cache whose record is absent or malformed is rejected, so output from before this change re-scans once on the first resume after upgrading; that is the deliberate direction, since a redundant re-scan is visible and an under-scan is not. The `.coverage` suffix is invisible to every result consumer: `masscan_results/` is aggregated by listing the directory, and `_parse_result_xml()` drops anything not ending in `.xml`, the same guard that hides `portN.xml.failed`. `_delete_previous_results()` removes it with the directory, so `--cleanup` and `[d]elete` need no special handling.
- **config.json validation**: `_load_config()` refuses to start a scan it cannot run correctly. Missing required keys are reported all at once and exit. `target_scan` goes through `_config_target_scan()`, which accepts any case/whitespace spelling of `Internal`/`External` (normalising to the exact literal the ~25 comparison sites use) and exits on anything else — an unvalidated `"internal"` matched neither literal, so the scan ran and looked completely normal while every `target_scan == 'Internal'` gated check was silently skipped. Every numeric goes through `_config_int(key, value, default, minimum=1)`, mirroring `_prompt_int`'s floor: a non-numeric or null value warns and takes the default, and a value below `minimum` is clamped with a warning. `max_rate` is included (defaulting to the interactive prompt's 20000 external / 2000 internal) and only then re-`str()`-ed for Popen.
- **Hostname support**: hostnames in the target file are resolved once at startup; nmap receives the original hostname (for SNI/vhost), masscan receives the resolved IP
- **IPv4-only, enforced at the edges**: the tool scans IPv4 exclusively (masscan/nmap invocations, target expansion, and address sorting all assume it). IPv6 is rejected rather than half-supported, in two places. (1) `_build_discovery_target_file()`'s `_parse_ranges()` skips any entry `ipaddress.ip_network()` resolves to a non-v4 network and prints the offending file, line number, and content — previously the v6 bounds were stored silently and only surfaced hundreds of lines later as `AddressValueError: ... (>= 2**32)` from `summarize_address_range()`, and only when an exclusions file happened to be configured. (2) The masscan/discovery XML parsers (`_parse_masscan_ping_xml()`, `_parse_nmap_sn_xml()`, `_run_masscan_batch()`) select `address[@addrtype='ipv4']` instead of the first `<address>` child, matching what the nmap-side parsers already did, so a dual-stacked host's IPv6 or MAC string can't enter `live_ips`/`port_ips` and become a masscan `-iL` target. Address sorting goes through `_ip_sort_key()`, which orders valid IPv4 numerically and sorts anything unparseable last instead of raising — the three former inline `tuple(int(o) for o in x.split('.'))` keys ran *after* a completed sweep, so one odd entry discarded the whole thing.
- **XML result parsing is per-element defensive**: every `etree.parse()` site guards the *walk* as well as the parse. Attributes are read with `.attrib.get(...)` and the element is skipped when the identifier is missing — never a bare `attrib['addr']` or `findall('address')[0]`, both of which raise `KeyError`/`IndexError` that `except etree.ParseError` does not catch. Those exceptions escaped the guard and discarded the results for *every other host* in the file (or, in `_host_elem_to_dict()`, lost `spoonmap_output.xml`/`.json` for the whole run) over one truncated element. `<script>` elements with no `id=` are filtered out of the comprehensions for the same reason. Where a fallback to the first `<address>` child is wanted after `address[@addrtype='ipv4']` misses (`generate_findings()`, `_scan_extra_sql_ports()`), it is a `None`-checked `find('address')`.
- **Firewall state table safety**: internal discovery caps masscan at `INTERNAL_DISCOVERY_MAX_RATE = 1000 pps`; at that rate with a 60 s half-open timeout, concurrent state entries peak at ~60 K regardless of target range size; for ranges above `INTERNAL_DISCOVERY_STATE_CEILING = 262_144` hosts the port list is trimmed from 10 to 5 to keep total packet volume bounded. Separately and for the same reason, `mass_scan()` clamps a **Full** scan to `full_scan_rate` — 10000 pps External, 1000 pps Internal — since a single 1-65535 invocation fans out every port across every target at once. This cap applies *only* to `scan_type == 'Full'`; category and custom batched scans scan a handful of ports per invocation and always use the operator's full `max_rate`. The clamp prints a notice when it actually lowers the rate, because `main()`'s run summary echoes the *requested* `max_rate`: clamping silently made the summary contradict what masscan was told to do, and read as the operator's `--max-rate` having been ignored outright.
- **Honeypot/tarpit detection**: `mass_scan()` flags hosts open on ≥`HONEYPOT_OPEN_PORT_FRACTION` (90%) of scanned TCP ports (min sample `HONEYPOT_MIN_PORTS_SCANNED = 10`) as likely tarpits (LaBrea, portspoof) via `_flag_suspected_tarpits()`/`_report_suspected_tarpits()`, writing `discovery/suspected_tarpits.txt`. Separately, `_count_unmatched_service_ports()` reads `nmap_results/*.xml` and counts open ports whose `-sV` probe captured a `servicefp` (no signature match); `≥HONEYPOT_MIN_UNMATCHED_PORTS = 3` such ports on one host is consistent with decoys (e.g. Artillery) that return random data on full connect. Both signals surface as a single "Likely Honeypot / Decoy Host" MEDIUM finding in `generate_findings()`. `_flag_suspected_tarpits()` counts TCP ports only, skipping any `port_key` that starts with `U:`, so every loop that reconstructs a port key from a `live_hosts/portNN.txt` filename must run the stem through `_fname_port()` (`'U_53'` → `'U:53'`) — the raw stem was counted as TCP, skewing the open-port fraction, and printed as `Hosts Found on Port U_53`.
