"""Tests for spoonmap.py"""
import ast
import datetime
import inspect
import io
import json
import os
import readline
import subprocess
import textwrap
import threading
from pathlib import Path
from queue import Empty, Queue
from unittest.mock import MagicMock, patch

import pytest
import xml.etree.ElementTree as etree

import spoonmap
from spoonmap import (
    AZURE_SQL_DOMAIN_SUFFIXES,
    DISCOVERY_MASSCAN_PORTS_EXTERNAL,
    DISCOVERY_MASSCAN_PORTS_INTERNAL,
    DISCOVERY_TCP_PORTS_INTERNAL,
    EXTERNAL_PORT_SCRIPTS,
    EXTERNAL_SENSITIVE_PORTS,
    HONEYPOT_MIN_PORTS_SCANNED,
    HONEYPOT_OPEN_PORT_FRACTION,
    HOST_DISCOVERY_NMAP_THRESHOLD,
    INTERNAL_DISCOVERY_MAX_RATE,
    INTERNAL_DISCOVERY_STATE_CEILING,
    SLOW_PORTS,
    INTERNAL_PORT_SCRIPTS,
    _build_discovery_target_file,
    _build_interactive_config,
    _build_nmap_cmd,
    _build_repro_cmd,
    _classify_sql,
    _config_int,
    _count_hosts_in_file,
    _count_unmatched_service_ports,
    _external_exposure_scripts,
    _format_eta,
    _raise_fd_limit,
    _sql_version_year,
    _summarize_vulns,
    _handle_previous_results,
    _prior_default,
    _prompt_int,
    _prompt_yes_no,
    _CONFIG_DOCS,
    _CONFIG_FIELD_ORDER,
    _CONFIG_GENERATED_KEY,
    _host_discovery,
    _atomic_write,
    _cli_target_from_argv,
    _parse_range_line,
    _parse_target_arg,
    _parse_target_ranges,
    _resolve_cli_target,
    _write_cli_target_file,
    _combine_live_hosts,
    _load_config,
    _read_config_file,
    _aggregate_gnmap,
    _gnmap_path,
    _gnmap_port_sort_key,
    _parse_gnmap_line,
    _write_gnmap_result,
    _write_artifact,
    _write_combined_results,
    _write_if_changed,
    _write_interactive_config,
    _discover_external_masscan,
    _discover_internal_masscan,
    _external_host_discovery,
    _flag_suspected_tarpits,
    _nmap_host_discovery,
    _report_suspected_tarpits,
    _stream_masscan_progress,
    preprocess_targets,
    _discovery_wait,
    _internal_host_discovery,
    _ip_sort_key,
    _merge_host_xml,
    _filter_udp_live_hosts,
    _nmap_port_discovery,
    _nmap_udp_discovery,
    _parse_masscan_ping_xml,
    _parse_nmap_sn_xml,
    _parse_result_xml,
    _operator_dir,
    _quarantine_failed_output,
    _resolve_nse_dir,
    _aggregate_result_dir,
    _path_completion,
    _run_masscan_batch,
    _resume_cache_usable,
    _safe_mtime,
    _safe_size,
    _scan_extra_sql_ports,
    _validate_snmp_any_community,
    _SMB_COUPLED_PORTS,
    SERVICE_CATEGORIES,
    _calc_scan_wait,
    _cleanup_cmd,
    _delete_previous_results,
    _get_scripts_for_port,
    _host_elem_to_dict,
    _previous_results_exist,
    _select_probe_ports,
    _write_findings_json,
    _write_findings_md,
    _write_findings_txt,
    create_hostname_target_file,
    generate_findings,
    is_hostname,
    lineCount,
    mass_scan,
    nmap_scan,
    nmap_worker,
    resolve_hostname,
    restore_terminal_state,
    save_terminal_state,
    verify_python_version,
)


def _write_target_stamp(output_file, target_file):
    """Write the resume-gate target sidecar for *output_file*.

    Delegates to production rather than recomputing the format: this is used by
    fixtures across the file whose subject is resume behaviour, not the stamp
    format, and a second implementation here turned an intentional format change
    into a dozen failures with an opaque "cache was rejected" symptom.  The
    format and its normalisation are pinned directly by TestTargetEntries.
    """
    spoonmap._stamp_target_coverage(str(output_file), str(target_file), None)


# ── small platform/utility helpers ─────────────────────────────────────────────

class TestVerifyPythonVersion:
    def test_python2_exits(self):
        with patch('sys.version_info', (2, 7, 18, 'final', 0)):
            with pytest.raises(SystemExit):
                verify_python_version()

    def test_python_3_5_exits(self):
        with patch('sys.version_info', (3, 5, 0, 'final', 0)):
            with pytest.raises(SystemExit):
                verify_python_version()

    def test_python_3_6_plus_is_ok(self):
        with patch('sys.version_info', (3, 10, 0, 'final', 0)):
            verify_python_version()  # must not raise


class TestToolVersion:
    """_tool_version() reports the installed version, or says it cannot."""

    def test_reports_the_installed_distribution_version(self):
        with patch('spoonmap.metadata.version', return_value='1.2.3'):
            assert spoonmap._tool_version() == '1.2.3'

    def test_running_from_a_checkout_is_not_a_version(self):
        """No distribution metadata exists when spoonmap.py is run as a plain
        script from a clone, which is the documented invocation. That must read
        as 'unknown', never as a version number that could be compared."""
        with patch('spoonmap.metadata.version',
                   side_effect=spoonmap.metadata.PackageNotFoundError):
            assert spoonmap._tool_version() == spoonmap._UNKNOWN_VERSION

    def test_the_unknown_sentinel_is_not_mistakable_for_a_version(self):
        assert not spoonmap._UNKNOWN_VERSION[0].isdigit()


class TestRaiseFdLimit:
    def test_sets_soft_limit_to_hard_when_below_65535(self):
        with patch('spoonmap.resource.getrlimit', return_value=(1024, 4096)), \
             patch('spoonmap.resource.setrlimit') as mock_set:
            _raise_fd_limit()
        mock_set.assert_called_once_with(spoonmap.resource.RLIMIT_NOFILE, (4096, 4096))

    def test_caps_soft_limit_at_65535_when_hard_is_higher(self):
        with patch('spoonmap.resource.getrlimit', return_value=(1024, 1048576)), \
             patch('spoonmap.resource.setrlimit') as mock_set:
            _raise_fd_limit()
        mock_set.assert_called_once_with(spoonmap.resource.RLIMIT_NOFILE, (65535, 1048576))

    def test_setrlimit_failure_is_swallowed(self):
        with patch('spoonmap.resource.getrlimit', return_value=(1024, 4096)), \
             patch('spoonmap.resource.setrlimit', side_effect=ValueError):
            _raise_fd_limit()  # must not raise


class TestSaveRestoreTerminalState:
    def test_save_returns_attrs_on_success(self):
        sentinel = ['sentinel-attrs']
        with patch('spoonmap.termios.tcgetattr', return_value=sentinel):
            assert save_terminal_state() == sentinel

    def test_save_returns_none_on_error(self):
        with patch('spoonmap.termios.tcgetattr', side_effect=OSError):
            assert save_terminal_state() is None

    def test_restore_applies_saved_state_and_resets_tty(self):
        with patch('spoonmap.termios.tcsetattr') as mock_set, \
             patch('spoonmap.subprocess.run') as mock_run:
            restore_terminal_state(['saved'])
        mock_set.assert_called_once()
        mock_run.assert_called_once()

    def test_restore_with_none_state_still_resets_tty(self):
        with patch('spoonmap.termios.tcsetattr') as mock_set, \
             patch('spoonmap.subprocess.run') as mock_run:
            restore_terminal_state(None)
        mock_set.assert_not_called()
        mock_run.assert_called_once()

    def test_restore_swallows_tcsetattr_error(self):
        with patch('spoonmap.termios.tcsetattr', side_effect=OSError), \
             patch('spoonmap.subprocess.run'):
            restore_terminal_state(['saved'])  # must not raise

    def test_restore_swallows_subprocess_error(self):
        with patch('spoonmap.termios.tcsetattr'), \
             patch('spoonmap.subprocess.run', side_effect=OSError):
            restore_terminal_state(['saved'])  # must not raise


class TestFormatEta:
    def test_singular_second(self):
        assert _format_eta(1) == '~1 second'

    def test_plural_seconds(self):
        assert _format_eta(45) == '~45 seconds'

    def test_singular_minute(self):
        assert _format_eta(60) == '~1 minute'

    def test_plural_minutes(self):
        assert _format_eta(300) == '~5 minutes'

    def test_exact_singular_hour(self):
        assert _format_eta(3600) == '~1 hour'

    def test_exact_plural_hours(self):
        assert _format_eta(7200) == '~2 hours'

    def test_hour_and_minute_singular(self):
        assert _format_eta(3660) == '~1 hour 1 minute'

    def test_hours_and_minutes_plural(self):
        assert _format_eta(7500) == '~2 hours 5 minutes'


class TestResolveHostname:
    def test_successful_resolution(self):
        with patch('spoonmap.socket.gethostbyname', return_value='10.0.0.5'):
            assert resolve_hostname('example.com') == '10.0.0.5'

    def test_failed_resolution_returns_none_and_warns(self, capsys):
        with patch('spoonmap.socket.gethostbyname', side_effect=OSError('nope')):
            assert resolve_hostname('bad.example.com') is None
        assert 'Could not resolve hostname' in capsys.readouterr().out


class TestCountHostsInFile:
    def test_counts_bare_ips_and_cidrs(self, tmp_path):
        f = tmp_path / 'targets.txt'
        f.write_text('10.0.0.1\n10.0.0.0/30\n')
        assert _count_hosts_in_file(str(f)) == 1 + 4

    def test_blank_and_comment_lines_skipped(self, tmp_path):
        f = tmp_path / 'targets.txt'
        f.write_text('\n# a comment\n10.0.0.1\n')
        assert _count_hosts_in_file(str(f)) == 1

    def test_hostname_counts_as_one(self, tmp_path):
        f = tmp_path / 'targets.txt'
        f.write_text('example.internal\n10.0.0.1\n')
        assert _count_hosts_in_file(str(f)) == 2

    def test_missing_file_returns_none(self, tmp_path):
        assert _count_hosts_in_file(str(tmp_path / 'nonexistent.txt')) is None

    def test_ipv6_entries_count_as_zero(self, tmp_path):
        """ipaddress parses IPv6 happily, so ``::/0`` used to contribute 2**128.
        That count drives the INTERNAL_DISCOVERY_STATE_CEILING port-list trim and
        _calc_scan_wait(), so one stray v6 line silently halved an all-IPv4
        scan's port list.  SpooNMAP is IPv4-only; _parse_ranges() already skips
        these, and this must agree."""
        f = tmp_path / 'targets.txt'
        f.write_text('10.0.0.1\n::/0\n2001:db8::1\nfe80::/64\n')
        assert _count_hosts_in_file(str(f)) == 1

    def test_ipv6_only_file_counts_zero_not_a_huge_number(self, tmp_path):
        f = tmp_path / 'targets.txt'
        f.write_text('2001:db8::/32\n')
        assert _count_hosts_in_file(str(f)) == 0


class TestBuildDiscoveryTargetFile:
    """_build_discovery_target_file() pre-subtracts exclusions from targets
    before masscan sees them, so masscan's randomization space stays small."""

    def test_no_exclusions_file_returns_target_unchanged(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        result_file, count = _build_discovery_target_file(str(target), None, str(tmp_path))
        assert result_file == str(target)
        assert count == 256

    def test_exclusions_file_missing_on_disk_returns_target_unchanged(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        missing_excl = str(tmp_path / 'nonexistent_excl.txt')
        result_file, count = _build_discovery_target_file(str(target), missing_excl, str(tmp_path))
        assert result_file == str(target)
        assert count == 256

    def test_unparseable_target_file_returns_zero_count(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('not a valid range\nnor is this\n')
        result_file, count = _build_discovery_target_file(str(target), None, str(tmp_path))
        assert result_file == str(target)
        assert count == 0

    def test_unparseable_exclusions_file_returns_target_unchanged(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('garbage, not a range\n')
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert result_file == str(target)
        assert count == 256

    def test_exclusions_fully_cover_targets_writes_empty_file(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/30\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.0/24\n')
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 0
        assert result_file == str(tmp_path / 'discovery_targets_filtered.txt')
        assert Path(result_file).read_text() == ''

    def test_partial_exclusion_writes_remaining_ranges(self, tmp_path):
        # 10.0.0.0/24 minus 10.0.0.0/25 leaves 10.0.0.128/25
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.0/25\n')
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 128
        content = Path(result_file).read_text()
        assert '10.0.0.128/25' in content

    def test_inline_comments_stripped(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24 # office network\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.128/25 # excluded segment\n')
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 128
        assert '10.0.0.0/25' in Path(result_file).read_text()

    def test_range_notation_parsed(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1-10.0.0.10\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.1-10.0.0.5\n')
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 5  # .6 through .10

    def test_netmask_notation_parsed(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0 255.255.255.0\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.0 255.255.255.128\n')
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 128

    def test_reversed_range_ignored(self, tmp_path):
        """start > end in range notation is silently dropped, not swapped."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.10-10.0.0.1\n10.0.0.1\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.99\n')  # anything, just to exercise the subtract path
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 1  # only the bare 10.0.0.1 line counted

    def test_no_remaining_exclusions_after_merge_returns_unchanged(self, tmp_path):
        """merge()/subtract() consume adjacent/overlapping target ranges correctly."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/25\n10.0.0.128/25\n')  # adjacent -> merges to /24
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.1.0/24\n')  # doesn't overlap target at all
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 256

    def test_comment_only_line_skipped(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('# just a comment, no content\n10.0.0.1\n')
        result_file, count = _build_discovery_target_file(str(target), None, str(tmp_path))
        assert count == 1

    def test_invalid_range_notation_ignored(self, tmp_path):
        """A dash-containing line that isn't a valid A.B.C.D-E.F.G.H range is skipped."""
        target = tmp_path / 'targets.txt'
        target.write_text('not-a-range\n10.0.0.1\n')
        result_file, count = _build_discovery_target_file(str(target), None, str(tmp_path))
        assert count == 1

    def test_invalid_netmask_notation_ignored(self, tmp_path):
        """A two-token line with an invalid mask is skipped."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0 999.999.999.999\n10.0.0.1\n')
        result_file, count = _build_discovery_target_file(str(target), None, str(tmp_path))
        assert count == 1

    def test_unreadable_target_file_returns_zero_count(self, tmp_path):
        """A directory in place of a file raises OSError on open(), swallowed
        by _parse_ranges — treated the same as an unparseable file."""
        target_dir = tmp_path / 'a_directory'
        target_dir.mkdir()
        result_file, count = _build_discovery_target_file(str(target_dir), None, str(tmp_path))
        assert count == 0

    def test_exclusion_entirely_before_and_between_targets_advances_cursor(self, tmp_path):
        """Exclusion ranges that end before the current target's start advance
        the shared exclusion cursor without subtracting anything from either
        target range."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n10.0.2.0/24\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('9.0.0.0/24\n10.0.1.0/24\n')  # before, then in the gap
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 512  # both target ranges fully preserved

    # ── IPv6 rejection (SpooNMAP is IPv4-only) ───────────────────────────────

    def test_ipv6_cidr_in_target_file_named_and_skipped(self, tmp_path, capsys):
        """ipaddress.ip_network() parses IPv6 happily, so the bad line used to be
        stored silently and only surfaced later as an AddressValueError."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n2001:db8::/32\n')
        result_file, count = _build_discovery_target_file(str(target), None, str(tmp_path))
        assert count == 256  # IPv6 range contributed nothing
        out = capsys.readouterr().out
        assert 'line 2' in out
        assert '2001:db8::/32' in out
        assert 'IPv4 only' in out

    def test_ipv6_bare_address_in_target_file_named_and_skipped(self, tmp_path, capsys):
        target = tmp_path / 'targets.txt'
        target.write_text('fe80::1\n10.0.0.1\n')
        result_file, count = _build_discovery_target_file(str(target), None, str(tmp_path))
        assert count == 1
        out = capsys.readouterr().out
        assert 'line 1' in out
        assert 'fe80::1' in out

    def test_ipv6_target_via_exclusions_path_does_not_raise(self, tmp_path):
        """The exclusions path is the one that reaches summarize_address_range()
        and used to raise AddressValueError for a bound >= 2**32."""
        target = tmp_path / 'targets.txt'
        target.write_text('2001:db8::/64\n10.0.0.0/24\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.0/25\n')
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 128
        content = Path(result_file).read_text()
        assert '10.0.0.128/25' in content
        assert ':' not in content  # no IPv6 leaked into the masscan target file

    def test_ipv6_in_exclusions_file_named_and_skipped(self, tmp_path, capsys):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('# comment\n2001:db8::/32\n10.0.0.0/25\n')
        result_file, count = _build_discovery_target_file(str(target), str(excl), str(tmp_path))
        assert count == 128
        out = capsys.readouterr().out
        assert str(excl) in out
        assert 'line 2' in out

    def test_ipv6_only_target_file_returns_zero_count(self, tmp_path, capsys):
        target = tmp_path / 'targets.txt'
        target.write_text('2001:db8::/32\n')
        result_file, count = _build_discovery_target_file(str(target), None, str(tmp_path))
        assert result_file == str(target)
        assert count == 0
        assert 'IPv4 only' in capsys.readouterr().out


# ── _ip_sort_key ──────────────────────────────────────────────────────────────

class TestIpSortKey:
    """_ip_sort_key() replaces three inline int(octet) tuple keys that raised
    ValueError — discarding a completed sweep — on any non-IPv4 string."""

    def test_ipv4_sorts_numerically_not_lexically(self):
        ips = ['10.0.0.10', '10.0.0.2', '9.255.255.255', '10.0.1.1']
        assert sorted(ips, key=_ip_sort_key) == [
            '9.255.255.255', '10.0.0.2', '10.0.0.10', '10.0.1.1']

    def test_matches_previous_octet_tuple_ordering_for_ipv4(self):
        ips = ['192.168.1.1', '10.0.0.1', '172.16.255.254', '10.0.0.255']
        legacy = sorted(ips, key=lambda x: tuple(int(o) for o in x.split('.')))
        assert sorted(ips, key=_ip_sort_key) == legacy

    def test_non_ipv4_entries_sort_last_without_raising(self):
        mixed = ['host.example.com', '::1', '10.0.0.1']
        assert sorted(mixed, key=_ip_sort_key) == ['10.0.0.1', '::1', 'host.example.com']

    def test_truncated_and_empty_strings_do_not_raise(self):
        assert sorted(['10.0.0', '', '10.0.0.1'], key=_ip_sort_key)[0] == '10.0.0.1'

    def test_out_of_range_octet_does_not_raise(self):
        """'10.0.0.999' parses as four ints but is not a valid address."""
        assert sorted(['10.0.0.999', '10.0.0.1'], key=_ip_sort_key) == [
            '10.0.0.1', '10.0.0.999']


# ── is_hostname ───────────────────────────────────────────────────────────────

class TestIsHostname:
    def test_ipv4_address(self):
        assert is_hostname('192.168.1.1') is False

    def test_cidr_notation(self):
        assert is_hostname('10.0.0.0/8') is False

    def test_host_cidr(self):
        assert is_hostname('192.168.1.5/32') is False

    def test_plain_hostname(self):
        assert is_hostname('example.com') is True

    def test_internal_hostname(self):
        assert is_hostname('internal-host') is True

    def test_subdomain(self):
        assert is_hostname('mail.corp.example.com') is True

    def test_empty_string(self):
        assert is_hostname('') is False

    def test_whitespace_only(self):
        assert is_hostname('   ') is False

    def test_comment_line(self):
        assert is_hostname('#192.168.0.0/24') is False

    def test_loopback(self):
        assert is_hostname('127.0.0.1') is False

    def test_hostname_with_surrounding_whitespace(self):
        assert is_hostname('  example.com  ') is True


# ── _select_probe_ports ───────────────────────────────────────────────────────

class TestSelectProbePorts:
    def test_selects_priority_ports_first(self):
        # 80, 443, 22 are all in PROBE_PORT_PRIORITY; 9999 is not
        result = _select_probe_ports(['9999', '80', '443', '22'])
        assert result[0] in ('80', '443', '22')
        assert '9999' not in result[:3] or len(result) > 3

    def test_respects_priority_ordering(self):
        # 443 is now first in PROBE_PORT_PRIORITY
        result = _select_probe_ports(['22', '443', '445'], max_ports=1)
        assert result == ['443']

    def test_caps_at_default_max(self):
        ports = ['445', '3389', '80', '443', '22', '135', '139']
        assert len(_select_probe_ports(ports)) == 5

    def test_custom_max_ports(self):
        ports = ['445', '3389', '80']
        assert len(_select_probe_ports(ports, max_ports=2)) == 2

    def test_falls_back_when_no_priority_match(self):
        ports = ['9997', '9998', '9999']
        result = _select_probe_ports(ports)
        assert result == ['9997', '9998', '9999']

    def test_fallback_also_caps_at_max(self):
        ports = ['9991', '9992', '9993', '9994', '9995', '9996']
        assert len(_select_probe_ports(ports)) == 5

    def test_empty_input(self):
        assert _select_probe_ports([]) == []

    def test_subset_of_priority_list(self):
        # Only two priority ports in dest — no non-priority ports to fill remaining slots
        result = _select_probe_ports(['22', '443'], max_ports=5)
        assert set(result) == {'22', '443'}

    def test_fills_remaining_slots_with_non_priority_ports(self):
        # 443 is priority; 9997/9998 are not — should fill up to max_ports=3
        result = _select_probe_ports(['443', '9997', '9998'], max_ports=3)
        assert result[0] == '443'          # priority port first
        assert set(result) == {'443', '9997', '9998'}
        assert len(result) == 3


# ── _calc_scan_wait ────────────────────────────────────────────────────────────

class TestCalcScanWait:
    def test_small_network_gets_full_wait(self):
        # /24 = 256 hosts at 1000 pps → scan_duration ≈ 0.25s → wait ≈ 29s
        result = _calc_scan_wait(256, '1000')
        assert result == 29

    def test_large_network_gets_zero_wait(self):
        # /16 = 65536 hosts at 1000 pps → scan_duration ≈ 65s > 30s → wait = 0
        result = _calc_scan_wait(65536, '1000')
        assert result == 0

    def test_medium_network_partial_wait(self):
        # 1000 hosts at 1000 pps → scan_duration = 1s → wait = 29s
        result = _calc_scan_wait(1000, '1000')
        assert result == 29

    def test_none_host_count_returns_default(self):
        assert _calc_scan_wait(None, '1000') == 2

    def test_zero_host_count_returns_default(self):
        assert _calc_scan_wait(0, '1000') == 2

    def test_higher_rate_reduces_wait_threshold(self):
        # 10000 pps: 30000 hosts needed for scan_duration = 3s
        # 1000 hosts / 10000 pps = 0.1s → wait = 29s
        result = _calc_scan_wait(1000, '10000')
        assert result == 29

    def test_threshold_boundary(self):
        # 30000 hosts / 1000 pps = 30s = recovery_window → wait = 0
        result = _calc_scan_wait(30000, '1000')
        assert result == 0

    def test_tiny_host_count_gets_zero_wait(self):
        # 4 discovered hosts: recovery_window = 30 * 4/256 ≈ 0.47s → wait = 0
        assert _calc_scan_wait(4, '2000') == 0

    def test_sub_24_scales_proportionally(self):
        # 16 hosts: recovery_window = 30 * 16/256 ≈ 1.875s, scan_duration ≈ 0.016s → wait = 1
        assert _calc_scan_wait(16, '1000') == 1


# ── _get_scripts_for_port ─────────────────────────────────────────────────────

class TestGetScriptsForPort:
    def test_external_ssh(self):
        assert _get_scripts_for_port('22', 'External') == 'ssh-auth-methods,ssh2-enum-algos'

    def test_external_ftp(self):
        # 21 is a sensitive external port, so vuln/vulners are appended; the base
        # script must still lead the list.
        assert _get_scripts_for_port('21', 'External').split(',')[0] == 'ftp-anon'

    def test_external_ssl_cert_ports(self):
        for port in ('443', '8443', '636', '10443'):
            assert 'ssl-cert' in _get_scripts_for_port(port, 'External'), port

    def test_external_mssql(self):
        # 1433 is a sensitive external port, so vuln/vulners are appended; the base
        # script must still lead the list.
        assert _get_scripts_for_port('1433', 'External').split(',')[0] == 'ms-sql-ntlm-info'

    def test_internal_ftp(self):
        assert _get_scripts_for_port('21', 'Internal') == 'ftp-anon'

    def test_internal_smb(self):
        result = _get_scripts_for_port('445', 'Internal')
        assert 'smb-security-mode' in result
        assert 'smb2-security-mode' in result
        assert 'smb-vuln-ms17-010' in result

    def test_internal_mssql(self):
        # azure-sql-detect.nse rides along with ms-sql-info to distinguish
        # Azure SQL Database (frozen 12.0 version, NOT end-of-life) from
        # genuinely end-of-life on-prem SQL Server.
        result = _get_scripts_for_port('1433', 'Internal')
        assert result.split(',')[0] == 'ms-sql-info'
        assert result.endswith('nse/azure-sql-detect.nse')

    def test_internal_udp_mssql(self):
        # Bundled pre-redesign script is referenced by absolute path
        result = _get_scripts_for_port('U:1434', 'Internal')
        assert result.endswith('nse/ms-sql-info.nse')

    def test_mssql_differs_by_scan_type(self):
        assert _get_scripts_for_port('1433', 'External') != _get_scripts_for_port('1433', 'Internal')

    def test_443_not_in_internal_table(self):
        # ssl-cert is external-only
        assert _get_scripts_for_port('443', 'Internal') is None

    def test_4786_external_uses_cisco_siet(self):
        result = _get_scripts_for_port('4786', 'External')
        assert result is not None and result.endswith('cisco-siet.nse')

    def test_4786_internal_uses_cisco_siet(self):
        result = _get_scripts_for_port('4786', 'Internal')
        assert result is not None and result.endswith('cisco-siet.nse')

    def test_6129_external_uses_dameware_detect(self):
        result = _get_scripts_for_port('6129', 'External')
        assert result is not None and result.endswith('nse/dameware-detect.nse')

    def test_6129_internal_uses_dameware_detect(self):
        result = _get_scripts_for_port('6129', 'Internal')
        assert result is not None and result.endswith('nse/dameware-detect.nse')

    def test_445_internal_includes_ms17010(self):
        result = _get_scripts_for_port('445', 'Internal')
        assert result is not None and 'smb-vuln-ms17-010' in result

    def test_unknown_port_external(self):
        assert _get_scripts_for_port('9999', 'External') is None

    def test_unknown_port_internal(self):
        assert _get_scripts_for_port('9999', 'Internal') is None


# ── lineCount ─────────────────────────────────────────────────────────────────

class TestLineCount:
    def test_counts_lines(self, tmp_path):
        f = tmp_path / 'hosts.txt'
        f.write_text('10.0.0.1\n10.0.0.2\n10.0.0.3\n')
        assert lineCount(str(f)) == 3

    def test_empty_file_returns_zero(self, tmp_path):
        f = tmp_path / 'empty.txt'
        f.write_text('')
        assert lineCount(str(f)) == 0

    def test_missing_file_returns_zero(self, tmp_path):
        assert lineCount(str(tmp_path / 'nonexistent.txt')) == 0

    def test_single_line_no_newline(self, tmp_path):
        f = tmp_path / 'one.txt'
        f.write_text('10.0.0.1')
        assert lineCount(str(f)) == 1

    def test_generic_read_error_returns_zero(self, tmp_path, capsys):
        # A directory raises IsADirectoryError (an OSError subclass, not
        # FileNotFoundError) on open() — exercises the generic except branch.
        d = tmp_path / 'a_directory'
        d.mkdir()
        assert lineCount(str(d)) == 0
        assert 'Error reading file' in capsys.readouterr().out


# ── _write_artifact ───────────────────────────────────────────────────────────

class TestWriteArtifact:
    """_write_artifact() must never let one unwritable path raise out."""

    def test_writes_content_and_reports_success(self, tmp_path):
        target = tmp_path / 'artifact.txt'
        assert _write_artifact(str(target), 'body\n') is True
        assert target.read_text() == 'body\n'

    def test_os_error_is_reported_not_raised(self, tmp_path, capsys):
        target = str(tmp_path / 'artifact.txt')
        with patch('spoonmap._atomic_write',
                   side_effect=OSError('No space left on device')):
            assert _write_artifact(target, 'body\n') is False
        out = capsys.readouterr().out
        assert 'could not write' in out
        assert target in out                    # names the path
        assert 'No space left on device' in out  # names the error


# ── _write_findings_txt ───────────────────────────────────────────────────────

SAMPLE_FINDINGS = [
    ('HIGH',   '10.0.0.4', 'tcp/445',  'SMBv2 Signing Not Required', 'no signing'),
    ('MEDIUM', '10.0.0.2', 'tcp/22',   'Weak SSH Algorithms', 'arcfour offered'),
    ('LOW',    '10.0.0.1', 'tcp/21',   'Anonymous FTP',      'Login allowed'),
    ('LOW',    '10.0.0.3', 'tcp/1433', 'SQL Server Found',    'version info'),
]


class TestWriteFindingsTxt:
    def test_creates_file(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        assert (tmp_path / 'findings.txt').exists()

    def test_contains_severity_headings(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.txt').read_text()
        assert 'HIGH' in content
        assert 'MEDIUM' in content
        assert 'LOW' in content

    def test_contains_host_and_title(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.txt').read_text()
        assert '10.0.0.1' in content
        assert 'Anonymous FTP' in content

    def test_total_count_line(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.txt').read_text()
        assert f'Total findings: {len(SAMPLE_FINDINGS)}' in content

    def test_empty_findings(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', [])
        assert 'Total findings: 0' in (tmp_path / 'findings.txt').read_text()

    def test_total_count_uses_group_count_not_instance_count(self, tmp_path):
        # Three instances of the same finding on different hosts → 1 group
        findings = [
            ('HIGH', '10.0.0.1', 'tcp/445', 'Service Exposed Externally', 'SMB'),
            ('HIGH', '10.0.0.2', 'tcp/445', 'Service Exposed Externally', 'SMB'),
            ('HIGH', '10.0.0.3', 'tcp/445', 'Service Exposed Externally', 'SMB'),
        ]
        _write_findings_txt(str(tmp_path), 'External', findings)
        content = (tmp_path / 'findings.txt').read_text()
        assert 'Total findings: 1' in content

    def test_service_exposed_externally_has_no_sample_output_block(self, tmp_path):
        findings = [('HIGH', '1.2.3.4', 'tcp/135', 'Service Exposed Externally', 'RPC')]
        _write_findings_txt(str(tmp_path), 'External', findings)
        content = (tmp_path / 'findings.txt').read_text()
        assert 'Sample output:' not in content

    def test_severity_ordering_in_output(self, tmp_path):
        _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.txt').read_text()
        assert content.index('HIGH') < content.index('MEDIUM') < content.index('LOW')

    def test_openai_extra_cmds_use_bare_port_number(self, tmp_path):
        # Regression: {port} must be the bare number, not the internal proto/port.
        findings = [('HIGH', '10.0.0.5', 'tcp/1234',
                     'OpenAI-Compatible LLM API Unauthenticated', 'LM Studio')]
        _write_findings_txt(str(tmp_path), 'External', findings)
        content = (tmp_path / 'findings.txt').read_text()
        assert 'http://10.0.0.5:1234/v1/models' in content
        assert 'http://10.0.0.5:tcp' not in content  # no malformed proto/port in URLs

    def test_snmp_repro_has_single_su_flag(self, tmp_path):
        findings = [('HIGH', '10.0.0.5', 'udp/161',
                     'SNMP Default Community String', 'public')]
        _write_findings_txt(str(tmp_path), 'Internal', findings)
        content = (tmp_path / 'findings.txt').read_text()
        assert 'nmap -sU -p 161 --script snmp-brute,snmp-sysdescr 10.0.0.5' in content
        assert '-sU -p 161 -sU' not in content  # no duplicate -sU

    def test_custom_nse_repro_uses_absolute_script_path(self, tmp_path):
        findings = [('HIGH', '10.0.0.5', 'tcp/389',
                     'LDAP Signing Not Required', 'Signing: NOT REQUIRED')]
        _write_findings_txt(str(tmp_path), 'Internal', findings)
        content = (tmp_path / 'findings.txt').read_text()
        assert f'--script {spoonmap._DIR}/nse/ldap-signing-check.nse' in content
        assert '--script spoonmap/nse/' not in content  # not the old relative path

    def test_write_failure_is_reported_not_raised(self, tmp_path, capsys):
        # A read-only output dir must not unwind main() and lose findings.md/.json.
        with patch('spoonmap._atomic_write', side_effect=OSError('Read-only file system')):
            _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        out = capsys.readouterr().out
        assert 'findings.txt' in out
        assert 'Read-only file system' in out


class TestBuildReproCmd:
    def test_udp_port_gets_su_flag(self):
        cmd = _build_repro_cmd('Anonymous FTP', 'udp/69', '10.0.0.1')
        assert cmd.startswith('nmap -sU -p 69')
        assert '10.0.0.1' in cmd

    def test_tcp_port_has_no_su_flag(self):
        cmd = _build_repro_cmd('Anonymous FTP', 'tcp/21', '10.0.0.1')
        assert '-sU' not in cmd
        assert '-p 21' in cmd

    def test_unparseable_port_str_falls_back_to_generic_command(self):
        cmd = _build_repro_cmd('Some Finding', 'not-a-port', '10.0.0.1')
        assert cmd == 'nmap -sV 10.0.0.1  # could not parse port from "not-a-port"'


# ── _write_findings_md ────────────────────────────────────────────────────────

class TestWriteFindingsMd:
    def test_creates_file(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        assert (tmp_path / 'findings.md').exists()

    def test_markdown_report_header(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert '# SpooNMAP Security Findings Report' in content

    def test_scan_type_in_header(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        assert 'External' in (tmp_path / 'findings.md').read_text()

    def test_contains_table_row(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert '10.0.0.1' in content
        assert 'Anonymous FTP' in content

    def test_pipe_in_detail_is_escaped(self, tmp_path):
        findings = [('HIGH', '1.2.3.4', 'tcp/80', 'Test Finding', 'a|b|c')]
        _write_findings_md(str(tmp_path), 'Internal', findings)
        content = (tmp_path / 'findings.md').read_text()
        assert r'a\|b\|c' in content

    def test_total_count_line(self, tmp_path):
        _write_findings_md(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert f'**Total findings:** {len(SAMPLE_FINDINGS)}' in content

    def test_finding_title_is_h3_subheading(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert '### Anonymous FTP' in content
        assert '### Weak SSH Algorithms' in content

    def test_finding_column_absent_from_table_header(self, tmp_path):
        _write_findings_md(str(tmp_path), 'External', SAMPLE_FINDINGS)
        content = (tmp_path / 'findings.md').read_text()
        assert '| Host | Port | Detail |' in content
        assert '| Finding |' not in content

    def test_multiple_hosts_same_finding_single_heading(self, tmp_path):
        findings = [
            ('LOW', '10.0.0.1', 'tcp/21', 'Anonymous FTP', 'Login allowed'),
            ('LOW', '10.0.0.2', 'tcp/21', 'Anonymous FTP', 'Login allowed'),
            ('LOW', '10.0.0.3', 'tcp/21', 'Anonymous FTP', 'Login allowed'),
        ]
        _write_findings_md(str(tmp_path), 'Internal', findings)
        content = (tmp_path / 'findings.md').read_text()
        assert content.count('### Anonymous FTP') == 1
        assert '10.0.0.1' in content
        assert '10.0.0.2' in content
        assert '10.0.0.3' in content

    def test_different_findings_same_severity_separate_headings(self, tmp_path):
        findings = [
            ('LOW', '10.0.0.1', 'tcp/21', 'Anonymous FTP', 'Login allowed'),
            ('LOW', '10.0.0.2', 'tcp/22', 'Weak SSH Auth', 'password accepted'),
        ]
        _write_findings_md(str(tmp_path), 'External', findings)
        content = (tmp_path / 'findings.md').read_text()
        assert '### Anonymous FTP' in content
        assert '### Weak SSH Auth' in content
        assert content.count('| Host | Port | Detail |') == 2

    def test_write_failure_is_reported_not_raised(self, tmp_path, capsys):
        with patch('spoonmap._atomic_write', side_effect=OSError('Disk quota exceeded')):
            _write_findings_md(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
        out = capsys.readouterr().out
        assert 'findings.md' in out
        assert 'Disk quota exceeded' in out


# ── _write_findings_json ──────────────────────────────────────────────────────

class TestWriteFindingsJson:
    def test_findings_written_as_json_array(self, tmp_path):
        findings = [('HIGH', '10.0.0.1', 'tcp/22', 'Weak SSH', 'detail')]
        _write_findings_json(str(tmp_path), findings)
        data = json.loads((tmp_path / 'findings.json').read_text())
        assert len(data) == 1
        assert data[0] == {'severity': 'HIGH', 'host': '10.0.0.1',
                           'port': 'tcp/22', 'title': 'Weak SSH', 'detail': 'detail'}

    def test_empty_findings_writes_empty_array(self, tmp_path):
        _write_findings_json(str(tmp_path), [])
        data = json.loads((tmp_path / 'findings.json').read_text())
        assert data == []

    def test_multiple_findings_all_fields_present(self, tmp_path):
        _write_findings_json(str(tmp_path), SAMPLE_FINDINGS)
        data = json.loads((tmp_path / 'findings.json').read_text())
        assert len(data) == len(SAMPLE_FINDINGS)
        for record in data:
            assert set(record.keys()) == {'severity', 'host', 'port', 'title', 'detail'}

    def test_write_failure_is_reported_not_raised(self, tmp_path, capsys):
        with patch('spoonmap._atomic_write', side_effect=OSError('Stale file handle')):
            _write_findings_json(str(tmp_path), SAMPLE_FINDINGS)
        out = capsys.readouterr().out
        assert 'findings.json' in out
        assert 'Stale file handle' in out


class TestGenerateFindingsWriteFailureIsolation:
    """One unwritable findings artifact must not cost the other two."""

    def test_txt_failure_still_writes_md_and_json(self, tmp_path, capsys):
        txt_path = f'{tmp_path}/findings.txt'
        real_atomic_write = spoonmap._atomic_write

        def fail_txt_only(path, content):
            if path == txt_path:
                raise OSError('Read-only file system')
            return real_atomic_write(path, content)

        with patch('spoonmap._atomic_write', side_effect=fail_txt_only):
            _write_findings_txt(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
            _write_findings_md(str(tmp_path), 'Internal', SAMPLE_FINDINGS)
            _write_findings_json(str(tmp_path), SAMPLE_FINDINGS)
        assert not (tmp_path / 'findings.txt').exists()
        assert (tmp_path / 'findings.md').exists()
        assert (tmp_path / 'findings.json').exists()
        assert 'findings.txt' in capsys.readouterr().out


# ── generate_findings ─────────────────────────────────────────────────────────

def _script_elems(scripts):
    return ''.join(
        '<script id="{}" output="{}"/>\n'.format(
            sid, out.replace('"', '&quot;').replace('\n', '&#10;')
        )
        for sid, out in (scripts or {}).items()
    )


def _nmap_xml(host_ip, protocol, portid, scripts=None, service_attrs=None):
    """Build a minimal nmap XML with scripts inside a <port> element."""
    service_elem = ''
    if service_attrs:
        attrs = ' '.join(f'{k}="{v}"' for k, v in service_attrs.items())
        service_elem = f'\n        <service {attrs}/>'
    # Indent every script line consistently so the XML declaration stays at col 0
    raw = _script_elems(scripts).rstrip('\n')
    indented_scripts = '\n'.join('        ' + ln for ln in raw.split('\n')) if raw else ''
    return (
        f'<?xml version="1.0"?>\n'
        f'<nmaprun>\n'
        f'  <host>\n'
        f'    <address addr="{host_ip}" addrtype="ipv4"/>\n'
        f'    <ports>\n'
        f'      <port protocol="{protocol}" portid="{portid}">'
        f'{service_elem}\n'
        f'{indented_scripts}\n'
        f'      </port>\n'
        f'    </ports>\n'
        f'  </host>\n'
        f'</nmaprun>\n'
    )


def _nmap_xml_hostscript(host_ip, protocol, portid, hostscripts):
    """Build a minimal nmap XML with scripts inside a <hostscript> element.

    SMB security-mode and ms-sql-info use hostrule and appear here in real
    nmap output, not inside <port>.
    """
    # Re-indent so every script line aligns with the template's 14-space indent,
    # preventing textwrap.dedent from computing a 0-space common indent when
    # multiple scripts are present.
    raw = _script_elems(hostscripts).rstrip('\n')
    indented_scripts = ('\n' + ' ' * 14).join(raw.split('\n')) if raw else ''
    return textwrap.dedent(f"""\
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="{host_ip}" addrtype="ipv4"/>
            <ports>
              <port protocol="{protocol}" portid="{portid}"/>
            </ports>
            <hostscript>
              {indented_scripts}
            </hostscript>
          </host>
        </nmaprun>
    """)


@pytest.fixture()
def nmap_dir(tmp_path):
    (tmp_path / 'nse_results').mkdir()
    return tmp_path  # callers write files under tmp_path/nse_results/


class TestGenerateFindings:
    # ── anonymous FTP ────────────────────────────────────────────────────────

    def test_anonymous_ftp_detected_rated_low_with_review_note(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'Anonymous FTP' in txt
        assert '10.0.0.1' in txt
        # Rated LOW by default with a reviewer escalation note
        import json as _json
        records = _json.loads((nmap_dir / 'findings.json').read_text())
        ftp = [r for r in records if r['title'] == 'Anonymous FTP']
        assert ftp and ftp[0]['severity'] == 'LOW'
        assert 'REVIEW REQUIRED' in ftp[0]['detail']

    def test_anonymous_ftp_not_triggered_when_denied(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login not allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' not in (nmap_dir / 'findings.txt').read_text()

    def test_anonymous_ftp_suppressed_via_port_9100(self, nmap_dir):
        (nmap_dir / 'discovery' / 'live_hosts').mkdir(parents=True)
        (nmap_dir / 'discovery' / 'live_hosts' / 'port9100.txt').write_text('10.0.0.3\n')
        xml = _nmap_xml('10.0.0.3', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' not in (nmap_dir / 'findings.txt').read_text()

    def test_anonymous_ftp_not_suppressed_for_different_host(self, nmap_dir):
        # port9100.txt lists a different IP — the scanned host is not a printer
        (nmap_dir / 'discovery' / 'live_hosts').mkdir(parents=True)
        (nmap_dir / 'discovery' / 'live_hosts' / 'port9100.txt').write_text('10.0.0.99\n')
        xml = _nmap_xml('10.0.0.4', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Anonymous FTP' in (nmap_dir / 'findings.txt').read_text()

    # ── SMB signing ──────────────────────────────────────────────────────────

    def test_smb2_signing_not_required(self, nmap_dir):
        # smb2-security-mode is a hostrule script — appears under <hostscript>
        xml = _nmap_xml_hostscript('10.0.0.5', 'tcp', '445',
                                   hostscripts={'smb2-security-mode': 'Message signing enabled but not required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Signing Not Required' in content
        assert '10.0.0.5' in content

    def test_smb_signing_required_not_flagged(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.5', 'tcp', '445',
                                   hostscripts={'smb2-security-mode': 'Message signing enabled and required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Signing Not Required' not in (nmap_dir / 'findings.txt').read_text()

    # ── SMBv1 Enabled ─────────────────────────────────────────────────────────

    def test_smbv1_enabled_detected(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.6', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'account_used: guest message_signing: required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv1 Enabled' in content
        assert 'MEDIUM' in content
        assert '10.0.0.6' in content

    def test_smbv1_enabled_not_on_external(self, nmap_dir):
        xml = _nmap_xml_hostscript('1.2.3.4', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'account_used: guest message_signing: required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'SMBv1 Enabled' not in (nmap_dir / 'findings.txt').read_text()

    def test_smbv1_enabled_and_signing_not_required_both_fire(self, nmap_dir):
        # Signing disabled implies SMBv1 is active — both findings should appear
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-security-mode':
                                                'message_signing: disabled (dangerous, but default)'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv1 Enabled' in content
        assert 'SMBv1 Signing Not Required' in content
        assert '10.0.0.9' in content

    def test_smb1_signing_suppressed_when_smb2_also_not_required(self, nmap_dir):
        """Both SMBv1 and SMBv2 signing not required → only SMBv2 finding emitted."""
        xml = _nmap_xml_hostscript('10.0.0.10', 'tcp', '445',
                                   hostscripts={
                                       'smb-security-mode': 'message_signing: disabled',
                                       'smb2-security-mode': 'Message signing enabled but not required',
                                   })
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv2 Signing Not Required' in content
        assert 'SMBv1 Signing Not Required' not in content

    def test_smb1_signing_fires_when_smb2_is_required(self, nmap_dir):
        """SMBv1 signing not required but SMBv2 IS required → SMBv1 finding still emitted."""
        xml = _nmap_xml_hostscript('10.0.0.11', 'tcp', '445',
                                   hostscripts={
                                       'smb-security-mode': 'message_signing: disabled',
                                       'smb2-security-mode': 'Message signing enabled and required',
                                   })
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SMBv1 Signing Not Required' in content
        assert 'SMBv2 Signing Not Required' not in content

    # ── EternalBlue (MS17-010) ────────────────────────────────────────────────

    def test_ms17010_vulnerable_critical_finding(self, nmap_dir):
        # smb-vuln-ms17-010 is a hostrule script — appears under <hostscript>
        xml = _nmap_xml_hostscript('10.0.0.7', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'MS17-010' in content
        assert 'CRITICAL' in content
        assert '10.0.0.7' in content

    def test_ms17010_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.7', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'MS17-010' not in (nmap_dir / 'findings.txt').read_text()

    def test_ms17010_only_on_internal(self, nmap_dir):
        # Should not fire on External scans
        xml = _nmap_xml_hostscript('1.2.3.4', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms17-010': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'MS17-010' not in (nmap_dir / 'findings.txt').read_text()

    # ── MS08-067 (NetAPI / Conficker) ─────────────────────────────────────────

    def test_ms08067_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.8', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms08-067': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'MS08-067' in content
        assert 'CRITICAL' in content
        assert '10.0.0.8' in content

    def test_ms08067_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.8', 'tcp', '445',
                                   hostscripts={'smb-vuln-ms08-067': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'MS08-067' not in (nmap_dir / 'findings.txt').read_text()

    # ── DoublePulsar ──────────────────────────────────────────────────────────

    def test_doublepulsar_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-double-pulsar-backdoor': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'DoublePulsar' in content
        assert 'CRITICAL' in content

    def test_doublepulsar_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.9', 'tcp', '445',
                                   hostscripts={'smb-double-pulsar-backdoor': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'DoublePulsar' not in (nmap_dir / 'findings.txt').read_text()

    # ── SambaCry ──────────────────────────────────────────────────────────────

    def test_sambacry_vulnerable_critical_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.10', 'tcp', '445',
                                   hostscripts={'smb-vuln-cve-2017-7494': 'VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SambaCry' in content
        assert 'CRITICAL' in content

    def test_sambacry_not_vulnerable_no_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript('10.0.0.10', 'tcp', '445',
                                   hostscripts={'smb-vuln-cve-2017-7494': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SambaCry' not in (nmap_dir / 'findings.txt').read_text()

    # ── Unauthenticated Docker API ────────────────────────────────────────────

    def test_docker_api_exposed_on_2375(self, nmap_dir):
        xml = _nmap_xml('10.0.0.12', 'tcp', '2375',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nse_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Docker API' in content
        assert 'CRITICAL' in content
        assert '10.0.0.12' in content

    def test_docker_api_exposed_on_4243(self, nmap_dir):
        xml = _nmap_xml('10.0.0.12', 'tcp', '4243',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nse_results' / 'port4243.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Docker API' in (nmap_dir / 'findings.txt').read_text()

    def test_docker_api_no_response_no_finding(self, nmap_dir):
        # No docker-version script output means API did not respond
        xml = _nmap_xml('10.0.0.12', 'tcp', '2375')
        (nmap_dir / 'nse_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Docker API' not in (nmap_dir / 'findings.txt').read_text()

    def test_docker_api_fires_on_external_too(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '2375',
                        scripts={'docker-version': 'Version: 20.10.7'})
        (nmap_dir / 'nse_results' / 'port2375.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Docker API' in (nmap_dir / 'findings.txt').read_text()

    # ── NTLM info disclosure ─────────────────────────────────────────────────

    def test_ntlm_disclosure_on_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '25',
                        scripts={'smtp-ntlm-info': 'NetBIOS_Domain_Name: CORP'})
        (nmap_dir / 'nse_results' / 'port25.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'NTLM Information Disclosure' in (nmap_dir / 'findings.txt').read_text()

    def test_ntlm_disclosure_not_on_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.2', 'tcp', '25',
                        scripts={'smtp-ntlm-info': 'NetBIOS_Domain_Name: CORP'})
        (nmap_dir / 'nse_results' / 'port25.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'NTLM Information Disclosure' not in (nmap_dir / 'findings.txt').read_text()

    # ── external sensitive port exposure ─────────────────────────────────────

    def test_sensitive_port_flagged_on_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '445')
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Service Exposed Externally' in (nmap_dir / 'findings.txt').read_text()

    def test_sensitive_port_not_flagged_on_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '445')
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Service Exposed Externally' not in (nmap_dir / 'findings.txt').read_text()

    # ── TLS certificate expiry ────────────────────────────────────────────────

    def test_expired_cert_flagged(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': 'Not valid after:  2020-06-01T00:00:00'})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Expired TLS Certificate' in (nmap_dir / 'findings.txt').read_text()

    def test_valid_cert_not_flagged(self, nmap_dir):
        future = datetime.date.today().replace(
            year=datetime.date.today().year + 2
        ).isoformat()
        xml = _nmap_xml('1.2.3.4', 'tcp', '443',
                        scripts={'ssl-cert': f'Not valid after:  {future}T00:00:00'})
        (nmap_dir / 'nse_results' / 'port443.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Expired TLS Certificate' not in (nmap_dir / 'findings.txt').read_text()

    # ── known-bad service detection ───────────────────────────────────────────

    def test_dameware_detected(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '6129',
                        service_attrs={'name': 'dameware',
                                       'product': 'DameWare Mini Remote Control'})
        (nmap_dir / 'nse_results' / 'port6129.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'DameWare' in content
        assert 'HIGH' in content

    def test_dameware_nse_confirmed_critical(self, nmap_dir):
        """dameware-detect script output raises finding to CRITICAL."""
        xml = _nmap_xml(
            '10.0.0.2', 'tcp', '6129',
            scripts={'dameware-detect':
                     'Product: SolarWinds DameWare Mini Remote Control\n'
                     'CVE: CVE-2019-3980 (CVSS 9.8) - Unauthenticated RCE v12.1.0.89 and earlier\n'
                     'Remediation: Upgrade to v12.1.2+'},
        )
        (nmap_dir / 'nse_results' / 'port6129.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'DameWare' in content
        assert 'CRITICAL' in content
        # CVE detail is written to findings.md (detail column) and findings.json
        md_content = (nmap_dir / 'findings.md').read_text()
        assert 'CVE-2019-3980' in md_content

    def test_cisco_smart_install_vulnerable(self, nmap_dir):
        # cisco-siet.nse confirms VULNERABLE → finding raised
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786',
                        scripts={'cisco-siet': 'Host: 10.0.0.1  Status: VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' in (nmap_dir / 'findings.txt').read_text()

    def test_cisco_smart_install_not_vulnerable_no_finding(self, nmap_dir):
        # cisco-siet.nse returns NOT VULNERABLE → no finding
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786',
                        scripts={'cisco-siet': 'Host: 10.0.0.1  Status: NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' not in (nmap_dir / 'findings.txt').read_text()

    def test_cisco_smart_install_no_script_no_finding(self, nmap_dir):
        # port 4786 open but no cisco-siet script output → no finding (avoid false positives)
        xml = _nmap_xml('10.0.0.1', 'tcp', '4786')
        (nmap_dir / 'nse_results' / 'port4786.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Cisco Smart Install' not in (nmap_dir / 'findings.txt').read_text()

    def test_sap_gateway_detected(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '3300')
        (nmap_dir / 'nse_results' / 'port3300.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SAP Gateway' in (nmap_dir / 'findings.txt').read_text()

    # ── output files ─────────────────────────────────────────────────────────

    def test_both_output_files_created(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert (nmap_dir / 'findings.txt').exists()
        assert (nmap_dir / 'findings.md').exists()

    def test_no_output_when_nmap_results_missing(self, tmp_path):
        generate_findings(str(tmp_path), 'Internal')
        assert not (tmp_path / 'findings.txt').exists()

    def test_severity_order_in_output(self, nmap_dir):
        # HIGH from nfs-showmount, LOW from ms-sql-info — HIGH must come first
        # ms-sql-info is a hostrule script — appears under <hostscript>
        (nmap_dir / 'nse_results' / 'port111.xml').write_text(
            _nmap_xml('10.0.0.1', 'tcp', '111',
                      scripts={'nfs-showmount': '/exports *'})
        )
        (nmap_dir / 'nse_results' / 'port1433.xml').write_text(
            _nmap_xml_hostscript('10.0.0.2', 'tcp', '1433',
                                 hostscripts={'ms-sql-info': 'SQL Server 2019'})
        )
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert content.index('HIGH') < content.index('LOW')

    def test_generate_findings_writes_json(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '21',
                        scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        data = json.loads((nmap_dir / 'findings.json').read_text())
        assert any(r['title'] == 'Anonymous FTP' for r in data)

    def test_open_filtered_port_excluded_from_findings(self, nmap_dir):
        """Port with state open|filtered must not appear in findings."""
        xml = (
            '<?xml version="1.0"?>\n'
            '<nmaprun>\n'
            '  <host>\n'
            '    <address addr="10.0.0.5" addrtype="ipv4"/>\n'
            '    <ports>\n'
            '      <port protocol="tcp" portid="445">\n'
            '        <state state="open|filtered"/>\n'
            '      </port>\n'
            '    </ports>\n'
            '  </host>\n'
            '</nmaprun>\n'
        )
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'Service Exposed Externally' not in findings_file.read_text()

    # ── file-parsing edge cases ──────────────────────────────────────────────

    def test_non_xml_file_in_nmap_dir_ignored(self, nmap_dir):
        (nmap_dir / 'nse_results' / 'notes.txt').write_text('not xml')
        generate_findings(str(nmap_dir), 'Internal')  # must not raise

    def test_malformed_xml_file_skipped(self, nmap_dir, capsys):
        (nmap_dir / 'nse_results' / 'port21.xml').write_text('<nmaprun><host>')
        generate_findings(str(nmap_dir), 'Internal')  # must not raise

    def test_host_without_ipv4_address_falls_back_to_first_address(self, nmap_dir):
        """A host with only a non-ipv4-typed <address> still gets processed."""
        xml = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            '<ports><port protocol="tcp" portid="21">'
            '<state state="open"/>'
            '<script id="ftp-anon" output="Anonymous FTP login allowed"/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Anonymous FTP' in content
        assert 'AA:BB:CC:DD:EE:FF' in content

    # ── ssh-auth-methods (external) ──────────────────────────────────────────

    def test_weak_ssh_auth_method_flagged_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '22',
                        scripts={'ssh-auth-methods': 'password\npublickey'})
        (nmap_dir / 'nse_results' / 'port22.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Weak SSH Authentication' in content
        assert 'HIGH' in content

    def test_ssh_auth_methods_not_flagged_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '22',
                        scripts={'ssh-auth-methods': 'password'})
        (nmap_dir / 'nse_results' / 'port22.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Weak SSH Authentication' not in (nmap_dir / 'findings.txt').read_text()

    # ── ssh2-enum-algos (external) ────────────────────────────────────────────

    def test_weak_ssh_algo_flagged_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '22',
                        scripts={'ssh2-enum-algos':
                                 'encryption_algorithms: (2)\n    arcfour\n    aes128-ctr'})
        (nmap_dir / 'nse_results' / 'port22.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Weak SSH Algorithms' in (nmap_dir / 'findings.txt').read_text()
        records = json.loads((nmap_dir / 'findings.json').read_text())
        algos = [r for r in records if r['title'] == 'Weak SSH Algorithms']
        assert algos and 'arcfour' in algos[0]['detail']

    # ── rmi-dumpregistry (internal) ───────────────────────────────────────────

    def test_rmi_dumpregistry_flagged_internal(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '1090',
                        scripts={'rmi-dumpregistry': 'jmxrmi -> //10.0.0.1:1090'})
        (nmap_dir / 'nse_results' / 'port1090.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Java RMI Registry Exposed' in content

    def test_rmi_dumpregistry_not_flagged_external(self, nmap_dir):
        xml = _nmap_xml('1.2.3.4', 'tcp', '1090',
                        scripts={'rmi-dumpregistry': 'jmxrmi -> //1.2.3.4:1090'})
        (nmap_dir / 'nse_results' / 'port1090.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        assert 'Java RMI Registry Exposed' not in (nmap_dir / 'findings.txt').read_text()

    # ── AJP connector / Ghostcat (port 8009) ──────────────────────────────────

    def test_ajp_connector_flagged(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '8009',
                        scripts={'ajp-headers': 'AJP/1.3'})
        (nmap_dir / 'nse_results' / 'port8009.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'AJP Connector Exposed' in content
        assert 'HIGH' in content

    def test_ajp_connector_not_flagged_without_script_output(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '8009', scripts={})
        (nmap_dir / 'nse_results' / 'port8009.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'AJP Connector Exposed' not in findings_file.read_text()

    # ── X11 (port 6000) ────────────────────────────────────────────────────────

    def test_x11_access_granted_flagged(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '6000',
                        scripts={'x11-access': 'X server access is granted'})
        (nmap_dir / 'nse_results' / 'port6000.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'X11 Display Accessible' in content

    def test_x11_access_denied_not_flagged(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'tcp', '6000',
                        scripts={'x11-access': 'X server access is denied'})
        (nmap_dir / 'nse_results' / 'port6000.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'X11 Display Accessible' not in (nmap_dir / 'findings.txt').read_text()

    # ── cups-browsed RCE (CVE-2024-47176) ─────────────────────────────────────

    def test_cups_browsed_rce_flagged_with_version(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'udp', '631',
                        scripts={'cups-browsed-rce':
                                 'LIKELY VULNERABLE\ncups_version: 2.0.1'})
        (nmap_dir / 'nse_results' / 'port631.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'CUPS RCE' in content
        assert 'CRITICAL' in content
        records = json.loads((nmap_dir / 'findings.json').read_text())
        cups = [r for r in records if 'CUPS RCE' in r['title']]
        assert cups and '2.0.1' in cups[0]['detail']

    def test_cups_browsed_rce_unknown_version_when_unparsed(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'udp', '631',
                        scripts={'cups-browsed-rce': 'LIKELY VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port631.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        cups = [r for r in records if 'CUPS RCE' in r['title']]
        assert cups and 'CUPS unknown' in cups[0]['detail']

    def test_cups_browsed_not_flagged_when_not_vulnerable(self, nmap_dir):
        xml = _nmap_xml('10.0.0.1', 'udp', '631',
                        scripts={'cups-browsed-rce': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port631.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'CUPS RCE' not in findings_file.read_text()

    # ── snmp-brute output line parsing ────────────────────────────────────────

    def test_snmp_brute_ignores_non_matching_lines(self, nmap_dir):
        """A snmp-brute output line that doesn't match the community regex is skipped."""
        xml = _nmap_xml('10.0.0.1', 'udp', '161',
                        scripts={'snmp-brute':
                                 'Some unrelated line\n'
                                 'public - Valid credentials    (Access level: read-only)'})
        (nmap_dir / 'nse_results' / 'port161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'public' in content

    # ── malformed <host> / <script> elements ──────────────────────────────────

    def test_host_without_address_child_skipped(self, nmap_dir):
        # A truncated result file can hold a <host> with no <address> at all.
        # It must be skipped, not abort the walk over every other host.
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><ports><port protocol="tcp" portid="21">'
            '<state state="open"/>'
            '<script id="ftp-anon" output="Anonymous FTP login allowed"/>'
            '</port></ports></host>'
            '<host><address addr="10.0.0.11" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="21"><state state="open"/>'
            '<script id="ftp-anon" output="Anonymous FTP login allowed"/>'
            '</port></ports></host>'
            '</nmaprun>'
        )
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        ftp = [r for r in records if r['title'] == 'Anonymous FTP']
        assert [r['host'] for r in ftp] == ['10.0.0.11']

    def test_host_address_without_addr_attribute_skipped(self, nmap_dir):
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="21"><state state="open"/>'
            '<script id="ftp-anon" output="Anonymous FTP login allowed"/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        assert not [r for r in records if r['title'] == 'Anonymous FTP']

    def test_non_ipv4_address_still_used(self, nmap_dir):
        # No addrtype="ipv4" child, but a usable <address> — falls back to it.
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="fe80::1" addrtype="ipv6"/>'
            '<ports><port protocol="tcp" portid="21"><state state="open"/>'
            '<script id="ftp-anon" output="Anonymous FTP login allowed"/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        ftp = [r for r in records if r['title'] == 'Anonymous FTP']
        assert ftp and ftp[0]['host'] == 'fe80::1'

    def test_script_without_id_skipped_other_scripts_kept(self, nmap_dir):
        # scripts_for_elem() is a closure, so exercise it via generate_findings().
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.12" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="21"><state state="open"/>'
            '<script output="truncated, no id attribute"/>'
            '<script id="ftp-anon" output="Anonymous FTP login allowed"/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        ftp = [r for r in records if r['title'] == 'Anonymous FTP']
        assert ftp and ftp[0]['host'] == '10.0.0.12'

    def test_hostscript_without_id_skipped_other_scripts_kept(self, nmap_dir):
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.13" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="445"><state state="open"/>'
            '</port></ports>'
            '<hostscript>'
            '<script output="truncated, no id attribute"/>'
            '<script id="smb2-security-mode" '
            'output="Message signing enabled but not required"/>'
            '</hostscript></host></nmaprun>'
        )
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'Signing Not Required' in (nmap_dir / 'findings.txt').read_text()


class TestCountUnmatchedServicePorts:
    """Unit tests for _count_unmatched_service_ports()."""

    def _xml(self, ip, port, protocol='tcp', state='open', service_attrs=None):
        service_elem = ''
        if service_attrs:
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
        assert _count_unmatched_service_ports(str(tmp_path)) == {}

    def test_unmatched_fingerprint_counted(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.1', '9999', service_attrs={
            'name': 'unknown', 'servicefp': 'SF-Port9999-TCP:V=7.94%I=7%D=1/1%r(NULL,10,abc);',
        })
        (nmap_results / 'port9999.xml').write_text(xml)
        assert _count_unmatched_service_ports(str(tmp_path)) == {'10.0.0.1': 1}

    def test_recognized_service_not_counted(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.1', '22', service_attrs={'name': 'ssh', 'product': 'OpenSSH'})
        (nmap_results / 'port22.xml').write_text(xml)
        assert _count_unmatched_service_ports(str(tmp_path)) == {}

    def test_closed_port_not_counted_even_with_fingerprint(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.1', '9999', state='closed', service_attrs={
            'name': 'unknown', 'servicefp': 'SF-Port9999-TCP:...',
        })
        (nmap_results / 'port9999.xml').write_text(xml)
        assert _count_unmatched_service_ports(str(tmp_path)) == {}

    def test_udp_files_skipped(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = self._xml('10.0.0.1', '53', protocol='udp', service_attrs={
            'name': 'unknown', 'servicefp': 'SF-PortU53...',
        })
        (nmap_results / 'portU_53.xml').write_text(xml)
        assert _count_unmatched_service_ports(str(tmp_path)) == {}

    def test_multiple_ports_same_host_aggregate(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        for port in ('2222', '3333', '4444'):
            xml = self._xml('10.0.0.1', port, service_attrs={
                'name': 'unknown', 'servicefp': f'SF-Port{port}-TCP:...',
            })
            (nmap_results / f'port{port}.xml').write_text(xml)
        assert _count_unmatched_service_ports(str(tmp_path)) == {'10.0.0.1': 3}

    def test_malformed_xml_skipped(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port80.xml').write_text('<nmaprun><host>')
        assert _count_unmatched_service_ports(str(tmp_path)) == {}

    def test_host_without_ipv4_address_skipped(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="00:11:22:33:44:55" addrtype="mac"/>'
            '<ports><port protocol="tcp" portid="9999">'
            '<state state="open"/>'
            '<service name="unknown" servicefp="SF-Port9999-TCP:..."/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_results / 'port9999.xml').write_text(xml)
        assert _count_unmatched_service_ports(str(tmp_path)) == {}

    def test_address_without_addr_attribute_skipped_others_kept(self, tmp_path):
        """attrib['addr'] raised KeyError, which the `except etree.ParseError`
        around the parse does not catch — aborting the honeypot heuristic for
        every remaining result file, not just the one unusable element."""
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="9999">'
            '<state state="open"/>'
            '<service name="unknown" servicefp="SF-Port9999-TCP:..."/>'
            '</port></ports></host>'
            '<host><address addr="10.0.0.8" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="9999">'
            '<state state="open"/>'
            '<service name="unknown" servicefp="SF-Port9999-TCP:..."/>'
            '</port></ports></host>'
            '</nmaprun>'
        )
        (nmap_results / 'port9999.xml').write_text(xml)
        assert _count_unmatched_service_ports(str(tmp_path)) == {'10.0.0.8': 1}


class TestGenerateFindingsHoneypot:
    """generate_findings() 'Likely Honeypot / Decoy Host' finding."""

    def _unmatched_xml(self, ip, port):
        return (
            '<?xml version="1.0"?><nmaprun>'
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{port}">'
            '<state state="open"/>'
            f'<service name="unknown" servicefp="SF-Port{port}-TCP:..."/>'
            '</port></ports></host></nmaprun>'
        )

    def test_tarpit_file_flags_host(self, nmap_dir):
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'suspected_tarpits.txt').write_text('10.0.0.1,19,20\n')
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['severity'] == 'MEDIUM'
        assert hp[0]['host'] == '10.0.0.1'
        assert '19/20' in hp[0]['detail']

    def test_unmatched_services_flag_host(self, nmap_dir):
        nmap_results = nmap_dir / 'nmap_results'
        nmap_results.mkdir()
        for port in ('2222', '3333', '4444'):
            (nmap_results / f'port{port}.xml').write_text(self._unmatched_xml('10.0.0.2', port))
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert hp and hp[0]['host'] == '10.0.0.2'
        assert 'no known service signature' in hp[0]['detail']

    def test_below_unmatched_threshold_not_flagged(self, nmap_dir):
        nmap_results = nmap_dir / 'nmap_results'
        nmap_results.mkdir()
        for port in ('2222', '3333'):  # one short of HONEYPOT_MIN_UNMATCHED_PORTS
            (nmap_results / f'port{port}.xml').write_text(self._unmatched_xml('10.0.0.3', port))
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'Likely Honeypot' not in findings_file.read_text()

    def test_both_signals_combine_in_one_finding(self, nmap_dir):
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'suspected_tarpits.txt').write_text('10.0.0.4,20,20\n')
        nmap_results = nmap_dir / 'nmap_results'
        nmap_results.mkdir()
        for port in ('2222', '3333', '4444'):
            (nmap_results / f'port{port}.xml').write_text(self._unmatched_xml('10.0.0.4', port))
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert len(hp) == 1
        assert '20/20' in hp[0]['detail']
        assert 'no known service signature' in hp[0]['detail']

    def test_truncated_tarpit_line_skipped_good_line_kept(self, nmap_dir):
        # _report_suspected_tarpits() writes line by line, so an interrupt can
        # leave a partial final line with three parts but empty numerics. That
        # must not abort findings generation — the good line still counts.
        (nmap_dir / 'discovery').mkdir(exist_ok=True)
        (nmap_dir / 'discovery' / 'suspected_tarpits.txt').write_text(
            '10.0.0.5,18,20\n10.0.0.6,5,\n10.0.0.7,,20\n')
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        hp = [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']
        assert [r['host'] for r in hp] == ['10.0.0.5']
        assert '18/20' in hp[0]['detail']

    def test_unreadable_tarpit_file_degrades_to_no_data(self, nmap_dir):
        # os.path.exists() passes but open() raises (e.g. permissions, or the
        # path is a directory) — findings must still be written.
        (nmap_dir / 'discovery' / 'suspected_tarpits.txt').mkdir(parents=True)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        assert not [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']

    def test_absent_tarpit_file_no_crash(self, nmap_dir):
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        assert not [r for r in records if r['title'] == 'Likely Honeypot / Decoy Host']


# ── _previous_results_exist / _delete_previous_results ───────────────────────

class TestPreviousResults:
    def test_empty_dir_returns_false(self, tmp_path):
        assert _previous_results_exist(str(tmp_path)) is False

    def test_detects_masscan_results_dir(self, tmp_path):
        d = tmp_path / 'discovery' / 'masscan_results'
        d.mkdir(parents=True)
        (d / 'port80.xml').write_text('<nmaprun/>')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_live_hosts_dir(self, tmp_path):
        d = tmp_path / 'discovery' / 'live_hosts'
        d.mkdir(parents=True)
        (d / 'port80.txt').write_text('10.0.0.1\n')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_nmap_results_dir(self, tmp_path):
        d = tmp_path / 'nmap_results'
        d.mkdir()
        (d / 'port22.xml').write_text('<nmaprun/>')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_aggregate_file(self, tmp_path):
        (tmp_path / 'all_live_hosts.txt').write_text('10.0.0.1\n')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_spoonmap_output_xml(self, tmp_path):
        (tmp_path / 'spoonmap_output.xml').write_text('<nmaprun/>')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_detects_findings_txt(self, tmp_path):
        (tmp_path / 'findings.txt').write_text('findings\n')
        assert _previous_results_exist(str(tmp_path)) is True

    def test_empty_result_dir_not_detected(self, tmp_path):
        # An empty result directory is not considered a previous run
        (tmp_path / 'discovery').mkdir()
        assert _previous_results_exist(str(tmp_path)) is False

    def test_delete_removes_result_dirs(self, tmp_path):
        for d in ('discovery', 'nmap_results', 'nse_results'):
            p = tmp_path / d
            p.mkdir()
            (p / 'file.xml').write_text('<nmaprun/>')
        _delete_previous_results(str(tmp_path))
        for d in ('discovery', 'nmap_results', 'nse_results'):
            assert not (tmp_path / d).exists()

    def test_delete_removes_aggregate_files(self, tmp_path):
        for f in ('all_live_hosts.txt', 'spoonmap_output.xml',
                  'findings.txt', 'findings.md'):
            (tmp_path / f).write_text('data')
        _delete_previous_results(str(tmp_path))
        for f in ('all_live_hosts.txt', 'spoonmap_output.xml',
                  'findings.txt', 'findings.md'):
            assert not (tmp_path / f).exists()

    def test_delete_leaves_other_files_untouched(self, tmp_path):
        (tmp_path / 'config.json').write_text('{}')
        (tmp_path / 'ranges.txt').write_text('10.0.0.0/24\n')
        _delete_previous_results(str(tmp_path))
        assert (tmp_path / 'config.json').exists()
        assert (tmp_path / 'ranges.txt').exists()

    def test_delete_is_idempotent(self, tmp_path):
        # Calling delete on a clean dir must not raise
        _delete_previous_results(str(tmp_path))
        _delete_previous_results(str(tmp_path))

    def test_false_after_delete(self, tmp_path):
        d = tmp_path / 'nmap_results'
        d.mkdir()
        (d / 'port22.xml').write_text('<nmaprun/>')
        (tmp_path / 'findings.txt').write_text('x')
        _delete_previous_results(str(tmp_path))
        assert _previous_results_exist(str(tmp_path)) is False


# ── SERVICE_CATEGORIES docker ports ───────────────────────────────────────────

class TestServiceCategoriesDockerPorts:
    def test_specialized_includes_port_9100(self):
        assert '9100' in SERVICE_CATEGORIES['Specialized']

    def test_specialized_includes_docker_port_2375(self):
        assert '2375' in SERVICE_CATEGORIES['Specialized']

    def test_specialized_includes_docker_port_4243(self):
        assert '4243' in SERVICE_CATEGORIES['Specialized']

    def test_remote_management_includes_winrm_5985(self):
        assert '5985' in SERVICE_CATEGORIES['Remote Management']

    def test_remote_management_includes_winrm_5986(self):
        assert '5986' in SERVICE_CATEGORIES['Remote Management']

    def test_web_includes_weblogic_7001(self):
        assert '7001' in SERVICE_CATEGORIES['Web']

    def test_web_includes_weblogic_7002(self):
        assert '7002' in SERVICE_CATEGORIES['Web']

    def test_weblogic_ports_in_external_sensitive(self):
        sensitive_ports = {p for p, _, _ in EXTERNAL_SENSITIVE_PORTS}
        assert '7001' in sensitive_ports
        assert '7002' in sensitive_ports


# ── LDAP / SMB category split ─────────────────────────────────────────────────

class TestLdapSmbCategorySplit:
    def test_authentication_key_removed(self):
        assert 'Authentication' not in SERVICE_CATEGORIES

    def test_ldap_key_contains_correct_ports(self):
        assert SERVICE_CATEGORIES['LDAP'] == ['389', '636']

    def test_smb_key_contains_correct_ports(self):
        assert SERVICE_CATEGORIES['SMB'] == ['445', '135', '139', 'U:137']

    def test_ldap_appears_before_smb(self):
        keys = list(SERVICE_CATEGORIES.keys())
        assert keys.index('LDAP') < keys.index('SMB')

    def test_ldap_and_smb_in_different_batches_with_batch_size_5(self):
        all_ports = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
        tcp_ports = [p for p in all_ports if not p.startswith('U:')]
        idx_389 = tcp_ports.index('389')
        idx_445 = tcp_ports.index('445')
        assert idx_389 // 5 != idx_445 // 5, (
            f'389 (batch {idx_389 // 5}) and 445 (batch {idx_445 // 5}) '
            'must be in different batches'
        )


# ── Full Port Scan in mass_scan() ─────────────────────────────────────────────

class TestFullPortScan:
    def test_full_scan_skips_probe_and_calls_masscan_with_range(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'80': {'10.0.0.1'}, '443': {'10.0.0.2'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results) as mock_batch:
            result = mass_scan('Full', ['1-65535'], '53', '20000',
                               '/fake/targets.txt', '', target_scan='External')
        mock_batch.assert_called_once_with(
            ['1-65535'], '10000',   # capped from 20000 (External cap)
            str(tmp_path) + '/discovery/masscan_results/portFull.xml',
            '/fake/targets.txt', '53', '',
            wait_secs=2,
        )
        assert 'Hosts Found on Port 80' in result
        assert 'Hosts Found on Port 443' in result

    def test_full_scan_rate_capped_internal(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'22': {'10.0.0.1'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results) as mock_batch:
            mass_scan('Full', ['1-65535'], '88', '2000', '/fake/targets.txt', '')
        mock_batch.assert_called_once_with(
            ['1-65535'], '1000',   # capped from 2000 (Internal cap)
            str(tmp_path) + '/discovery/masscan_results/portFull.xml',
            '/fake/targets.txt', '88', '',
            wait_secs=2,
        )

    def test_full_scan_targets_discovered_hosts_not_full_range(self, tmp_path):
        """A Full sweep must scan the discovery file, not the whole range.

        65535 ports against every address in the range instead of the
        discovered live hosts multiplies the scan by the range's dead space,
        and full_scan_rate is capped, so the operator cannot compensate.
        """
        spoonmap.output_path = str(tmp_path)
        discovery_file = tmp_path / 'discovery' / 'live_hosts_discovery.txt'
        discovery_file.parent.mkdir(parents=True)
        discovery_file.write_text('10.0.0.1\n10.0.0.2\n10.0.0.3\n')
        with patch('spoonmap._run_masscan_batch', return_value={'22': {'10.0.0.1'}}) as mock_batch:
            mass_scan('Full', ['1-65535'], '88', '2000', '/fake/targets.txt', '',
                      discovery_file=str(discovery_file))
        # Full tuple, not just the target: wait_secs=0 also pins that --wait is
        # derived from the discovered host count rather than the whole range.
        mock_batch.assert_called_once_with(
            ['1-65535'], '1000',
            str(tmp_path) + '/discovery/masscan_results/portFull.xml',
            str(discovery_file), '88', '',
            wait_secs=0,
        )

    def test_full_scan_falls_back_when_discovery_file_missing(self, tmp_path):
        """A discovery path that was never written must not become the -iL target."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={'22': {'10.0.0.1'}}) as mock_batch:
            mass_scan('Full', ['1-65535'], '88', '2000', '/fake/targets.txt', '',
                      discovery_file=str(tmp_path / 'discovery' / 'absent.txt'))
        assert mock_batch.call_args[0][3] == '/fake/targets.txt'

    def test_full_scan_unions_live_hosts_with_prior_run(self, tmp_path, capsys):
        """A narrowed Full sweep must not delete hosts an earlier wider run found.

        The sweep now covers only the discovered hosts, so finding fewer hosts
        on a port than a previous run recorded is legitimate — dropping the
        difference would lose it from live_hosts/, all_live_hosts.txt, the nmap
        banner input, and spoonmap_output.*.
        """
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'live_hosts').mkdir(parents=True)
        (disc / 'live_hosts' / 'port22.txt').write_text('10.0.0.1\n10.0.0.7\n')
        discovery_file = disc / 'live_hosts_discovery.txt'
        discovery_file.write_text('10.0.0.1\n')
        with patch('spoonmap._run_masscan_batch', return_value={'22': {'10.0.0.1'}}):
            result = mass_scan('Full', ['1-65535'], '88', '2000',
                               '/fake/targets.txt', '',
                               discovery_file=str(discovery_file))
        kept = (disc / 'live_hosts' / 'port22.txt').read_text().split()
        assert kept == ['10.0.0.1', '10.0.0.7']
        # The retained host is reflected in the reported count, as on the resume
        # path, not silently present on disk only.
        assert 'Hosts Found on Port 22: 2' in result

    def test_full_scan_warns_when_rate_is_capped(self, tmp_path, capsys):
        """A clamped rate is disclosed — the run summary shows the requested rate."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={'22': {'10.0.0.1'}}):
            mass_scan('Full', ['1-65535'], '88', '5000', '/fake/targets.txt', '')
        out = capsys.readouterr().out
        assert 'capped at 1000 pps' in out
        assert 'requested 5000' in out

    def test_full_scan_no_warning_when_rate_under_cap(self, tmp_path, capsys):
        """No notice when the operator's rate is already below the cap."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={'22': {'10.0.0.1'}}):
            mass_scan('Full', ['1-65535'], '88', '500', '/fake/targets.txt', '')
        assert 'capped' not in capsys.readouterr().out

    def test_category_scan_does_not_warn_about_full_scan_cap(self, tmp_path, capsys):
        """The cap applies only to Full — a batched scan uses the full rate silently."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={'22': {'10.0.0.1'}}):
            mass_scan('Category', ['22'], '88', '5000', '/fake/targets.txt', '')
        assert 'capped' not in capsys.readouterr().out

    def test_full_scan_writes_live_hosts_files(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'22': {'10.0.0.5', '10.0.0.6'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results):
            mass_scan('Full', ['1-65535'], '53', '10000', '/fake/targets.txt', '')
        live_file = tmp_path / 'discovery' / 'live_hosts' / 'port22.txt'
        assert live_file.exists()
        assert '10.0.0.5' in live_file.read_text()
        assert '10.0.0.6' in live_file.read_text()
        # The atomic write must not leave its temp file where the resume path
        # and _combine_live_hosts() enumerate this directory.
        assert [p.name for p in live_file.parent.iterdir()] == ['port22.txt']

    def test_full_scan_live_hosts_write_failure_keeps_prior_file(self, tmp_path):
        """A failed live_hosts write must leave the previous host list complete.

        Truncating this file makes a later resume scan that port against fewer
        hosts, silently, with no error anywhere in the output.
        """
        spoonmap.output_path = str(tmp_path)
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        live_dir.mkdir(parents=True)
        (live_dir / 'port22.txt').write_text('10.0.0.1\n10.0.0.2\n')
        with patch('spoonmap._run_masscan_batch', return_value={'22': {'10.0.0.5'}}), \
             patch('spoonmap.os.replace', side_effect=OSError('ENOSPC')):
            with pytest.raises(OSError):
                mass_scan('Full', ['1-65535'], '53', '10000', '/fake/targets.txt', '')
        assert (live_dir / 'port22.txt').read_text() == '10.0.0.1\n10.0.0.2\n'
        assert [p.name for p in live_dir.iterdir()] == ['port22.txt']

    def test_full_scan_resume_reloads_from_live_hosts(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        (disc / 'live_hosts').mkdir(parents=True)
        targets = disc / 'resolved_targets.txt'
        targets.write_text('10.0.0.0/24\n')
        cached = disc / 'masscan_results' / 'portFull.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, targets)
        (disc / 'live_hosts' / 'port22.txt').write_text('10.0.0.1\n10.0.0.2\n')
        (disc / 'live_hosts' / 'port22_hostnames.txt').write_text('host.example\n')

        with patch('spoonmap._run_masscan_batch') as mock_batch:
            result = mass_scan('Full', ['1-65535'], '53', '10000',
                               str(targets), '', resume=True)

        assert not mock_batch.called
        assert 'Hosts Found on Port 22: 2' in result

    def test_full_scan_flags_suspected_tarpit(self, tmp_path, capsys):
        spoonmap.output_path = str(tmp_path)
        # 15 distinct open ports on one host trips the ratio once the fraction
        # threshold is lowered — real full scans reaching 90% of 65535 is the
        # realistic trigger, but that's impractical to construct in a test.
        fake_results = {str(p): {'10.0.0.9'} for p in range(15)}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results), \
             patch('spoonmap.HONEYPOT_OPEN_PORT_FRACTION', 0.0001):
            mass_scan('Full', ['1-65535'], '53', '10000', '/fake/targets.txt', '')
        tarpit_file = tmp_path / 'discovery' / 'suspected_tarpits.txt'
        assert tarpit_file.exists()
        assert '10.0.0.9' in tarpit_file.read_text()
        assert 'tarpit' in capsys.readouterr().out.lower()

    def test_full_scan_no_tarpit_flag_for_normal_host_count(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        fake_results = {'22': {'10.0.0.1'}, '80': {'10.0.0.1'}, '443': {'10.0.0.1'}}
        with patch('spoonmap._run_masscan_batch', return_value=fake_results):
            mass_scan('Full', ['1-65535'], '53', '10000', '/fake/targets.txt', '')
        assert not (tmp_path / 'discovery' / 'suspected_tarpits.txt').exists()

    def test_full_scan_resume_flags_suspected_tarpit(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        live_dir = disc / 'live_hosts'
        live_dir.mkdir(parents=True)
        targets = disc / 'resolved_targets.txt'
        targets.write_text('10.0.0.0/24\n')
        cached = disc / 'masscan_results' / 'portFull.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, targets)
        for p in range(15):
            (live_dir / f'port{p}.txt').write_text('10.0.0.9\n')

        with patch('spoonmap._run_masscan_batch') as mock_batch, \
             patch('spoonmap.HONEYPOT_OPEN_PORT_FRACTION', 0.0001):
            mass_scan('Full', ['1-65535'], '53', '10000',
                      str(targets), '', resume=True)

        assert not mock_batch.called
        tarpit_file = disc / 'suspected_tarpits.txt'
        assert tarpit_file.exists()
        assert '10.0.0.9' in tarpit_file.read_text()

    def test_full_scan_resume_normalises_udp_port_key(self, tmp_path):
        """A resumed Full scan must convert 'portU_53.txt' to the 'U:53' port key.

        The raw filename stem fails the port_key.startswith('U:') test in
        _flag_suspected_tarpits(), so a UDP port was counted toward the TCP
        open-port fraction.  Nine TCP ports sit one below the threshold of 10;
        counting the UDP port as a tenth spuriously flags the host as a tarpit.
        """
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        live_dir = disc / 'live_hosts'
        live_dir.mkdir(parents=True)
        targets = disc / 'resolved_targets.txt'
        targets.write_text('10.0.0.0/24\n')
        cached = disc / 'masscan_results' / 'portFull.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, targets)
        for p in range(9):
            (live_dir / f'port{p}.txt').write_text('10.0.0.9\n')
        (live_dir / 'portU_53.txt').write_text('10.0.0.9\n')

        with patch('spoonmap._run_masscan_batch') as mock_batch, \
             patch('spoonmap.HONEYPOT_OPEN_PORT_FRACTION', 0.0001):
            result = mass_scan('Full', ['1-65535'], '53', '10000',
                               str(targets), '', resume=True)

        assert not mock_batch.called
        assert 'Hosts Found on Port U:53: 1' in result
        assert 'Hosts Found on Port U_53' not in result
        assert not (disc / 'suspected_tarpits.txt').exists()

    def _setup_full_resume_cache(self, tmp_path, xml_text):
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        (disc / 'live_hosts').mkdir(parents=True)
        targets = disc / 'resolved_targets.txt'
        targets.write_text('10.0.0.1\n')
        cached = disc / 'masscan_results' / 'portFull.xml'
        cached.write_text(xml_text)
        (disc / 'live_hosts' / 'port22.txt').write_text('10.0.0.1\n10.0.0.2\n')
        _write_target_stamp(cached, targets)
        os.utime(str(targets), (1000, 1000))
        os.utime(str(cached), (2000, 2000))  # fresh mtime
        return disc, targets

    def test_full_scan_resume_reruns_on_zero_length_xml(self, tmp_path, capsys):
        # A masscan killed mid-run leaves an empty portFull.xml; resume must
        # redo the scan instead of trusting the (fresh) mtime.
        disc, targets = self._setup_full_resume_cache(tmp_path, '')
        with patch('spoonmap._run_masscan_batch',
                   return_value={'443': {'10.0.0.3'}}) as mock_batch:
            result = mass_scan('Full', ['1-65535'], '53', '10000',
                               str(targets), '', resume=True)

        assert mock_batch.called
        out = capsys.readouterr().out
        assert 're-running Full port scan' in out
        assert 'skipping completed Full port scan' not in out
        assert 'Hosts Found on Port 443: 1' in result

    def test_full_scan_resume_reruns_on_unparseable_xml(self, tmp_path, capsys):
        disc, targets = self._setup_full_resume_cache(tmp_path, '<nmaprun><host>')
        with patch('spoonmap._run_masscan_batch',
                   return_value={'443': {'10.0.0.3'}}) as mock_batch:
            result = mass_scan('Full', ['1-65535'], '53', '10000',
                               str(targets), '', resume=True)

        assert mock_batch.called
        assert 're-running Full port scan' in capsys.readouterr().out
        assert 'Hosts Found on Port 443: 1' in result

    def test_full_scan_resume_reruns_on_stale_xml(self, tmp_path):
        disc, targets = self._setup_full_resume_cache(tmp_path, '<nmaprun/>')
        os.utime(str(targets), (3000, 3000))  # targets newer → stale cache
        with patch('spoonmap._run_masscan_batch',
                   return_value={'443': {'10.0.0.3'}}) as mock_batch:
            result = mass_scan('Full', ['1-65535'], '53', '10000',
                               str(targets), '', resume=True)

        assert mock_batch.called
        assert 'Hosts Found on Port 443: 1' in result

    def test_full_scan_resume_still_skips_valid_fresh_xml(self, tmp_path, capsys):
        # Load-bearing direction: a completed Full scan must stay skipped.
        disc, targets = self._setup_full_resume_cache(tmp_path, '<nmaprun/>')
        with patch('spoonmap._run_masscan_batch') as mock_batch:
            result = mass_scan('Full', ['1-65535'], '53', '10000',
                               str(targets), '', resume=True)

        assert not mock_batch.called
        assert 'skipping completed Full port scan' in capsys.readouterr().out
        assert 'Hosts Found on Port 22: 2' in result


class TestMassScanTarpitFlag:
    """mass_scan() batch-path wiring of the suspected-tarpit check (non-Full scans)."""

    def test_batch_scan_flags_suspected_tarpit(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        # batch_size == len(tcp_ports) puts every port into the single
        # two-call probe (fast + slow), so port_ips is fully populated with
        # no further main-batch iterations needed.
        tcp_ports = [str(2000 + i) for i in range(15)]
        fast_response = {p: {'10.0.0.9'} for p in tcp_ports}
        with patch('spoonmap._run_masscan_batch', side_effect=[fast_response, {}]):
            mass_scan('All', tcp_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=len(tcp_ports))
        tarpit_file = tmp_path / 'discovery' / 'suspected_tarpits.txt'
        assert tarpit_file.exists()
        assert '10.0.0.9' in tarpit_file.read_text()

    def test_batch_scan_no_tarpit_flag_for_realistic_open_count(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        tcp_ports = [str(2000 + i) for i in range(15)]
        fast_response = {tcp_ports[0]: {'10.0.0.9'},
                         tcp_ports[1]: {'10.0.0.9'},
                         tcp_ports[2]: {'10.0.0.9'}}
        # Ports missed by the probe are re-queued into one main batch call.
        with patch('spoonmap._run_masscan_batch', side_effect=[fast_response, {}, {}]):
            mass_scan('All', tcp_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=len(tcp_ports))
        assert not (tmp_path / 'discovery' / 'suspected_tarpits.txt').exists()


# ── _load_config ──────────────────────────────────────────────────────────────

def _config_dict(**overrides):
    """A minimal config.json dict for _load_config(), with *overrides* applied.

    Covers only the keys _load_config() indexes unconditionally; everything
    else is optional and left to the loader's own defaults.
    """
    cfg = {
        'banner_scan': 'True',
        'target_scan': 'Internal',
        'max_rate': '2000',
        'target_file': '/t/ranges.txt',
        'output_path': '/t/out',
    }
    cfg.update(overrides)
    return cfg


class TestLoadConfig:
    """_load_config() derives every scan setting from a parsed config.json."""

    def test_all_string_expands_every_category(self):
        cfg = _load_config(_config_dict(scan_categories='All'), '/t')
        expected = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
        assert cfg['scan_type'] == 'All'
        assert sorted(cfg['dest_ports']) == sorted(expected)

    def test_all_list_matches_all_string(self):
        as_list = _load_config(_config_dict(scan_categories=['All']), '/t')
        as_str = _load_config(_config_dict(scan_categories='All'), '/t')
        assert as_list['scan_type'] == 'All'
        assert as_list['dest_ports'] == as_str['dest_ports']

    def test_missing_scan_categories_defaults_to_all(self):
        assert _load_config(_config_dict(), '/t')['scan_type'] == 'All'

    def test_category_list_uses_only_valid_names(self):
        cfg = _load_config(
            _config_dict(scan_categories=['Web', 'NotACategory']), '/t')
        assert cfg['scan_type'] == 'Web'
        assert cfg['dest_ports'] == list(SERVICE_CATEGORIES['Web'])

    def test_unknown_scalar_scan_categories_yields_no_ports(self):
        cfg = _load_config(_config_dict(scan_categories='Bogus'), '/t')
        assert cfg['scan_type'] == ''
        assert cfg['dest_ports'] == []

    def test_udp_ports_sort_to_end(self):
        cfg = _load_config(_config_dict(scan_categories='All'), '/t')
        udp = [i for i, p in enumerate(cfg['dest_ports']) if p.startswith('U:')]
        tcp = [i for i, p in enumerate(cfg['dest_ports']) if not p.startswith('U:')]
        assert udp and tcp
        assert min(udp) > max(tcp)

    def test_dest_ports_override_forces_custom_scan_type(self):
        cfg = _load_config(
            _config_dict(scan_categories='All', dest_ports=['80', 'U:53']), '/t')
        assert cfg['scan_type'] == 'Custom'
        assert cfg['dest_ports'] == ['80', 'U:53']

    def test_empty_dest_ports_does_not_override(self):
        cfg = _load_config(_config_dict(scan_categories='Full', dest_ports=[]), '/t')
        assert cfg['scan_type'] == 'Full'
        assert cfg['dest_ports'] == ['1-65535']

    def test_banner_scan_true_string_becomes_bool(self):
        assert _load_config(_config_dict(banner_scan='True'), '/t')['banner_scan'] is True

    def test_banner_scan_other_string_becomes_false(self):
        assert _load_config(_config_dict(banner_scan='False'), '/t')['banner_scan'] is False

    def test_script_scan_and_host_discovery_string_to_bool(self):
        cfg = _load_config(
            _config_dict(script_scan='True', host_discovery='False'), '/t')
        assert cfg['script_scan'] is True
        assert cfg['host_discovery'] is False

    def test_script_scan_defaults_false_host_discovery_defaults_true(self):
        cfg = _load_config(_config_dict(), '/t')
        assert cfg['script_scan'] is False
        assert cfg['host_discovery'] is True

    def test_numeric_settings_coerced_to_int(self):
        cfg = _load_config(
            _config_dict(nmap_threads='9', masscan_batch_size='3',
                         nmap_threshold='1000'), '/t')
        assert cfg['nmap_threads'] == 9
        assert cfg['masscan_batch_size'] == 3
        assert cfg['nmap_threshold'] == 1000

    def test_numeric_settings_defaults(self):
        cfg = _load_config(_config_dict(), '/t')
        assert cfg['nmap_threads'] == 5
        assert cfg['masscan_batch_size'] == 5
        assert cfg['nmap_threshold'] == 5_000_000

    def test_relative_paths_resolve_against_dir_path(self):
        cfg = _load_config(
            _config_dict(target_file='ranges.txt', output_path='out',
                         exclusions_file='excl.txt'), '/opt/spoonmap')
        assert cfg['target_file'] == os.path.join('/opt/spoonmap', 'ranges.txt')
        assert cfg['output_path'] == os.path.join('/opt/spoonmap', 'out')
        assert cfg['exclusions_file'] == os.path.join('/opt/spoonmap', 'excl.txt')

    def test_absolute_paths_left_alone(self):
        cfg = _load_config(
            _config_dict(target_file='/abs/ranges.txt', output_path='/abs/out',
                         exclusions_file='/abs/excl.txt'), '/opt/spoonmap')
        assert cfg['target_file'] == '/abs/ranges.txt'
        assert cfg['output_path'] == '/abs/out'
        assert cfg['exclusions_file'] == '/abs/excl.txt'

    def test_empty_exclusions_file_normalizes_to_none(self):
        assert _load_config(_config_dict(exclusions_file=''), '/t')['exclusions_file'] is None

    def test_missing_exclusions_file_normalizes_to_none(self):
        assert _load_config(_config_dict(), '/t')['exclusions_file'] is None

    def test_resume_flag_is_ored_with_config_value(self):
        assert _load_config(_config_dict(resume='False'), '/t', True)['resume'] is True

    def test_config_resume_true_without_flag(self):
        assert _load_config(_config_dict(resume=' TRUE '), '/t')['resume'] is True

    def test_resume_defaults_false(self):
        assert _load_config(_config_dict(), '/t')['resume'] is False

    def test_generated_marker_detected(self):
        cfg = _load_config(_config_dict(**{_CONFIG_GENERATED_KEY: 'note'}), '/t')
        assert cfg['config_generated'] is True

    def test_hand_written_config_not_marked_generated(self):
        assert _load_config(_config_dict(), '/t')['config_generated'] is False

    def test_source_port_is_always_empty(self):
        assert _load_config(_config_dict(), '/t')['source_port'] == ''

    def test_passthrough_values(self):
        cfg = _load_config(
            _config_dict(target_scan='External', max_rate='20000',
                         scan_categories=['Web']), '/t')
        assert cfg['target_scan'] == 'External'
        assert cfg['max_rate'] == '20000'
        assert cfg['scan_categories'] == ['Web']

    # ---- JSON-native booleans (config.json.sample quotes booleans but not
    # ints, so operators reasonably write real JSON true/false) --------------

    def test_json_native_true_enables_script_scan(self):
        # Regression: == 'True' made a real JSON `true` evaluate to False, so
        # "script_scan": true silently ran no script scan and warned nobody.
        assert _load_config(_config_dict(script_scan=True), '/t')['script_scan'] is True

    def test_json_native_false_disables_script_scan(self):
        assert _load_config(_config_dict(script_scan=False), '/t')['script_scan'] is False

    def test_json_native_true_enables_banner_scan(self):
        assert _load_config(_config_dict(banner_scan=True), '/t')['banner_scan'] is True

    def test_json_native_false_disables_host_discovery(self):
        cfg = _load_config(_config_dict(host_discovery=False), '/t')
        assert cfg['host_discovery'] is False

    def test_json_native_false_resume_does_not_raise(self):
        # .strip() on a bool raised AttributeError before the coercion helper.
        assert _load_config(_config_dict(resume=False), '/t')['resume'] is False

    def test_json_native_true_resume(self):
        assert _load_config(_config_dict(resume=True), '/t')['resume'] is True

    def test_legacy_string_resume_still_works(self):
        assert _load_config(_config_dict(resume='False'), '/t')['resume'] is False

    def test_null_boolean_falls_back_to_default(self):
        cfg = _load_config(_config_dict(host_discovery=None, script_scan=None), '/t')
        assert cfg['host_discovery'] is True
        assert cfg['script_scan'] is False

    def test_unparseable_boolean_warns_and_uses_default(self, capsys):
        cfg = _load_config(_config_dict(host_discovery='maybe'), '/t')
        assert cfg['host_discovery'] is True
        out = capsys.readouterr().out
        assert 'host_discovery' in out
        assert 'not a boolean' in out

    # ---- numeric coercion --------------------------------------------------

    def test_max_rate_json_number_coerced_to_str(self):
        # _discover_external_masscan passes max_rate straight to Popen(), which
        # rejects an int with a bare TypeError.
        assert _load_config(_config_dict(max_rate=2000), '/t')['max_rate'] == '2000'

    def test_non_numeric_nmap_threads_warns_and_uses_default(self, capsys):
        cfg = _load_config(_config_dict(nmap_threads='lots'), '/t')
        assert cfg['nmap_threads'] == 5
        out = capsys.readouterr().out
        assert 'nmap_threads' in out
        assert 'not a number' in out

    def test_null_masscan_batch_size_warns_and_uses_default(self, capsys):
        cfg = _load_config(_config_dict(masscan_batch_size=None), '/t')
        assert cfg['masscan_batch_size'] == 5
        assert 'masscan_batch_size' in capsys.readouterr().out

    # ---- numeric floors (the interactive twin _prompt_int has always enforced
    # minimum=1; the config path enforced nothing) ---------------------------

    def test_zero_nmap_threads_is_clamped_to_one(self, capsys):
        # nmap_scan() does `for _ in range(max_threads)`, so 0 starts no workers
        # and work_queue.join() hangs forever — after discovery already ran.
        cfg = _load_config(_config_dict(nmap_threads=0), '/t')
        assert cfg['nmap_threads'] == 1
        out = capsys.readouterr().out
        assert 'nmap_threads' in out
        assert 'below the minimum' in out

    def test_negative_masscan_batch_size_is_clamped_to_one(self, capsys):
        # range(0, len(normal), 0) raises "range() arg 3 must not be zero",
        # unwinding main() mid-scan.
        cfg = _load_config(_config_dict(masscan_batch_size=-3), '/t')
        assert cfg['masscan_batch_size'] == 1
        assert 'masscan_batch_size' in capsys.readouterr().out

    def test_zero_nmap_threshold_is_clamped_to_one(self, capsys):
        cfg = _load_config(_config_dict(nmap_threshold=0), '/t')
        assert cfg['nmap_threshold'] == 1
        assert 'nmap_threshold' in capsys.readouterr().out

    def test_null_max_rate_warns_instead_of_crashing_mid_scan(self, capsys):
        # str(None) == 'None' used to reach int(max_rate) in
        # _discover_internal_masscan() as a raw ValueError traceback.
        cfg = _load_config(_config_dict(max_rate=None), '/t')
        assert cfg['max_rate'] == '2000'
        out = capsys.readouterr().out
        assert 'max_rate' in out
        assert 'not a number' in out

    def test_null_max_rate_default_follows_target_scan(self, capsys):
        cfg = _load_config(_config_dict(max_rate=None, target_scan='External'), '/t')
        assert cfg['max_rate'] == '20000'
        assert 'max_rate' in capsys.readouterr().out

    def test_zero_max_rate_is_clamped_not_passed_to_masscan(self, capsys):
        # '0' is truthy, so the `if not max_rate:` re-prompt never fired and
        # masscan ran at --max-rate 0.
        cfg = _load_config(_config_dict(max_rate=0), '/t')
        assert cfg['max_rate'] == '1'
        assert 'below the minimum' in capsys.readouterr().out

    # ---- required-key validation -------------------------------------------

    def test_missing_target_scan_reports_key_and_exits(self, capsys):
        cfg = _config_dict()
        del cfg['target_scan']
        with pytest.raises(SystemExit) as exc:
            _load_config(cfg, '/t')
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert 'target_scan' in out
        assert 'missing required key' in out

    def test_every_missing_key_named_in_one_message(self, capsys):
        # Not one crash at a time: all missing keys in a single message.
        with pytest.raises(SystemExit):
            _load_config({'target_scan': 'Internal'}, '/t')
        out = capsys.readouterr().out
        for key in ('banner_scan', 'max_rate', 'target_file', 'output_path'):
            assert key in out
        assert 'missing required keys' in out
        # config.json.sample is program data next to the module (_DIR), not
        # the operator's CWD, so the guidance must name a real path rather
        # than a bare filename an installed user has no hope of finding.
        assert f'{spoonmap._DIR}/config.json.sample' in out

    # ---- target_scan validation --------------------------------------------

    def test_lowercase_target_scan_is_normalised(self):
        # Unvalidated, "internal" matched neither literal: the scan ran and
        # looked normal while every target_scan == 'Internal' gated check (SMB
        # security mode, MS17-010, LDAP signing/channel binding, ms-sql-info,
        # the extra SQL port sweep) was silently skipped.
        assert _load_config(_config_dict(target_scan='internal'),
                            '/t')['target_scan'] == 'Internal'

    def test_padded_mixed_case_target_scan_is_normalised(self):
        assert _load_config(_config_dict(target_scan='  eXTERNAL '),
                            '/t')['target_scan'] == 'External'

    def test_unrecognised_target_scan_exits(self, capsys):
        with pytest.raises(SystemExit) as exc:
            _load_config(_config_dict(target_scan='inernal'), '/t')
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert 'target_scan' in out
        assert "'Internal' or 'External'" in out
        assert f'{spoonmap._DIR}/config.json.sample' in out

    def test_null_target_scan_exits_rather_than_scanning(self, capsys):
        with pytest.raises(SystemExit):
            _load_config(_config_dict(target_scan=None), '/t')
        assert 'target_scan' in capsys.readouterr().out


# ── _config_int ───────────────────────────────────────────────────────────────

class TestConfigInt:
    """_config_int() called directly, for the contract no current call site can
    reach: every one of the four passes a default at or above its minimum."""

    def test_non_numeric_input_clamps_the_fallback_default(self, capsys):
        # The whole point of `minimum` is that returning a smaller number breaks
        # the caller (nmap_threads=0 hangs work_queue.join(); batch_size=0 raises
        # out of range()). Clamping only the parsed value left the fallback path
        # able to return exactly the value the clamp exists to prevent.
        assert _config_int('nmap_threads', 'lots', 0, minimum=1) == 1
        assert 'nmap_threads' in capsys.readouterr().out

    def test_null_input_clamps_the_fallback_default(self, capsys):
        assert _config_int('masscan_batch_size', None, -5, minimum=1) == 1
        assert 'not a number' in capsys.readouterr().out

    def test_warning_reports_the_clamped_value_actually_used(self, capsys):
        _config_int('nmap_threads', 'lots', 0, minimum=3)
        # Reporting the raw default would name a value the run never used.
        assert 'using 3' in capsys.readouterr().out

    def test_default_at_or_above_minimum_is_returned_unchanged(self, capsys):
        assert _config_int('nmap_threads', 'lots', 5, minimum=1) == 5
        assert 'using 5' in capsys.readouterr().out

    def test_parsed_value_is_still_clamped(self, capsys):
        assert _config_int('nmap_threads', 0, 5, minimum=1) == 1
        assert 'below the minimum' in capsys.readouterr().out

    def test_valid_value_passes_through_without_a_warning(self, capsys):
        assert _config_int('nmap_threads', '8', 5, minimum=1) == 8
        assert capsys.readouterr().out == ''


# ── Config: Full scan_categories ──────────────────────────────────────────────

class TestConfigFullScanCategory:
    def _resolve(self, scan_categories):
        """Derive scan_type/dest_ports through the real config loader."""
        cfg = _load_config(_config_dict(scan_categories=scan_categories), '/t')
        return cfg['scan_type'], cfg['dest_ports']

    def test_full_string_sets_scan_type_and_ports(self):
        scan_type, dest_ports = self._resolve('Full')
        assert scan_type == 'Full'
        assert dest_ports == ['1-65535']

    def test_full_list_sets_scan_type_and_ports(self):
        scan_type, dest_ports = self._resolve(['Full'])
        assert scan_type == 'Full'
        assert dest_ports == ['1-65535']

    def test_full_yields_no_udp_ports(self):
        """Full is TCP-only: no U: entry reaches dest_ports, so no UDP discovery runs.

        _nmap_udp_discovery() is driven by [p for p in dest_ports if
        p.startswith('U:')], so an empty UDP slice here is what the docs promise.
        """
        _, dest_ports = self._resolve('Full')
        assert [p for p in dest_ports if p.startswith('U:')] == []

    def test_all_is_unaffected(self):
        scan_type, dest_ports = self._resolve('All')
        assert scan_type == 'All'
        assert '1-65535' not in dest_ports

    def test_all_does_cover_udp(self):
        """The counterpart to Full's TCP-only behaviour — All keeps the U: ports."""
        _, dest_ports = self._resolve('All')
        assert 'U:623' in dest_ports


# ── config source port derivation ────────────────────────────────────────────

class TestConfigSourcePort:
    """Config-file branch leaves source_port empty for either target_scan.

    The old '88' internal / '53' external source-port bypass is gone; the
    loader hardcodes '' so no --source-port is passed.
    """

    def _source_port_for(self, target_scan_value):
        """Read source_port out of the real config loader."""
        return _load_config(_config_dict(target_scan=target_scan_value), '/t')['source_port']

    def test_internal_scan_uses_no_source_port(self):
        assert self._source_port_for('Internal') == ''

    def test_external_scan_uses_no_source_port(self):
        assert self._source_port_for('External') == ''


# ── interactive config persistence ───────────────────────────────────────────

class TestBuildInteractiveConfig:
    """_build_interactive_config output must round-trip through the loader."""

    def _resolve(self, config):
        """Round-trip a written config through the real loader."""
        cfg = _load_config(config, '/t')
        return cfg['scan_type'], cfg['dest_ports']

    def _dest_ports_for(self, categories):
        all_ports = [p for name in categories for p in SERVICE_CATEGORIES[name]]
        return [p for p in all_ports if not p.startswith('U:')] + \
               [p for p in all_ports if p.startswith('U:')]

    def test_category_list_round_trips(self):
        selected = ['Web', 'Database']
        dest_ports = self._dest_ports_for(selected)
        cfg = _build_interactive_config(
            selected, dest_ports, 'Web, Database', True, False, 'Internal',
            '2000', '/t/ranges.txt', '/t/out', None, 5, 5, 5_000_000, True)
        assert cfg['scan_categories'] == selected
        assert 'dest_ports' not in cfg
        assert self._resolve(cfg) == ('Web, Database', dest_ports)

    def test_full_round_trips(self):
        cfg = _build_interactive_config(
            'Full', ['1-65535'], 'Full', True, False, 'External',
            '20000', '/t/r', '/t/o', None, 5, 5, 5_000_000, True)
        assert cfg['scan_categories'] == 'Full'
        assert self._resolve(cfg) == ('Full', ['1-65535'])

    def test_all_round_trips(self):
        dest_ports = [p for cat in SERVICE_CATEGORIES.values() for p in cat]
        cfg = _build_interactive_config(
            'All', dest_ports, 'All', True, False, 'Internal',
            '2000', '/t/r', '/t/o', None, 5, 5, 5_000_000, True)
        assert cfg['scan_categories'] == 'All'
        assert self._resolve(cfg)[0] == 'All'

    def test_custom_writes_dest_ports_not_categories(self):
        cfg = _build_interactive_config(
            None, ['80', '443', 'U:53'], 'Custom', True, False, 'External',
            '20000', '/t/r', '/t/o', None, 5, 5, 5_000_000, True)
        assert cfg['dest_ports'] == ['80', '443', 'U:53']
        assert 'scan_categories' not in cfg
        assert self._resolve(cfg) == ('Custom', ['80', '443', 'U:53'])

    def test_booleans_serialize_as_json_booleans_and_rate_as_a_string(self):
        """Booleans match config.json.sample's spelling (and what the generated
        file's own __*_choices__ notes advertise) rather than the quoted strings
        the sample used to carry; max_rate stays a string because
        _discover_external_masscan() hands it straight to Popen()."""
        cfg = _build_interactive_config(
            'All', [], 'All', True, False, 'Internal', 2000,
            'r', 'o', None, 5, 5, 5_000_000, False)
        assert cfg['banner_scan'] is True
        assert cfg['script_scan'] is False
        assert cfg['host_discovery'] is False
        assert cfg['max_rate'] == '2000'
        assert cfg['resume'] is False

    def test_generated_booleans_survive_a_json_round_trip(self, tmp_path):
        """The generated file is read back by main()'s loader, so the booleans
        must mean the same thing after json.dump/json.load as they did in the
        dict — this is the pairing that silently broke when the loader compared
        == 'True' and an operator wrote a JSON-native true."""
        cfg = _build_interactive_config(
            'All', [], 'All', True, True, 'Internal', '2000',
            '/t/r', '/t/o', None, 5, 5, 5_000_000, False)
        path = tmp_path / 'config.json'
        assert _write_interactive_config(str(path), cfg) is True
        reloaded = _load_config(json.loads(path.read_text()), '/t')
        assert reloaded['banner_scan'] is True
        assert reloaded['script_scan'] is True
        assert reloaded['host_discovery'] is False
        assert reloaded['resume'] is False

    def test_exclusions_none_becomes_empty_string(self):
        cfg = _build_interactive_config(
            'All', [], 'All', True, False, 'Internal', '2000',
            'r', 'o', None, 5, 5, 5_000_000, True)
        assert cfg['exclusions_file'] == ''

    def test_exclusions_path_preserved(self):
        cfg = _build_interactive_config(
            'All', [], 'All', True, False, 'Internal', '2000',
            'r', 'o', '/etc/excl.txt', 5, 5, 5_000_000, True)
        assert cfg['exclusions_file'] == '/etc/excl.txt'

    def test_numeric_fields_are_ints(self):
        cfg = _build_interactive_config(
            'All', [], 'All', True, False, 'Internal', '2000',
            'r', 'o', None, '7', '3', '1000000', True)
        assert cfg['nmap_threads'] == 7
        assert cfg['masscan_batch_size'] == 3
        assert cfg['nmap_threshold'] == 1_000_000

    def _cfg(self, **overrides):
        args = dict(
            scan_categories='All', dest_ports=[], scan_type='All', banner_scan=True,
            script_scan=False, target_scan='Internal', max_rate='2000',
            target_file='r', output_path='o', exclusions_file=None, nmap_threads=5,
            masscan_batch_size=5, nmap_threshold=5_000_000, host_discovery=True)
        args.update(overrides)
        return _build_interactive_config(*[args[k] for k in (
            'scan_categories', 'dest_ports', 'scan_type', 'banner_scan',
            'script_scan', 'target_scan', 'max_rate', 'target_file', 'output_path',
            'exclusions_file', 'nmap_threads', 'masscan_batch_size',
            'nmap_threshold', 'host_discovery')])

    def test_marker_key_written_first(self):
        cfg = self._cfg()
        assert list(cfg)[0] == _CONFIG_GENERATED_KEY
        assert 'Remove this key' in cfg[_CONFIG_GENERATED_KEY]

    def test_doc_keys_written_for_present_fields(self):
        cfg = self._cfg()
        for field, entries in _CONFIG_DOCS.items():
            if field not in cfg:
                continue
            for doc_key, doc_text in entries:
                assert cfg[doc_key] == doc_text

    def test_doc_key_precedes_its_field(self):
        keys = list(self._cfg())
        assert keys.index('__banner_scan_choices__') < keys.index('banner_scan')
        assert keys.index('__banner_scan_udp_warning__') < keys.index('banner_scan')
        assert keys.index('__target_scan_choices__') < keys.index('target_scan')

    def test_fields_follow_canonical_order(self):
        keys = [k for k in self._cfg() if not k.startswith('__')]
        expected = [k for k in _CONFIG_FIELD_ORDER if k in keys]
        assert keys == expected

    def test_custom_carries_dest_ports_docs_only(self):
        cfg = self._cfg(scan_categories=None, dest_ports=['80'], scan_type='Custom')
        assert '__dest_ports_note__' in cfg
        assert '__scan_categories_choices__' not in cfg

    def test_categories_carry_scan_categories_docs_only(self):
        cfg = self._cfg()
        assert '__scan_categories_choices__' in cfg
        assert '__dest_ports_note__' not in cfg

    def test_doc_keys_do_not_disturb_round_trip(self):
        """The loader must still resolve a documented config the same way."""
        selected = ['Web', 'Database']
        dest_ports = self._dest_ports_for(selected)
        cfg = self._cfg(scan_categories=selected, dest_ports=dest_ports,
                        scan_type='Web, Database')
        assert self._resolve(cfg) == ('Web, Database', dest_ports)


class TestConfigDocs:
    """_CONFIG_DOCS is the single source of truth; config.json.sample must agree.

    Both files document the same fields for the same users, so drift between
    them is a defect — edit the constant and the sample together.
    """

    @staticmethod
    def _sample():
        sample = Path(__file__).resolve().parent.parent / 'config.json.sample'
        with open(sample) as fh:
            return json.load(fh)

    def test_sample_parses(self):
        assert isinstance(self._sample(), dict)

    def test_every_constant_doc_key_matches_the_sample(self):
        sample = self._sample()
        for field, entries in _CONFIG_DOCS.items():
            for doc_key, doc_text in entries:
                assert doc_key in sample, f'{doc_key} missing from config.json.sample'
                assert sample[doc_key] == doc_text, f'{doc_key} text differs from the sample'

    def test_every_sample_doc_key_is_in_the_constant(self):
        known = {doc_key for entries in _CONFIG_DOCS.values() for doc_key, _ in entries}
        # The marker key is generated-only: the sample is hand-authored and must
        # not carry it, or a copied sample would re-open the prompts.
        sample_doc_keys = {k for k in self._sample() if k.startswith('__')}
        assert sample_doc_keys - known == set()

    def test_sample_has_no_generated_marker(self):
        assert _CONFIG_GENERATED_KEY not in self._sample()

    def test_scan_categories_choices_track_service_categories(self):
        choices = dict(_CONFIG_DOCS['scan_categories'])['__scan_categories_choices__']
        assert choices == 'All, Full, ' + ', '.join(SERVICE_CATEGORIES)

    def test_full_note_states_tcp_only_and_no_udp(self):
        """Full is TCP 1-65535 with no UDP discovery; the note must say so.

        The choices string lists Full alongside the categories, several of which
        are UDP-only — without this the name reads as a superset of All.
        """
        note = dict(_CONFIG_DOCS['scan_categories'])['__scan_categories_full_note__']
        assert 'TCP 1-65535 ONLY' in note
        assert 'no UDP discovery' in note

    def test_host_discovery_note_does_not_claim_a_source_port_probe(self):
        """source_port is unconditionally '' — the note described a removed feature."""
        note = dict(_CONFIG_DOCS['host_discovery'])['__host_discovery_note__']
        assert 'source port 53' not in note
        assert 'source port 88' not in note


class TestWriteInteractiveConfig:
    def test_writes_valid_json(self, tmp_path):
        path = str(tmp_path / 'config.json')
        cfg = {'banner_scan': 'True', 'target_scan': 'Internal'}
        assert _write_interactive_config(path, cfg) is True
        with open(path) as fh:
            assert json.load(fh) == cfg

    def test_returns_false_on_unwritable_path(self, tmp_path, capsys):
        path = str(tmp_path / 'nonexistent_dir' / 'config.json')
        assert _write_interactive_config(path, {'a': 'b'}) is False
        assert 'could not write' in capsys.readouterr().out

    def test_build_then_write_round_trips(self, tmp_path):
        selected = ['Web']
        all_ports = [p for name in selected for p in SERVICE_CATEGORIES[name]]
        dest_ports = [p for p in all_ports if not p.startswith('U:')] + \
                     [p for p in all_ports if p.startswith('U:')]
        cfg = _build_interactive_config(
            selected, dest_ports, 'Web', True, False, 'Internal', '2000',
            'r', 'o', None, 5, 5, 5_000_000, True)
        path = str(tmp_path / 'config.json')
        assert _write_interactive_config(path, cfg) is True
        with open(path) as fh:
            assert json.load(fh) == cfg

    def test_preserves_unknown_keys_from_existing_file(self, tmp_path):
        """A re-prompted run rewrites a file the user may have annotated."""
        path = str(tmp_path / 'config.json')
        with open(path, 'w') as fh:
            json.dump({'banner_scan': 'False', '__my_note__': 'keep me',
                       'future_key': 42}, fh)
        assert _write_interactive_config(path, {'banner_scan': 'True'}) is True
        with open(path) as fh:
            written = json.load(fh)
        assert written['banner_scan'] == 'True'      # ours wins
        assert written['__my_note__'] == 'keep me'   # theirs survives
        assert written['future_key'] == 42

    def test_written_keys_keep_their_order_ahead_of_preserved_ones(self, tmp_path):
        path = str(tmp_path / 'config.json')
        with open(path, 'w') as fh:
            json.dump({'__my_note__': 'n'}, fh)
        _write_interactive_config(path, {'a': 1, 'b': 2})
        with open(path) as fh:
            assert list(json.load(fh)) == ['a', 'b', '__my_note__']

    def test_unparseable_existing_file_is_replaced(self, tmp_path):
        path = str(tmp_path / 'config.json')
        with open(path, 'w') as fh:
            fh.write('{ not json')
        assert _write_interactive_config(path, {'banner_scan': 'True'}) is True
        with open(path) as fh:
            assert json.load(fh) == {'banner_scan': 'True'}

    def test_non_dict_existing_file_is_replaced(self, tmp_path):
        path = str(tmp_path / 'config.json')
        with open(path, 'w') as fh:
            json.dump(['a', 'list'], fh)
        assert _write_interactive_config(path, {'banner_scan': 'True'}) is True
        with open(path) as fh:
            assert json.load(fh) == {'banner_scan': 'True'}


# ── _atomic_write ─────────────────────────────────────────────────────────────

class TestAtomicWrite:
    """_atomic_write() replaces a file in one step, leaving no temp behind."""

    def test_creates_missing_file(self, tmp_path):
        p = tmp_path / 'f.txt'
        _atomic_write(str(p), 'hello')
        assert p.read_text() == 'hello'

    def test_overwrites_existing_file(self, tmp_path):
        p = tmp_path / 'f.txt'
        p.write_text('old')
        _atomic_write(str(p), 'new')
        assert p.read_text() == 'new'

    def test_no_temp_file_left_behind(self, tmp_path):
        p = tmp_path / 'f.txt'
        _atomic_write(str(p), 'data')
        assert [q.name for q in tmp_path.iterdir()] == ['f.txt']

    def test_temp_file_lands_in_same_directory(self, tmp_path):
        p = tmp_path / 'sub' / 'f.txt'
        p.parent.mkdir()
        seen = {}
        real_mkstemp = spoonmap.tempfile.mkstemp

        def _spy(**kwargs):
            seen['dir'] = kwargs['dir']
            return real_mkstemp(**kwargs)

        with patch('spoonmap.tempfile.mkstemp', side_effect=_spy):
            _atomic_write(str(p), 'data')
        assert seen['dir'] == str(tmp_path / 'sub')

    def test_bare_filename_writes_to_cwd(self, tmp_path):
        cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            _atomic_write('bare.txt', 'data')
        finally:
            os.chdir(cwd)
        assert (tmp_path / 'bare.txt').read_text() == 'data'

    def test_failed_replace_removes_temp_and_keeps_original(self, tmp_path):
        p = tmp_path / 'f.txt'
        p.write_text('old')
        with patch('spoonmap.os.replace', side_effect=OSError('boom')):
            with pytest.raises(OSError):
                _atomic_write(str(p), 'new')
        assert p.read_text() == 'old'
        assert [q.name for q in tmp_path.iterdir()] == ['f.txt']


# ── resume freshness (idempotent target write + staleness gates) ──────────────

class TestSafeMtime:
    def test_returns_mtime_of_existing_file(self, tmp_path):
        p = tmp_path / 'f.txt'
        p.write_text('x')
        os.utime(str(p), (1000, 1000))
        assert _safe_mtime(str(p)) == 1000

    def test_missing_file_reads_as_zero(self, tmp_path):
        # Also covers the TOCTOU case: a file removed between exists() and
        # getmtime() must read as stale instead of raising FileNotFoundError.
        assert _safe_mtime(str(tmp_path / 'gone.txt')) == 0


class TestSafeSize:
    def test_returns_size_of_existing_file(self, tmp_path):
        p = tmp_path / 'f.txt'
        p.write_text('abcd')
        assert _safe_size(str(p)) == 4

    def test_missing_file_reads_as_zero(self, tmp_path):
        assert _safe_size(str(tmp_path / 'gone.txt')) == 0

    def test_directory_reads_as_zero(self, tmp_path):
        # Directories have a non-zero st_size, so the isfile() guard the callers
        # used to make inline has to live in here.
        assert _safe_size(str(tmp_path)) == 0

    def test_stat_failure_reads_as_zero(self, tmp_path):
        # The exists()-then-stat race _safe_mtime() closes for mtimes: a file
        # removed (or a mount yanked) between the two calls must read as
        # unusable rather than raising out of a scan.
        p = tmp_path / 'f.txt'
        p.write_text('abcd')
        with patch('spoonmap.os.path.getsize', side_effect=OSError('gone')):
            assert _safe_size(str(p)) == 0


class TestResumeCacheUsable:
    """The content/freshness predicates, isolated from the coverage check.

    Every case here supplies a real target file and a matching coverage record,
    so a rejection can only come from the condition the test is named for.  Left
    unstamped, the gate would reject everything for a missing record and the
    "is usable" cases would be untestable.
    """

    def _target(self, tmp_path):
        t = tmp_path / 'targets.txt'
        t.write_text('10.0.0.1\n')
        return t

    def test_missing_output_is_not_usable(self, tmp_path):
        t = self._target(tmp_path)
        assert _resume_cache_usable(str(tmp_path / 'none.xml'), 0, 'thing',
                                    target_file=str(t), exclusions_file=None) is False

    def test_fresh_parseable_xml_is_usable(self, tmp_path):
        t = self._target(tmp_path)
        p = tmp_path / 'out.xml'
        p.write_text('<nmaprun/>')
        _write_target_stamp(p, t)
        os.utime(str(p), (2000, 2000))
        assert _resume_cache_usable(str(p), 1000, 'thing',
                                    target_file=str(t), exclusions_file=None) is True

    def test_stale_xml_is_not_usable(self, tmp_path, capsys):
        t = self._target(tmp_path)
        p = tmp_path / 'out.xml'
        p.write_text('<nmaprun/>')
        _write_target_stamp(p, t)
        os.utime(str(p), (1000, 1000))
        assert _resume_cache_usable(str(p), 2000, 'thing',
                                    target_file=str(t), exclusions_file=None) is False
        # Staleness is not an "unusable content" condition — no content warning.
        assert 'cached result was empty' not in capsys.readouterr().out

    def test_zero_length_xml_is_not_usable(self, tmp_path, capsys):
        t = self._target(tmp_path)
        p = tmp_path / 'out.xml'
        p.write_text('')
        _write_target_stamp(p, t)
        assert _resume_cache_usable(str(p), 0, 'port 445 discovery',
                                    target_file=str(t), exclusions_file=None) is False
        assert 're-running port 445 discovery' in capsys.readouterr().out

    def test_unparseable_xml_is_not_usable(self, tmp_path, capsys):
        t = self._target(tmp_path)
        p = tmp_path / 'out.xml'
        p.write_text('<nmaprun><host>')  # unclosed tags
        _write_target_stamp(p, t)
        assert _resume_cache_usable(str(p), 0, 'port 445 discovery',
                                    target_file=str(t), exclusions_file=None) is False
        assert 'cached result was empty' in capsys.readouterr().out

    def test_nonempty_text_output_is_usable(self, tmp_path):
        t = self._target(tmp_path)
        p = tmp_path / 'hosts.txt'
        p.write_text('10.0.0.1\n')
        _write_target_stamp(p, t)
        assert _resume_cache_usable(str(p), 0, 'thing', target_file=str(t),
                                    exclusions_file=None, is_xml=False) is True

    def test_empty_text_output_is_not_usable(self, tmp_path, capsys):
        t = self._target(tmp_path)
        p = tmp_path / 'hosts.txt'
        p.write_text('')
        _write_target_stamp(p, t)
        assert _resume_cache_usable(str(p), 0, 'host discovery', target_file=str(t),
                                    exclusions_file=None, is_xml=False) is False
        assert 're-running host discovery' in capsys.readouterr().out

    def test_text_predicate_not_applied_as_xml(self, tmp_path):
        # A .txt host list would always fail _parse_result_xml's suffix check;
        # is_xml=False must use the non-empty predicate instead.
        t = self._target(tmp_path)
        p = tmp_path / 'hosts.txt'
        p.write_text('10.0.0.1\n')
        _write_target_stamp(p, t)
        assert _parse_result_xml(str(p)) is None
        assert _resume_cache_usable(str(p), 0, 'thing', target_file=str(t),
                                    exclusions_file=None, is_xml=False) is True


class TestWriteIfChanged:
    def test_creates_missing_file(self, tmp_path):
        p = tmp_path / 'f.txt'
        assert _write_if_changed(str(p), 'hello') is True
        assert p.read_text() == 'hello'

    def test_preserves_mtime_when_unchanged(self, tmp_path):
        p = tmp_path / 'f.txt'
        p.write_text('same')
        os.utime(str(p), (1000, 1000))
        assert _write_if_changed(str(p), 'same') is False
        assert os.path.getmtime(str(p)) == 1000  # untouched

    def test_rewrites_and_bumps_mtime_when_changed(self, tmp_path):
        p = tmp_path / 'f.txt'
        p.write_text('old')
        os.utime(str(p), (1000, 1000))
        assert _write_if_changed(str(p), 'new') is True
        assert p.read_text() == 'new'
        assert os.path.getmtime(str(p)) > 1000


class TestPreprocessTargetsIdempotent:
    """resolved_targets.txt must keep its mtime when the target set is unchanged."""

    def test_unchanged_targets_preserve_mtime(self, tmp_path, capsys):
        target = tmp_path / 'ranges.txt'
        target.write_text('10.0.0.0/24\n192.168.1.1\n')
        out = tmp_path / 'out'
        preprocess_targets(str(target), str(out))
        resolved = out / 'discovery' / 'resolved_targets.txt'
        os.utime(str(resolved), (1000, 1000))
        preprocess_targets(str(target), str(out))
        assert os.path.getmtime(str(resolved)) == 1000

    def test_changed_targets_bump_mtime(self, tmp_path, capsys):
        target = tmp_path / 'ranges.txt'
        target.write_text('10.0.0.0/24\n')
        out = tmp_path / 'out'
        preprocess_targets(str(target), str(out))
        resolved = out / 'discovery' / 'resolved_targets.txt'
        os.utime(str(resolved), (1000, 1000))
        target.write_text('10.0.0.0/24\n192.168.5.5\n')
        preprocess_targets(str(target), str(out))
        assert os.path.getmtime(str(resolved)) > 1000
        assert '192.168.5.5' in resolved.read_text()


class TestPreprocessTargetsHostnames:
    """Hostname resolution branch of preprocess_targets()."""

    def test_blank_and_comment_lines_skipped(self, tmp_path):
        target = tmp_path / 'ranges.txt'
        target.write_text('\n# a comment\n10.0.0.1\n')
        out = tmp_path / 'out'
        _, ip_to_hostname = preprocess_targets(str(target), str(out))
        resolved = (out / 'discovery' / 'resolved_targets.txt').read_text()
        assert resolved.strip() == '10.0.0.1'
        assert ip_to_hostname == {}

    def test_resolvable_hostname_mapped_to_ip(self, tmp_path, capsys):
        target = tmp_path / 'ranges.txt'
        target.write_text('example.internal\n')
        out = tmp_path / 'out'
        with patch('spoonmap.resolve_hostname', return_value='10.0.0.9'):
            _, ip_to_hostname = preprocess_targets(str(target), str(out))
        assert ip_to_hostname == {'10.0.0.9': 'example.internal'}
        resolved = (out / 'discovery' / 'resolved_targets.txt').read_text()
        assert resolved.strip() == '10.0.0.9'
        assert 'example.internal -> 10.0.0.9' in capsys.readouterr().out

    def test_unresolvable_hostname_skipped(self, tmp_path, capsys):
        target = tmp_path / 'ranges.txt'
        target.write_text('bad.internal\n10.0.0.2\n')
        out = tmp_path / 'out'
        with patch('spoonmap.resolve_hostname', return_value=None):
            _, ip_to_hostname = preprocess_targets(str(target), str(out))
        assert ip_to_hostname == {}
        resolved = (out / 'discovery' / 'resolved_targets.txt').read_text()
        assert resolved.strip() == '10.0.0.2'
        assert 'Skipping bad.internal (resolution failed)' in capsys.readouterr().out


class TestHostDiscoveryResumeFreshness:
    def _setup(self, tmp_path):
        out = tmp_path / 'out'
        disc = out / 'discovery'
        disc.mkdir(parents=True)
        target = disc / 'resolved_targets.txt'
        target.write_text('10.0.0.1\n')
        cache = disc / 'live_hosts_discovery.txt'
        cache.write_text('10.0.0.1\n')
        _write_target_stamp(cache, target)
        return out, target, cache

    def test_fresh_cache_is_reused(self, tmp_path, capsys):
        out, target, cache = self._setup(tmp_path)
        os.utime(str(target), (1000, 1000))
        os.utime(str(cache), (2000, 2000))  # cache newer than targets
        with patch('spoonmap._internal_host_discovery') as m:
            result = _host_discovery(str(target), str(out), '1000', None,
                                     scan_type='Internal', resume=True)
        assert result == str(cache)
        assert not m.called
        assert 'skipping host discovery' in capsys.readouterr().out

    def test_stale_cache_triggers_rediscovery(self, tmp_path, capsys):
        out, target, cache = self._setup(tmp_path)
        os.utime(str(cache), (1000, 1000))   # cache older
        os.utime(str(target), (2000, 2000))  # targets newer → stale
        with patch('spoonmap._build_discovery_target_file',
                   return_value=(str(target), 1)), \
             patch('spoonmap._internal_host_discovery',
                   return_value={'10.9.9.9'}) as m:
            result = _host_discovery(str(target), str(out), '1000', None,
                                     scan_type='Internal', resume=True)
        assert m.called
        assert result == str(cache)
        assert '10.9.9.9' in cache.read_text()

    def test_empty_cache_triggers_rediscovery(self, tmp_path, capsys):
        # A discovery run that died before writing any host leaves a
        # zero-length live_hosts_discovery.txt; a fresh mtime must not make
        # that count as "discovery already done".
        out, target, cache = self._setup(tmp_path)
        cache.write_text('')
        os.utime(str(target), (1000, 1000))
        os.utime(str(cache), (2000, 2000))  # fresh, but empty
        with patch('spoonmap._build_discovery_target_file',
                   return_value=(str(target), 1)), \
             patch('spoonmap._internal_host_discovery',
                   return_value={'10.9.9.9'}) as m:
            result = _host_discovery(str(target), str(out), '1000', None,
                                     scan_type='Internal', resume=True)
        assert m.called
        assert result == str(cache)
        assert '10.9.9.9' in cache.read_text()
        assert 're-running host discovery' in capsys.readouterr().out

    def test_cache_deleted_after_exists_check_is_not_reused(self, tmp_path):
        # TOCTOU: the file vanishes between exists() and getmtime(); the gate
        # must treat it as stale rather than raising FileNotFoundError.
        out, target, cache = self._setup(tmp_path)
        os.utime(str(target), (1000, 1000))
        os.utime(str(cache), (2000, 2000))
        real_exists = os.path.exists

        def vanishing_exists(path):
            if path == str(cache) and os.path.lexists(path):
                os.unlink(path)
                return True
            return real_exists(path)

        with patch('spoonmap.os.path.exists', side_effect=vanishing_exists), \
             patch('spoonmap._build_discovery_target_file',
                   return_value=(str(target), 1)), \
             patch('spoonmap._internal_host_discovery',
                   return_value={'10.9.9.9'}) as m:
            result = _host_discovery(str(target), str(out), '1000', None,
                                     scan_type='Internal', resume=True)
        assert m.called
        assert result == str(cache)


class TestHostDiscoveryBranches:
    """_host_discovery() branches not covered by the resume-freshness tests."""

    def test_external_scan_type_calls_external_discovery(self, tmp_path):
        out = tmp_path / 'out'
        target = tmp_path / 'targets.txt'
        target.write_text('1.2.3.4\n')
        with patch('spoonmap._external_host_discovery', return_value={'1.2.3.4'}) as m_ext, \
             patch('spoonmap._internal_host_discovery') as m_int:
            result = _host_discovery(str(target), str(out), '10000', None, scan_type='External')
        assert m_ext.called
        assert not m_int.called
        assert result is not None

    def test_zero_live_hosts_returns_none_with_warning(self, tmp_path, capsys):
        out = tmp_path / 'out'
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        with patch('spoonmap._internal_host_discovery', return_value=set()):
            result = _host_discovery(str(target), str(out), '1000', None, scan_type='Internal')
        assert result is None
        assert 'found 0 live hosts' in capsys.readouterr().out

    def test_prefiltered_target_prints_message(self, tmp_path, capsys):
        out = tmp_path / 'out'
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        filtered_path = str(tmp_path / 'out' / 'discovery' / 'discovery_targets_filtered.txt')
        with patch('spoonmap._build_discovery_target_file',
                   return_value=(filtered_path, 128)), \
             patch('spoonmap._internal_host_discovery', return_value={'10.0.0.1'}):
            _host_discovery(str(target), str(out), '1000', None, scan_type='Internal')
        assert 'pre-filtered to 128 target IPs' in capsys.readouterr().out

    def test_non_ipv4_host_does_not_discard_completed_discovery(self, tmp_path):
        """The sort runs after the whole sweep finishes, so a ValueError here
        threw away every discovered host, not just the odd one."""
        out = tmp_path / 'out'
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        with patch('spoonmap._internal_host_discovery',
                   return_value={'10.0.0.2', '10.0.0.10', 'fe80::1'}):
            result = _host_discovery(str(target), str(out), '1000', None, scan_type='Internal')
        assert result is not None
        lines = Path(result).read_text().split()
        assert lines == ['10.0.0.2', '10.0.0.10', 'fe80::1']


class TestNmapUdpDiscoveryResumeFreshness:
    def _setup(self, tmp_path):
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        (disc / 'live_hosts').mkdir(parents=True)
        target = disc / 'resolved_targets.txt'
        target.write_text('10.0.0.1\n')
        xml = disc / 'masscan_results' / 'portU_53.xml'
        xml.write_text('<nmaprun/>')
        live = disc / 'live_hosts' / 'portU_53.txt'
        live.write_text('10.0.0.5\n')
        _write_target_stamp(xml, target)
        return target, xml, live

    def test_fresh_cache_reused_without_scanning(self, tmp_path):
        target, xml, live = self._setup(tmp_path)
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))  # cached XML newer than targets
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen:
            result = spoonmap._nmap_udp_discovery(
                'U:53', str(target), str(tmp_path), '', None, resume=True)
        assert result == {'10.0.0.5'}
        assert not mock_popen.called

    def test_stale_cache_triggers_rescan(self, tmp_path):
        target, xml, live = self._setup(tmp_path)
        fresh_xml = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="10.0.0.9" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="53">'
            '<state state="open"/></port></ports>'
            '</host></nmaprun>'
        )
        # Fresh content but a stale mtime: nmap (mocked) would rewrite the XML
        # *after* the freshness check, so the check must see the old mtime.
        xml.write_text(fresh_xml)
        os.utime(str(xml), (1000, 1000))
        os.utime(str(target), (2000, 2000))  # targets newer → stale
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            result = spoonmap._nmap_udp_discovery(
                'U:53', str(target), str(tmp_path), '', None, resume=True)
        assert mock_popen.called
        assert result == {'10.0.0.9'}

    _RESCAN_XML = (
        '<?xml version="1.0"?>'
        '<nmaprun><host>'
        '<address addr="10.0.0.9" addrtype="ipv4"/>'
        '<ports><port protocol="udp" portid="53">'
        '<state state="open"/></port></ports>'
        '</host></nmaprun>'
    )

    def _fake_popen_writing_results(self):
        def fake_popen(cmd, *args, **kwargs):
            with open(cmd[cmd.index('-oX') + 1], 'w') as fh:
                fh.write(self._RESCAN_XML)
            proc = MagicMock()
            proc.wait.return_value = 0
            return proc
        return fake_popen

    def test_zero_length_cached_xml_triggers_rescan(self, tmp_path, capsys):
        # An nmap killed before it flushed anything leaves an empty portU_53.xml;
        # a fresh mtime must not make that count as a completed UDP scan.
        target, xml, live = self._setup(tmp_path)
        xml.write_text('')
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))  # fresh, but empty
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen',
                   side_effect=self._fake_popen_writing_results()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            result = spoonmap._nmap_udp_discovery(
                'U:53', str(target), str(tmp_path), '', None, resume=True)
        assert mock_popen.called
        assert result == {'10.0.0.9'}
        assert 're-running UDP port 53 discovery' in capsys.readouterr().out

    def test_unparseable_cached_xml_triggers_rescan(self, tmp_path, capsys):
        target, xml, live = self._setup(tmp_path)
        xml.write_text('<nmaprun><host>')  # unclosed tags
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen',
                   side_effect=self._fake_popen_writing_results()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            result = spoonmap._nmap_udp_discovery(
                'U:53', str(target), str(tmp_path), '', None, resume=True)
        assert mock_popen.called
        assert result == {'10.0.0.9'}
        assert 're-running UDP port 53 discovery' in capsys.readouterr().out


# ── _handle_previous_results (delete / append / resume prompt) ────────────────

class TestPromptYesNo:
    def test_empty_uses_default_true(self):
        assert _prompt_yes_no('q', True, MagicMock(return_value='')) is True

    def test_empty_uses_default_false(self):
        assert _prompt_yes_no('q', False, MagicMock(return_value='')) is False

    def test_accepts_y_and_yes(self):
        assert _prompt_yes_no('q', False, MagicMock(return_value='y')) is True
        assert _prompt_yes_no('q', False, MagicMock(return_value='YES')) is True

    def test_accepts_n_and_no(self):
        assert _prompt_yes_no('q', True, MagicMock(return_value='n')) is False
        assert _prompt_yes_no('q', True, MagicMock(return_value='No')) is False

    def test_reprompts_on_invalid_then_accepts(self, capsys):
        # 'Ywa' (the reported bad input) must NOT be silently accepted; re-prompt.
        prompt = MagicMock(side_effect=['Ywa', 'maybe', 'y'])
        assert _prompt_yes_no('q', False, prompt) is True
        assert prompt.call_count == 3
        assert "Please answer" in capsys.readouterr().out

    def test_whitespace_only_uses_default(self):
        assert _prompt_yes_no('q', True, MagicMock(return_value='   ')) is True


class TestPromptInt:
    def test_empty_uses_default(self):
        assert _prompt_int('q', 5, prompt_fn=MagicMock(return_value='')) == 5

    def test_whitespace_only_uses_default(self):
        assert _prompt_int('q', 7, prompt_fn=MagicMock(return_value='  ')) == 7

    def test_default_coerced_to_int(self):
        # config.json may carry these as strings
        assert _prompt_int('q', '9', prompt_fn=MagicMock(return_value='')) == 9

    def test_accepts_valid_number(self):
        assert _prompt_int('q', 5, prompt_fn=MagicMock(return_value='12')) == 12

    def test_reprompts_on_non_numeric(self, capsys):
        prompt = MagicMock(side_effect=['abc', '3'])
        assert _prompt_int('q', 5, prompt_fn=prompt) == 3
        assert prompt.call_count == 2
        assert 'whole number' in capsys.readouterr().out

    def test_reprompts_below_minimum(self, capsys):
        prompt = MagicMock(side_effect=['0', '1'])
        assert _prompt_int('q', 5, minimum=1, prompt_fn=prompt) == 1
        assert prompt.call_count == 2
        assert 'at least 1' in capsys.readouterr().out


class TestPriorDefault:
    def test_prior_value_wins(self):
        assert _prior_default({'max_rate': '2000'}, 'max_rate', '20000') == '2000'

    def test_missing_key_falls_back(self):
        assert _prior_default({}, 'max_rate', '20000') == '20000'

    def test_none_empty_string_and_empty_list_fall_back(self):
        assert _prior_default({'k': None}, 'k', 'fb') == 'fb'
        assert _prior_default({'k': ''}, 'k', 'fb') == 'fb'
        assert _prior_default({'k': []}, 'k', 'fb') == 'fb'

    def test_false_is_preserved_not_replaced(self):
        """The reason this helper exists: a prior 'no' must survive a True
        fallback, which a plain `or` would silently discard."""
        assert _prior_default({'banner_scan': False}, 'banner_scan', True) is False
        assert _prior_default({'host_discovery': False}, 'host_discovery', True) is False

    def test_zero_is_preserved(self):
        assert _prior_default({'n': 0}, 'n', 5) == 0

    def test_non_empty_list_preserved(self):
        assert _prior_default({'p': ['80']}, 'p', []) == ['80']


class TestHandlePreviousResults:
    def test_no_previous_results_returns_resume_unchanged(self):
        prompt = MagicMock()
        with patch('spoonmap._previous_results_exist', return_value=False):
            assert _handle_previous_results('/out', False, prompt) == (False, 'none')
            assert _handle_previous_results('/out', True, prompt) == (True, 'none')
        prompt.assert_not_called()

    def test_resume_flag_skips_prompt(self):
        prompt = MagicMock()
        with patch('spoonmap._previous_results_exist', return_value=True):
            assert _handle_previous_results('/out', True, prompt) == (True, 'none')
        prompt.assert_not_called()

    def test_resume_choice_enables_resume_without_deleting(self):
        prompt = MagicMock(return_value='r')
        with patch('spoonmap._previous_results_exist', return_value=True), \
             patch('spoonmap._delete_previous_results') as del_mock:
            assert _handle_previous_results('/out', False, prompt) == (True, 'r')
        del_mock.assert_not_called()

    def test_delete_choice_removes_and_stays_off(self):
        prompt = MagicMock(return_value='d')
        with patch('spoonmap._previous_results_exist', return_value=True), \
             patch('spoonmap._delete_previous_results') as del_mock:
            assert _handle_previous_results('/out', False, prompt) == (False, 'd')
        del_mock.assert_called_once_with('/out')

    def test_append_choice_keeps_files_and_stays_off(self):
        prompt = MagicMock(return_value='a')
        with patch('spoonmap._previous_results_exist', return_value=True), \
             patch('spoonmap._delete_previous_results') as del_mock:
            assert _handle_previous_results('/out', False, prompt) == (False, 'a')
        del_mock.assert_not_called()

    def test_default_empty_input_is_append(self):
        prompt = MagicMock(return_value='')
        with patch('spoonmap._previous_results_exist', return_value=True), \
             patch('spoonmap._delete_previous_results') as del_mock:
            assert _handle_previous_results('/out', False, prompt) == (False, 'a')
        del_mock.assert_not_called()

    def test_invalid_input_reprompts_until_valid(self):
        prompt = MagicMock(side_effect=['x', 'nonsense', 'r'])
        with patch('spoonmap._previous_results_exist', return_value=True), \
             patch('spoonmap._delete_previous_results'):
            assert _handle_previous_results('/out', False, prompt) == (True, 'r')
        assert prompt.call_count == 3

    def test_choice_distinguishes_delete_from_append(self):
        """Both leave resume off, so main() needs the choice to know whether to
        re-open the option prompts."""
        with patch('spoonmap._previous_results_exist', return_value=True), \
             patch('spoonmap._delete_previous_results'):
            delete_resume, delete_choice = _handle_previous_results(
                '/out', False, MagicMock(return_value='delete'))
            append_resume, append_choice = _handle_previous_results(
                '/out', False, MagicMock(return_value='append'))
        assert delete_resume is append_resume is False
        assert (delete_choice, append_choice) == ('d', 'a')


# ── _read_config_file ─────────────────────────────────────────────────────────

class TestReadConfigFile:
    """config.json is written non-atomically, so a truncated file must not
    turn both normal startup and --cleanup into identical tracebacks."""

    def test_valid_object_is_returned(self, tmp_path):
        cfg = tmp_path / 'config.json'
        cfg.write_text('{"output_path": "/out"}')
        assert _read_config_file(str(cfg)) == {'output_path': '/out'}

    def test_malformed_json_reports_path_and_exits(self, tmp_path, capsys):
        cfg = tmp_path / 'config.json'
        cfg.write_text('{"output_path": "/out",}')  # trailing comma
        with pytest.raises(SystemExit) as exc:
            _read_config_file(str(cfg))
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert 'could not parse' in out
        assert str(cfg) in out

    def test_empty_file_reports_path_and_exits(self, tmp_path, capsys):
        cfg = tmp_path / 'config.json'
        cfg.write_text('')
        with pytest.raises(SystemExit) as exc:
            _read_config_file(str(cfg))
        assert exc.value.code == 1
        assert 'could not parse' in capsys.readouterr().out

    def test_unreadable_file_reports_path_and_exits(self, tmp_path, capsys):
        cfg = str(tmp_path / 'config.json')
        with patch('spoonmap.open', side_effect=PermissionError('Permission denied')):
            with pytest.raises(SystemExit) as exc:
                _read_config_file(cfg)
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert 'could not read' in out
        assert cfg in out

    def test_json_array_rejected_as_not_an_object(self, tmp_path, capsys):
        # A list has no .get(), so this would be an AttributeError later.
        cfg = tmp_path / 'config.json'
        cfg.write_text('[]')
        with pytest.raises(SystemExit) as exc:
            _read_config_file(str(cfg))
        assert exc.value.code == 1
        assert 'must contain a JSON object' in capsys.readouterr().out


# ── _cleanup_cmd ──────────────────────────────────────────────────────────────

class TestCleanupCmd:
    def _make_scan_data(self, tmp_path):
        """Populate tmp_path with representative scan output."""
        (tmp_path / 'nmap_results').mkdir()
        (tmp_path / 'nmap_results' / 'port445.xml').write_text('<nmaprun/>')
        (tmp_path / 'findings.txt').write_text('findings')
        (tmp_path / 'all_live_hosts.txt').write_text('10.0.0.1\n')

    def test_cleanup_with_explicit_path(self, tmp_path, capsys):
        self._make_scan_data(tmp_path)
        with patch('sys.argv', ['spoonmap.py', '--cleanup', str(tmp_path)]):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 0
        assert not (tmp_path / 'nmap_results').exists()
        assert not (tmp_path / 'findings.txt').exists()
        assert 'removed' in capsys.readouterr().out

    def test_cleanup_uses_config_json_path(self, tmp_path, capsys):
        out_dir = tmp_path / 'output'
        out_dir.mkdir()
        self._make_scan_data(out_dir)
        cfg = tmp_path / 'config.json'
        cfg.write_text(f'{{"output_path": "{out_dir}"}}')
        with patch('sys.argv', ['spoonmap.py', '--cleanup']):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 0
        assert not _previous_results_exist(str(out_dir))

    def test_cleanup_uses_relative_config_json_path(self, tmp_path, capsys):
        """A relative output_path in config.json is joined against dir_path."""
        out_dir = tmp_path / 'relative_output'
        out_dir.mkdir()
        self._make_scan_data(out_dir)
        cfg = tmp_path / 'config.json'
        cfg.write_text('{"output_path": "relative_output"}')
        with patch('sys.argv', ['spoonmap.py', '--cleanup']):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 0
        assert not _previous_results_exist(str(out_dir))

    def test_cleanup_with_malformed_config_reports_error(self, tmp_path, capsys):
        # --cleanup is the documented recovery command; a truncated config.json
        # must not make it fail with the same traceback as normal startup.
        (tmp_path / 'config.json').write_text('{"output_path":')
        with patch('sys.argv', ['spoonmap.py', '--cleanup']):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 1
        assert 'could not parse' in capsys.readouterr().out

    def test_cleanup_no_data_exits_cleanly(self, tmp_path, capsys):
        with patch('sys.argv', ['spoonmap.py', '--cleanup', str(tmp_path)]):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 0
        assert 'No scan data' in capsys.readouterr().out

    def test_cleanup_missing_dir_exits_error(self, tmp_path, capsys):
        missing = str(tmp_path / 'nonexistent')
        with patch('sys.argv', ['spoonmap.py', '--cleanup', missing]):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 1

    def test_cleanup_no_path_no_config_exits_error(self, tmp_path, capsys):
        with patch('sys.argv', ['spoonmap.py', '--cleanup']):
            with pytest.raises(SystemExit) as exc:
                _cleanup_cmd(str(tmp_path))
        assert exc.value.code == 1
        assert 'Usage' in capsys.readouterr().out

    def test_cleanup_removes_json_files(self, tmp_path, capsys):
        self._make_scan_data(tmp_path)
        (tmp_path / 'findings.json').write_text('[]')
        (tmp_path / 'spoonmap_output.json').write_text('[]')
        with patch('sys.argv', ['spoonmap.py', '--cleanup', str(tmp_path)]):
            with pytest.raises(SystemExit):
                _cleanup_cmd(str(tmp_path))
        assert not (tmp_path / 'findings.json').exists()
        assert not (tmp_path / 'spoonmap_output.json').exists()


class TestPathCompletion:
    """_path_completion(): readline tab-completion context manager."""

    def test_enables_and_resets_completer(self):
        with _path_completion():
            assert readline.get_completer() is not None
        assert readline.get_completer() is None

    def test_completer_matches_files_and_appends_slash_to_dirs(self, tmp_path):
        (tmp_path / 'report.txt').write_text('')
        (tmp_path / 'subdir').mkdir()
        with _path_completion():
            completer = readline.get_completer()
            prefix = str(tmp_path) + os.sep
            matches = []
            state = 0
            while True:
                m = completer(prefix, state)
                if m is None:
                    break
                matches.append(m)
                state += 1
        assert any(m.endswith('subdir' + os.sep) for m in matches)
        assert any(m.endswith('report.txt') for m in matches)

    def test_import_error_falls_back_silently(self):
        with patch.dict('sys.modules', {'readline': None}):
            with _path_completion():
                pass  # must not raise


# ── snmp-brute finding ────────────────────────────────────────────────────────

class TestSnmpBruteFinding:
    def test_snmp_brute_generates_finding_for_non_printer(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials\nprivate - Valid credentials'},
            service_attrs={'name': 'snmp', 'product': 'Net-SNMP'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' in content
        assert '10.0.0.5' in content

    def test_snmp_brute_community_strings_listed_in_detail(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials\nprivate - Valid credentials'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'public' in content
        assert 'private' in content

    def test_snmp_brute_suppressed_via_port_9100(self, nmap_dir):
        (nmap_dir / 'discovery' / 'live_hosts').mkdir(parents=True)
        (nmap_dir / 'discovery' / 'live_hosts' / 'port9100.txt').write_text('10.0.0.12\n')
        xml = _nmap_xml('10.0.0.12', 'udp', '161',
                        scripts={'snmp-brute': 'public - Valid credentials'})
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        assert 'SNMP Default Community String' not in (nmap_dir / 'findings.txt').read_text()

    def test_snmp_brute_no_valid_creds_no_finding(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - No response\nprivate - No response'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' not in content

    def test_snmp_brute_tcp_port_161_also_checked(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.7', 'tcp', '161',
            scripts={'snmp-brute': 'public - Valid credentials'},
        )
        (nmap_dir / 'nse_results' / 'port161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Default Community String' in content


class TestValidateSnmpAnyCommunity:
    """_validate_snmp_any_community(): confirms 'accepts any community' via a
    follow-up nmap probe using a random (never-configured) community string."""

    def _snmp_brute_xml(self, ip, valid_count):
        creds = '\n'.join(f'cred{i} - Valid credentials' for i in range(valid_count))
        return (
            '<?xml version="1.0"?><nmaprun><host>'
            f'<address addr="{ip}" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="161">'
            f'<script id="snmp-brute" output="{creds}"/>'
            '</port></ports></host></nmaprun>'
        )

    def test_confirmed_via_random_community_probe(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port161.xml').write_text(self._snmp_brute_xml('10.0.0.5', 5))

        mock_result = MagicMock()
        mock_result.stdout = 'Valid credentials'
        with patch('spoonmap.subprocess.run', return_value=mock_result) as mock_run:
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {'10.0.0.5': True}
        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index('--source-port') + 1] == '88'  # Internal → 88

    def test_external_scan_uses_source_port_53(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port161.xml').write_text(self._snmp_brute_xml('1.2.3.4', 5))

        mock_result = MagicMock()
        mock_result.stdout = 'Valid credentials'
        with patch('spoonmap.subprocess.run', return_value=mock_result) as mock_run:
            _validate_snmp_any_community(str(tmp_path), 'External')

        cmd = mock_run.call_args[0][0]
        assert cmd[cmd.index('--source-port') + 1] == '53'

    def test_below_threshold_not_probed(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port161.xml').write_text(self._snmp_brute_xml('10.0.0.6', 2))

        with patch('spoonmap.subprocess.run') as mock_run:
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {}
        assert not mock_run.called

    def test_random_community_not_confirmed_not_validated(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port161.xml').write_text(self._snmp_brute_xml('10.0.0.7', 5))

        mock_result = MagicMock()
        mock_result.stdout = 'no response'
        with patch('spoonmap.subprocess.run', return_value=mock_result):
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {}

    def test_malformed_xml_skipped(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port161.xml').write_text('<nmaprun><host>')  # unclosed tags

        with patch('spoonmap.subprocess.run') as mock_run:
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {}
        assert not mock_run.called

    def test_host_without_address_skipped(self, tmp_path):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<ports><port protocol="udp" portid="161">'
            '<script id="snmp-brute" output="a - Valid credentials\nb - Valid credentials'
            '\nc - Valid credentials\nd - Valid credentials\ne - Valid credentials"/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_results / 'port161.xml').write_text(xml)

        with patch('spoonmap.subprocess.run') as mock_run:
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {}
        assert not mock_run.called

    def test_timeout_expired_caught_and_warning_printed(self, tmp_path, capsys):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port161.xml').write_text(self._snmp_brute_xml('10.0.0.10', 5))

        with patch('spoonmap.subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='nmap', timeout=60)):
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {}
        output = capsys.readouterr().out
        assert '10.0.0.10' in output
        assert 'validation skipped' in output

    def test_file_not_found_error_caught_and_warning_printed(self, tmp_path, capsys):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        (nmap_results / 'port161.xml').write_text(self._snmp_brute_xml('10.0.0.11', 5))

        with patch('spoonmap.subprocess.run', side_effect=FileNotFoundError('nmap not found')):
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {}
        output = capsys.readouterr().out
        assert '10.0.0.11' in output
        assert 'validation skipped' in output

    def test_timeout_on_first_host_succeeds_on_second(self, tmp_path, capsys):
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.12" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="161">'
            '<script id="snmp-brute" output="a - Valid credentials\nb - Valid credentials'
            '\nc - Valid credentials\nd - Valid credentials\ne - Valid credentials"/>'
            '</port></ports></host>'
            '<host><address addr="10.0.0.13" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="161">'
            '<script id="snmp-brute" output="a - Valid credentials\nb - Valid credentials'
            '\nc - Valid credentials\nd - Valid credentials\ne - Valid credentials"/>'
            '</port></ports></host>'
            '</nmaprun>'
        )
        (nmap_results / 'port161.xml').write_text(xml)

        mock_result = MagicMock()
        mock_result.stdout = 'Valid credentials'
        with patch('spoonmap.subprocess.run',
                   side_effect=[subprocess.TimeoutExpired(cmd='nmap', timeout=60), mock_result]):
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {'10.0.0.13': True}
        assert '10.0.0.12' not in validated
        output = capsys.readouterr().out
        assert '10.0.0.12' in output
        assert 'validation skipped' in output

    def test_mac_address_is_not_used_as_the_scan_target(self, tmp_path):
        """The unfiltered find('address') took the first <address> child whatever
        its type.  On an ARP-resolved internal host that is the MAC, and this ip
        goes straight to nmap as a scan target — so the follow-up probe aimed at
        a MAC address.  The ipv4 child must win regardless of document order."""
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            '<address addr="10.0.0.21" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="161">'
            '<script id="snmp-brute" output="a - Valid credentials\nb - Valid credentials'
            '\nc - Valid credentials\nd - Valid credentials\ne - Valid credentials"/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_results / 'port161.xml').write_text(xml)

        mock_result = MagicMock()
        mock_result.stdout = 'Valid credentials'
        with patch('spoonmap.subprocess.run', return_value=mock_result) as mock_run:
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {'10.0.0.21': True}
        assert mock_run.call_args[0][0][-1] == '10.0.0.21'

    def test_host_with_no_ipv4_address_is_skipped(self, tmp_path):
        """An IPv6-only <host> has no usable IPv4 target, so it must be skipped
        rather than handing nmap a v6 literal this IPv4-only tool cannot scan."""
        nmap_results = tmp_path / 'nmap_results'
        nmap_results.mkdir()
        xml = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="fe80::1" addrtype="ipv6"/>'
            '<ports><port protocol="udp" portid="161">'
            '<script id="snmp-brute" output="a - Valid credentials\nb - Valid credentials'
            '\nc - Valid credentials\nd - Valid credentials\ne - Valid credentials"/>'
            '</port></ports></host></nmaprun>'
        )
        (nmap_results / 'port161.xml').write_text(xml)

        with patch('spoonmap.subprocess.run') as mock_run:
            validated = _validate_snmp_any_community(str(tmp_path), 'Internal')

        assert validated == {}
        assert not mock_run.called


# ── SNMP severity and detail tests ───────────────────────────────────────────

class TestSnmpSeverityAndDetail:
    def test_snmp_rw_on_network_device_is_critical(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={
                'snmp-brute': 'public - Valid credentials   (Access level: read-write)',
                'snmp-sysdescr': 'Cisco IOS Software, Version 15.7',
            },
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'CRITICAL' in content
        assert 'SNMP Default Community String' in content

    def test_snmp_rw_on_non_network_device_is_high(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={
                'snmp-brute': 'public - Valid credentials   (Access level: read-write)',
                'snmp-sysdescr': 'Linux Ubuntu 20.04 x86_64',
            },
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'HIGH' in content
        assert 'SNMP Default Community String' in content

    def test_snmp_ro_only_is_low(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials   (Access level: read-only)'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LOW' in content
        assert 'SNMP Default Community String' in content

    def test_snmp_accepts_any_rw_network_device_is_critical(self, nmap_dir):
        # Accepts-any severity follows the same tiering as default-community:
        # read-write on a network device is CRITICAL.
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={
                'snmp-brute': 'public - Valid credentials   (Access level: read-write)',
                'snmp-sysdescr': 'Cisco IOS Software, Version 15.7',
            },
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal',
                          snmp_any_validated={'10.0.0.5': True})
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Accepts Any Community String' in content
        assert 'CRITICAL' in content

    def test_snmp_accepts_any_read_only_is_low(self, nmap_dir):
        # Accepts-any but only read-only, non-network host -> LOW, not CRITICAL.
        xml = _nmap_xml(
            '10.0.0.6', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials   (Access level: read-only)'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal',
                          snmp_any_validated={'10.0.0.6': True})
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SNMP Accepts Any Community String' in content
        assert 'CRITICAL' not in content
        assert 'LOW' in content

    def test_snmp_printer_exclusion_note_in_detail(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={'snmp-brute': 'public - Valid credentials'},
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.md').read_text()
        assert 'printer' in content.lower()

    def test_snmp_sysdescr_in_detail(self, nmap_dir):
        xml = _nmap_xml(
            '10.0.0.5', 'udp', '161',
            scripts={
                'snmp-brute': 'public - Valid credentials',
                'snmp-sysdescr': 'Linux host 5.4.0 #1 SMP x86_64',
            },
        )
        (nmap_dir / 'nse_results' / 'portU:161.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.md').read_text()
        assert 'Linux host 5.4.0' in content


# ── INTERNAL_PORT_SCRIPTS includes snmp-brute ─────────────────────────────────

class TestInternalPortScriptsSnmp:
    def test_snmp_tcp_161_included(self):
        assert '161' in INTERNAL_PORT_SCRIPTS
        assert 'snmp-brute' in INTERNAL_PORT_SCRIPTS['161']
        assert 'snmp-sysdescr' in INTERNAL_PORT_SCRIPTS['161']

    def test_snmp_udp_161_included(self):
        assert 'U:161' in INTERNAL_PORT_SCRIPTS
        assert 'snmp-brute' in INTERNAL_PORT_SCRIPTS['U:161']
        assert 'snmp-sysdescr' in INTERNAL_PORT_SCRIPTS['U:161']


# ── _host_elem_to_dict ────────────────────────────────────────────────────────

class TestHostElemToDict:
    def _host_elem(self, ip, protocol='tcp', portid='80', state='open',
                   service_name='', product='', version='',
                   port_scripts=None, hostscripts=None):
        """Build a minimal <host> element for testing."""
        port_script_xml = ''.join(
            f'<script id="{sid}" output="{out}"/>'
            for sid, out in (port_scripts or {}).items()
        )
        hostscript_xml = ''
        if hostscripts:
            inner = ''.join(
                f'<script id="{sid}" output="{out}"/>'
                for sid, out in hostscripts.items()
            )
            hostscript_xml = f'<hostscript>{inner}</hostscript>'
        svc_xml = (f'<service name="{service_name}" product="{product}" version="{version}"/>'
                   if service_name or product or version else '')
        xml = (
            f'<host>'
            f'<address addr="{ip}" addrtype="ipv4"/>'
            f'<ports>'
            f'<port protocol="{protocol}" portid="{portid}">'
            f'<state state="{state}"/>'
            f'{svc_xml}'
            f'{port_script_xml}'
            f'</port>'
            f'</ports>'
            f'{hostscript_xml}'
            f'</host>'
        )
        return etree.fromstring(xml)

    def test_basic_port_parsed(self):
        elem = self._host_elem('10.0.0.1', protocol='tcp', portid='443', state='open')
        result = _host_elem_to_dict(elem)
        assert result['ip'] == '10.0.0.1'
        assert len(result['ports']) == 1
        p = result['ports'][0]
        assert p['protocol'] == 'tcp'
        assert p['portid'] == '443'
        assert p['state'] == 'open'

    def test_hostname_included_when_provided(self):
        elem = self._host_elem('10.0.0.2')
        result = _host_elem_to_dict(elem, ip_to_hostname={'10.0.0.2': 'host.example.com'})
        assert result['hostname'] == 'host.example.com'

    def test_hostname_omitted_when_not_in_map(self):
        elem = self._host_elem('10.0.0.3')
        result = _host_elem_to_dict(elem, ip_to_hostname={'10.0.0.99': 'other.example.com'})
        assert 'hostname' not in result

    def test_hostname_omitted_when_no_map(self):
        elem = self._host_elem('10.0.0.4')
        result = _host_elem_to_dict(elem)
        assert 'hostname' not in result

    def test_hostscripts_parsed(self):
        elem = self._host_elem('10.0.0.5', hostscripts={'smb2-security-mode': 'signing not required'})
        result = _host_elem_to_dict(elem)
        assert result['hostscripts'] == {'smb2-security-mode': 'signing not required'}

    def test_port_scripts_parsed(self):
        elem = self._host_elem('10.0.0.6', port_scripts={'ftp-anon': 'Anonymous FTP login allowed'})
        result = _host_elem_to_dict(elem)
        assert result['ports'][0]['scripts'] == {'ftp-anon': 'Anonymous FTP login allowed'}

    def test_service_fields_parsed(self):
        elem = self._host_elem('10.0.0.7', service_name='http', product='Apache', version='2.4')
        result = _host_elem_to_dict(elem)
        p = result['ports'][0]
        assert p['service'] == 'http'
        assert p['product'] == 'Apache'
        assert p['version'] == '2.4'

    def test_missing_ports_element_returns_empty_list(self):
        xml = '<host><address addr="10.0.0.8" addrtype="ipv4"/></host>'
        elem = etree.fromstring(xml)
        result = _host_elem_to_dict(elem)
        assert result['ports'] == []
        assert result['hostscripts'] == {}

    def test_port_script_without_id_skipped_not_fatal(self):
        # A <script> with no id= (truncated NSE output) must not raise KeyError;
        # this feeds the whole-run aggregation, so a raise loses all output.
        xml = (
            '<host><address addr="10.0.0.9" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="21"><state state="open"/>'
            '<script output="no id attribute"/>'
            '<script id="ftp-anon" output="Anonymous FTP login allowed"/>'
            '</port></ports></host>'
        )
        result = _host_elem_to_dict(etree.fromstring(xml))
        assert result['ports'][0]['scripts'] == {'ftp-anon': 'Anonymous FTP login allowed'}

    def test_hostscript_without_id_skipped_not_fatal(self):
        xml = (
            '<host><address addr="10.0.0.10" addrtype="ipv4"/>'
            '<hostscript>'
            '<script output="no id attribute"/>'
            '<script id="smb2-security-mode" output="signing not required"/>'
            '</hostscript></host>'
        )
        result = _host_elem_to_dict(etree.fromstring(xml))
        assert result['hostscripts'] == {'smb2-security-mode': 'signing not required'}


# ── TestMassScanProbe ─────────────────────────────────────────────────────────

class TestMassScanProbe:
    """Tests for the adaptive probe logic inside mass_scan()."""

    def _make_batch_side_effect(self, responses):
        """Return a side_effect callable that yields successive response dicts."""
        call_iter = iter(responses)
        def side_effect(*args, **kwargs):
            return next(call_iter)
        return side_effect

    # ── batch_size=1 cases ───────────────────────────────────────────────────

    def test_batch1_fast_finds_hosts_on_first_port(self, tmp_path):
        """fast call hits on first probe port → 1 probe call + 1 main batch, rate unchanged."""
        spoonmap.output_path = str(tmp_path)
        # External scan: EXTERNAL_PROBE_PORT_PRIORITY = ['443','80','8080','8443']
        # dest_ports=['443','3306'] → probe_ports=['443'], remaining=['3306']
        # (3306 is not in EXTERNAL_PROBE_PORT_PRIORITY so it stays in remaining)
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 — hit
            {},                       # main batch for port 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            result = mass_scan('All', ['443', '3306'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        # 2 calls: probe_fast_0 + 1 main batch
        assert mock_b.call_count == 2
        first_call_xml = mock_b.call_args_list[0][0][2]
        assert 'probe_fast_0' in first_call_xml
        assert 'Hosts Found on Port 443' in result

    def test_batch1_fast_zero_slow_finds_hosts(self, tmp_path):
        """fast=0, slow hits → effective_rate switched to half_rate."""
        spoonmap.output_path = str(tmp_path)
        # External: dest_ports=['443','3306'] → probe=['443'], remaining=['3306']
        responses = [
            {},                        # probe_fast_0 (443) — miss
            {'443': {'10.0.0.5'}},    # probe_slow_0 (443) — hit
            {},                        # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            result = mass_scan('All', ['443', '3306'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        assert mock_b.call_count == 3
        # probe_slow_0 must use half_rate (5000)
        slow_call = mock_b.call_args_list[1]
        assert slow_call[0][1] == '5000'
        assert 'probe_slow_0' in slow_call[0][2]
        assert 'Hosts Found on Port 443' in result

    def test_batch2_selects_two_probe_ports(self, tmp_path):
        """batch_size=2: two probe ports selected; both appear in legacy probe calls."""
        spoonmap.output_path = str(tmp_path)
        # Internal scan: PROBE_PORT_PRIORITY starts with 443, 445
        # dest_ports=['443','445','3306'] → probe=['443','445'], remaining=['3306']
        # 445 is in SLOW_PORTS so it gets a solo batch after missing the probe
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast(['443','445']) — hit on 443
            {},                       # probe_slow(['443','445']) — miss
            {},                       # main batch ['3306'] (normal)
            {},                       # main batch ['445'] (slow-port solo, re-queued after probe miss)
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            mass_scan('All', ['443', '445', '3306'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=2)

        probe_call = mock_b.call_args_list[0]
        probed_ports = set(probe_call[0][0])
        assert '443' in probed_ports
        assert '445' in probed_ports
        assert len(probed_ports) == 2

    def test_batch1_all_probe_ports_miss(self, tmp_path):
        """All probe ports return 0 hosts → for-else fires, rate unchanged."""
        spoonmap.output_path = str(tmp_path)
        # Internal: dest_ports=['443','3306'] → probe=['443'], remaining=['3306']
        # (3306 not in PROBE_PORT_PRIORITY)
        responses = [
            {},   # probe_fast_0 (443) — miss
            {},   # probe_slow_0 (443) — miss
            {},   # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            mass_scan('All', ['443', '3306'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=1)

        # 2 probe calls + 1 main batch call
        assert mock_b.call_count == 3
        # Main batch call must use max_rate (no rate reduction)
        main_batch_call = mock_b.call_args_list[2]
        assert main_batch_call[0][1] == '1000'

    def test_non_ipv4_probe_hit_does_not_abort_the_scan(self, tmp_path):
        """The combined-target sort runs mid-mass_scan, between the probe and the
        remaining port batches, so a ValueError killed the run outright."""
        spoonmap.output_path = str(tmp_path)
        responses = [
            {'443': {'10.0.0.10', '10.0.0.2', 'fe80::1'}},  # probe_fast_0 — hit
            {},                                              # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            result = mass_scan('All', ['443', '3306'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        assert mock_b.call_count == 2
        assert 'Hosts Found on Port 443' in result
        combined = tmp_path / 'discovery' / 'live_hosts_combined.txt'
        assert combined.read_text().split() == ['10.0.0.2', '10.0.0.10', 'fe80::1']

    # ── probe/cache union on resume ──────────────────────────────────────────

    def test_probe_unions_with_cached_live_hosts_file(self, tmp_path):
        """A re-probe that finds fewer hosts than the cached file must not delete
        the difference.  The probe has no resume gate, so every resumed run
        re-probes; it probes the narrower probe_target and its packet loss varies,
        so returning a subset of the cached hosts is normal.  Overwriting
        live_hosts/portN.txt with only the probe's hits lost confirmed hosts from
        all_live_hosts.txt and from the nmap banner phase's input."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n10.0.0.2\n10.0.0.3\n')

        responses = [
            {'443': {'10.0.0.2'}},   # probe_fast_0 — hit, but only 1 of the 3
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            result = mass_scan('All', ['443', '3306'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        written = (live_hosts / 'port443.txt').read_text().split()
        assert sorted(written) == ['10.0.0.1', '10.0.0.2', '10.0.0.3']
        assert 'Hosts Found on Port 443: 3' in result

    def test_probe_only_hosts_added_to_cached_live_hosts_file(self, tmp_path):
        """The union is in both directions: a host the probe found for the first
        time is added to the cached file rather than discarded."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n')

        responses = [
            {'443': {'10.0.0.7'}},   # probe_fast_0 — a host not in the cache
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)

        written = (live_hosts / 'port443.txt').read_text().split()
        assert sorted(written) == ['10.0.0.1', '10.0.0.7']

    def test_probe_miss_does_not_truncate_cached_live_hosts_file(self, tmp_path):
        """A probe that finds nothing at either rate must leave the cached file
        alone.  This is the worst version of the bug: an empty probe result set
        wrote an empty (or absent) port file over a full one."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n10.0.0.2\n')

        responses = [
            {},   # probe_fast_0 (443) — miss
            {},   # probe_slow_0 (443) — miss
            {},   # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)

        written = (live_hosts / 'port443.txt').read_text().split()
        assert sorted(written) == ['10.0.0.1', '10.0.0.2']

    def test_batch_size_gt1_probe_unions_with_cached_live_hosts_file(self, tmp_path):
        """The legacy two-call probe path shares the same write loop, so it must
        union with the cache too."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n10.0.0.4\n')

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast
            {'443': {'10.0.0.1'}},   # probe_slow — no new IPs
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '80', '3306'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=2)

        written = (live_hosts / 'port443.txt').read_text().split()
        assert sorted(written) == ['10.0.0.1', '10.0.0.4']

    # ── cached hosts folded into the combined batch target ───────────────────

    def _write_scope(self, tmp_path, body='10.0.0.0/24\n'):
        """Write a real target file so target_file defines a parseable scope."""
        target_file = tmp_path / 'targets.txt'
        target_file.write_text(body)
        return str(target_file)

    def test_cached_hosts_are_scanned_by_the_remaining_batches(self, tmp_path):
        """host_discovery=False resume: with no discovery_file, the combined
        target used to be this run's probe hits alone, so a cached host was
        retained in live_hosts/portN.txt (and all_live_hosts.txt) while never
        being scanned for any remaining port — output claiming coverage the scan
        never performed."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n10.0.0.2\n10.0.0.3\n')
        target_file = self._write_scope(tmp_path)

        responses = [
            {'443': {'10.0.0.2'}},   # probe_fast_0 — only one of the three
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            mass_scan('All', ['443', '3306'], '53', '10000',
                      target_file, '', batch_size=1, resume=True)

        combined_path = tmp_path / 'discovery' / 'live_hosts_combined.txt'
        assert sorted(combined_path.read_text().split()) == [
            '10.0.0.1', '10.0.0.2', '10.0.0.3']
        # The remaining-port batch must actually be pointed at that list.
        assert mock_b.call_args_list[1][0][3] == str(combined_path)

    def test_cached_hosts_outside_current_scope_are_not_scanned(self, tmp_path):
        """Nothing prunes live_hosts/ when ranges.txt narrows, so a cached file
        can hold hosts from a previous, wider engagement. Those must never reach
        masscan as targets — scanning out of scope is worse than under-scanning."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        # Both are leftovers from a previous, wider scope: one sorting above
        # every current range and one below, which are separate paths through
        # the bisect in _ip_in_ranges().
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n10.99.0.7\n9.1.1.1\n')
        target_file = self._write_scope(tmp_path, '10.0.0.0/24\n')

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      target_file, '', batch_size=1, resume=True)

        combined = (tmp_path / 'discovery' / 'live_hosts_combined.txt').read_text()
        assert combined.split() == ['10.0.0.1']
        assert '10.99.0.7' not in combined
        assert '9.1.1.1' not in combined
        # They keep their place in the retained host list — this gates scanning,
        # not keeping.
        retained = (live_hosts / 'port443.txt').read_text()
        assert '10.99.0.7' in retained
        assert '9.1.1.1' in retained

    def test_narrowed_scope_warns_about_retained_out_of_scope_hosts(self, tmp_path, capsys):
        """A narrowed ranges.txt on a resumed run must *say* that cached hosts
        outside the new scope are still in the output, and must still write them.

        Both halves matter. all_live_hosts.txt and spoonmap_output.* feed
        engagement deliverables, so an out-of-scope host sitting there unannounced
        is one an operator may report on or pivot to believing it was authorised —
        that is where a rules-of-engagement violation starts. But deleting
        confirmed results is the failure mode this whole area exists to prevent,
        so the fix is disclosure, never pruning.
        """
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        # Four leftovers from a previous /8 engagement, one in the current scope.
        (live_hosts / 'port443.txt').write_text(
            '10.0.0.1\n10.99.0.7\n10.99.0.8\n10.99.0.9\n10.99.0.10\n')
        target_file = self._write_scope(tmp_path, '10.0.0.0/24\n')

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      target_file, '', batch_size=1, resume=True)

        out = capsys.readouterr().out
        assert '4 retained host(s) are OUTSIDE the current target scope' in out
        assert 'NOT scanned this run' in out
        assert '10.99.0.7' in out          # a named example
        assert '(+1 more)' in out          # 4 found, 3 shown
        assert '[d]elete' in out           # operator's delete options
        assert '--cleanup' in out

        # ...and every one of them is still retained, per-port and in the
        # combined deliverable.
        retained = (live_hosts / 'port443.txt').read_text().split()
        assert sorted(retained) == ['10.0.0.1', '10.99.0.10', '10.99.0.7',
                                    '10.99.0.8', '10.99.0.9']
        _combine_live_hosts(str(tmp_path / 'discovery'), str(tmp_path))
        combined_output = (tmp_path / 'all_live_hosts.txt').read_text().split()
        assert sorted(combined_output) == sorted(retained)
        # But they were never handed to masscan as targets.
        batch_target = (tmp_path / 'discovery' / 'live_hosts_combined.txt').read_text()
        assert batch_target.split() == ['10.0.0.1']

    def test_no_warning_when_every_retained_host_is_in_scope(self, tmp_path, capsys):
        """The warning must not cry wolf on an ordinary resumed scan."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n10.0.0.2\n')
        target_file = self._write_scope(tmp_path, '10.0.0.0/24\n')

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      target_file, '', batch_size=1, resume=True)

        assert 'OUTSIDE the current target scope' not in capsys.readouterr().out

    def test_non_ipv4_cached_entry_is_not_folded_and_does_not_raise(self, tmp_path):
        """A hostname or IPv6 literal that leaked into a resume file must read as
        out of scope rather than crash the scope check."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\nfe80::1\nweb1.corp.local\n')
        target_file = self._write_scope(tmp_path)

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      target_file, '', batch_size=1, resume=True)

        combined = (tmp_path / 'discovery' / 'live_hosts_combined.txt').read_text()
        assert '10.0.0.1' in combined
        assert 'fe80::1' not in combined
        assert 'web1.corp.local' not in combined

    def test_fold_reports_how_many_cached_hosts_were_added(self, tmp_path, capsys):
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n10.0.0.2\n10.0.0.3\n')
        target_file = self._write_scope(tmp_path)

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 — 2 cached hosts are new
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      target_file, '', batch_size=1, resume=True)

        assert 'added 2 cached host(s)' in capsys.readouterr().out

    def test_no_cached_hosts_means_no_fold_message(self, tmp_path, capsys):
        """Nothing cached beyond the probe's own hits — the combined target is
        unchanged and the fold stays quiet."""
        spoonmap.output_path = str(tmp_path)
        target_file = self._write_scope(tmp_path)

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      target_file, '', batch_size=1)

        out = capsys.readouterr().out
        assert 'cached host(s)' not in out
        combined = (tmp_path / 'discovery' / 'live_hosts_combined.txt').read_text()
        assert combined.split() == ['10.0.0.1']

    def test_unparseable_target_file_folds_nothing(self, tmp_path):
        """No parseable scope means no way to prove a cached host is in scope, so
        nothing is folded — the pre-existing behaviour, and the safe direction."""
        spoonmap.output_path = str(tmp_path)
        live_hosts = tmp_path / 'discovery' / 'live_hosts'
        live_hosts.mkdir(parents=True)
        (live_hosts / 'port443.txt').write_text('10.0.0.1\n10.0.0.9\n')

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1, resume=True)

        combined = (tmp_path / 'discovery' / 'live_hosts_combined.txt').read_text()
        assert combined.split() == ['10.0.0.1']

    # ── batch_size > 1 (legacy two-call probe) ───────────────────────────────

    def test_batch5_uses_legacy_two_call_probe(self, tmp_path):
        """batch_size=5: first 2 calls use probe_fast.xml / probe_slow.xml filenames."""
        spoonmap.output_path = str(tmp_path)
        # External: EXTERNAL_PROBE_PORT_PRIORITY=['443','80','8080','8443']
        # probe_ports=['443','80','8080'] (first 5 from priority intersect dest)
        # remaining_ports=['22','25','135'] (not in EXTERNAL_PROBE_PORT_PRIORITY)
        dest_ports = ['443', '80', '8080', '22', '25', '135']
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast
            {'443': {'10.0.0.1'}},   # probe_slow (same IPs → no new_ips)
            {},                       # main batch ['22', '25', '135']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            mass_scan('All', dest_ports, '53', '10000',
                      '/fake/targets.txt', '', batch_size=5)

        assert 'probe_fast.xml' in mock_b.call_args_list[0][0][2]
        assert 'probe_slow.xml' in mock_b.call_args_list[1][0][2]

    def test_batch_size_gt1_new_ips_in_slow_probe_switches_to_half_rate(self, tmp_path):
        """batch_size>1: probe_slow finds hosts probe_fast missed → subsequent
        batches run at the reduced (half) rate."""
        spoonmap.output_path = str(tmp_path)
        # External: probe_ports=['443','80'] (both non-SLOW), remaining=['3306']
        responses = [
            {'443': {'10.0.0.1'}},                        # probe_fast
            {'443': {'10.0.0.1'}, '80': {'10.0.0.2'}},    # probe_slow — new_ips={'10.0.0.2'}
            {},                                             # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b:
            mass_scan('All', ['443', '80', '3306'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=2)

        main_batch_call = mock_b.call_args_list[2]
        assert main_batch_call[0][1] == '5000'  # half of 10000

    def test_discovery_file_ips_merged_into_combined_target(self, tmp_path):
        """batch_size=1: discovery_file IPs are unioned with probe-found IPs
        into live_hosts_combined.txt for the remaining-port batches."""
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        disc.mkdir(parents=True)
        discovery_file = disc / 'live_hosts_discovery.txt'
        discovery_file.write_text('10.0.0.1\n10.0.0.9\n')

        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 — hit, breaks probe loop
            {},                       # main batch ['3306']
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1,
                      discovery_file=str(discovery_file))

        combined = (disc / 'live_hosts_combined.txt').read_text()
        assert '10.0.0.1' in combined
        assert '10.0.0.9' in combined  # only in discovery_file, not probe results

    def test_unwritable_combined_target_falls_back_to_full_target_file(self, tmp_path, capsys):
        """The combined list is the masscan -iL target for every remaining
        batch, so a failed write (ENOSPC) must not raise out of mass_scan() and
        lose the whole run's aggregation — the batches fall back to the full
        target file, which over-scans rather than silently under-scanning."""
        spoonmap.output_path = str(tmp_path)
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 — hit
            {},                       # main batch ['3306']
        ]
        real_atomic_write = spoonmap._atomic_write

        def fail_only_combined(path, content):
            # The per-port live_hosts writes must still land; only the combined
            # target list is out of disk space.
            if path.endswith('live_hosts_combined.txt'):
                raise OSError('No space left on device')
            return real_atomic_write(path, content)

        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b, \
             patch('spoonmap._atomic_write', side_effect=fail_only_combined):
            result = mass_scan('All', ['443', '3306'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        assert 'Hosts Found on Port 443' in result
        # target_file positional arg of the remaining-port batch call
        assert mock_b.call_args_list[1][0][3] == '/fake/targets.txt'
        assert 'could not write combined target list' in capsys.readouterr().out

    def test_non_oserror_combined_target_write_failure_also_falls_back(self, tmp_path, capsys):
        """_atomic_write() re-raises whatever it caught after cleaning up, so
        narrowing this handler to OSError left any other failure unwinding
        mass_scan() and losing the whole run's aggregation — exactly the outcome
        the fallback exists to prevent."""
        spoonmap.output_path = str(tmp_path)
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 — hit
            {},                       # main batch ['3306']
        ]
        real_atomic_write = spoonmap._atomic_write

        def fail_only_combined(path, content):
            if path.endswith('live_hosts_combined.txt'):
                raise RuntimeError('rename hook exploded')
            return real_atomic_write(path, content)

        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)) as mock_b, \
             patch('spoonmap._atomic_write', side_effect=fail_only_combined):
            result = mass_scan('All', ['443', '3306'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        assert 'Hosts Found on Port 443' in result
        assert mock_b.call_args_list[1][0][3] == '/fake/targets.txt'
        assert 'could not write combined target list' in capsys.readouterr().out

    def test_keyboardinterrupt_during_combined_target_write_still_propagates(self, tmp_path):
        """The widened handler must not swallow Ctrl-C: an interrupt here means
        stop the scan, not carry on against the full (larger) target file."""
        spoonmap.output_path = str(tmp_path)
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 — hit
            {},                       # main batch ['3306']
        ]
        real_atomic_write = spoonmap._atomic_write

        def interrupt_only_combined(path, content):
            if path.endswith('live_hosts_combined.txt'):
                raise KeyboardInterrupt
            return real_atomic_write(path, content)

        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)), \
             patch('spoonmap._atomic_write', side_effect=interrupt_only_combined):
            with pytest.raises(KeyboardInterrupt):
                mass_scan('All', ['443', '3306'], '53', '10000',
                          '/fake/targets.txt', '', batch_size=1)

    # ── scan-type-aware probe port selection ─────────────────────────────────

    def test_external_scan_uses_web_probe_ports_only(self, tmp_path):
        """source_port=53 (External) → probe prefers EXTERNAL_PROBE_PORT_PRIORITY ports."""
        spoonmap.output_path = str(tmp_path)
        # batch_size=1: dest=['443','80','445','22'] → probe=['443'], remaining=['80','445','22']
        dest_ports = ['443', '80', '445', '22']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)

        probe_calls = [
            call for call in mock_b.call_args_list
            if 'probe_fast' in call[0][2] or 'probe_slow' in call[0][2]
        ]
        probed_ports = {p for call in probe_calls for p in call[0][0]}
        # With batch_size=1, only one probe port; it must be the top priority match
        assert probed_ports == {'443'}

    def test_internal_scan_uses_full_probe_priority(self, tmp_path):
        """source_port=88 (Internal) → probe ports drawn from full PROBE_PORT_PRIORITY."""
        spoonmap.output_path = str(tmp_path)
        # 445 is in PROBE_PORT_PRIORITY but NOT in EXTERNAL_PROBE_PORT_PRIORITY
        # batch_size=2: dest_ports=['443','445','3306'] → probe=['443','445'], remaining=['3306']
        # (3306 not in PROBE_PORT_PRIORITY)
        dest_ports = ['443', '445', '3306']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=2)

        probe_calls = [
            call for call in mock_b.call_args_list
            if 'probe_fast' in call[0][2] or 'probe_slow' in call[0][2]
        ]
        probed_ports = {p for call in probe_calls for p in call[0][0]}
        # 443 is first in PROBE_PORT_PRIORITY so it must be probed
        assert '443' in probed_ports
        # 445 is in PROBE_PORT_PRIORITY but not EXTERNAL_PROBE_PORT_PRIORITY
        assert '445' in probed_ports

    # ── wait_secs forwarding ──────────────────────────────────────────────────

    def test_wait_secs_forwarded_to_all_batch_calls(self, tmp_path):
        """_calc_scan_wait result is passed as wait_secs= to every _run_masscan_batch call."""
        spoonmap.output_path = str(tmp_path)
        # Write a real target file so _count_hosts_in_file returns a known count.
        # 256 hosts (/24) at 1000 pps → _calc_scan_wait returns 29.
        target_file = str(tmp_path / 'targets.txt')
        with open(target_file, 'w') as f:
            f.write('10.0.0.0/24\n')

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['443', '3306'], '88', '1000',
                      target_file, '', batch_size=1)

        # Every call must carry wait_secs=29
        for call in mock_b.call_args_list:
            assert call[1].get('wait_secs') == 29

    # ── slow-port solo batching ───────────────────────────────────────────────

    def test_slow_port_scanned_solo_at_large_batch_size(self, tmp_path):
        """SLOW_PORTS are always scanned in solo batches, even when batch_size > 1."""
        spoonmap.output_path = str(tmp_path)
        # 389 is in SLOW_PORTS; 80 and 443 are normal ports.
        # With batch_size=5 all three would normally share one batch.
        dest_ports = ['80', '389', '443']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)

        # Collect ports from every main batch (non-probe) call
        main_batches = [
            call[0][0] for call in mock_b.call_args_list
            if 'probe_fast' not in call[0][2] and 'probe_slow' not in call[0][2]
        ]
        solo_batches = [b for b in main_batches if b == ['389']]
        assert solo_batches, "Expected a solo batch for port 389"

    def test_non_slow_ports_batched_together(self, tmp_path):
        """Normal ports are still grouped into the same batch (not split unnecessarily)."""
        spoonmap.output_path = str(tmp_path)
        dest_ports = ['80', '443', '8080']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)

        main_batches = [
            call[0][0] for call in mock_b.call_args_list
            if 'probe_fast' not in call[0][2] and 'probe_slow' not in call[0][2]
        ]
        # All three normal ports must share one batch (batch_size=5 fits them all)
        combined = [p for batch in main_batches for p in batch]
        assert '80' in combined and '443' in combined and '8080' in combined
        assert any(len(b) > 1 for b in main_batches), "Normal ports should be grouped together"

    def test_absent_slow_port_has_no_solo_batch(self, tmp_path):
        """When a SLOW_PORT is not in dest_ports, no solo batch is created for it."""
        spoonmap.output_path = str(tmp_path)
        # 389 intentionally omitted from dest_ports
        dest_ports = ['80', '443']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)

        all_ports_scanned = [
            p for call in mock_b.call_args_list for p in call[0][0]
        ]
        assert '389' not in all_ports_scanned

    # ── summary deduplication ─────────────────────────────────────────────────

    def test_slow_port_summary_not_emitted_in_probe_phase(self, tmp_path):
        """Port 445 (SLOW_PORT) probed and found: summary must not appear from probe phase.

        445 is always re-queued for a solo batch; the summary is emitted exactly
        once from that batch phase, not twice (once from probe + once from batch).
        """
        spoonmap.output_path = str(tmp_path)
        # Internal scan: PROBE_PORT_PRIORITY includes 445 (position 2, after 443).
        # dest_ports=['445','3306'], batch_size=1 → probe selects ['445'].
        # remaining=['3306']. 445 is in SLOW_PORTS so it is re-queued for a solo batch.
        responses = [
            {'445': {'10.0.0.1'}},   # probe_fast_0 (445) — hit
            {},                       # probe_slow_0 (445) — no extra hosts
            {'445': {'10.0.0.2'}},   # solo batch for 445 — additional host
            {},                       # main batch for 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            result = mass_scan('All', ['445', '3306'], '88', '1000',
                               '/fake/targets.txt', '', batch_size=1)

        assert result.count('Hosts Found on Port 445') == 1

    def test_slow_port_summary_emitted_from_batch_phase(self, tmp_path):
        """The single 445 summary reflects merged count: probe IPs ∪ batch IPs."""
        spoonmap.output_path = str(tmp_path)
        responses = [
            {'445': {'10.0.0.1'}},   # probe_fast_0 — 1 host
            {},                       # probe_slow_0
            {'445': {'10.0.0.2'}},   # solo batch — 1 additional host
            {},                       # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            result = mass_scan('All', ['445', '3306'], '88', '1000',
                               '/fake/targets.txt', '', batch_size=1)

        # Both hosts (probe + batch) must be reflected in the summary count
        assert 'Hosts Found on Port 445: 2' in result

    def test_non_slow_port_summary_emitted_from_probe(self, tmp_path):
        """Non-SLOW_PORT found in probe still emits summary exactly once."""
        spoonmap.output_path = str(tmp_path)
        # 3306 is not in SLOW_PORTS and not in PROBE_PORT_PRIORITY,
        # so with dest_ports=['443','3306'] the probe selects ['443'].
        # 443 is not a SLOW_PORT → summary appears from probe phase.
        responses = [
            {'443': {'10.0.0.1'}},   # probe_fast_0 (443) — hit
            {},                       # main batch 3306
        ]
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            result = mass_scan('All', ['443', '3306'], '88', '1000',
                               '/fake/targets.txt', '', batch_size=1)

        assert result.count('Hosts Found on Port 443') == 1


# ── TestMassScanResume ────────────────────────────────────────────────────────

class TestMassScanResume:
    """Tests for --resume batch-skipping in mass_scan()."""

    def _write_batch_xml(self, path):
        """Write a minimal XML file to simulate a completed masscan batch."""
        path.write_text('<?xml version="1.0"?><nmaprun></nmaprun>')

    def test_completed_batch_skipped_when_resume_true(self, tmp_path):
        """A batch whose XML is newer than resolved_targets.txt is skipped when resume=True."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        self._write_batch_xml(batch_xml)

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')
        # Make batch XML newer than targets file
        import os
        import time as _time
        _write_target_stamp(batch_xml, targets_file)
        os.utime(str(targets_file), (0, 0))
        os.utime(str(batch_xml), (_time.time(), _time.time()))

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      str(targets_file), '', batch_size=10, resume=True)

        # Only probe calls should fire; the one main batch must be skipped
        main_calls = [
            c for c in mock_b.call_args_list
            if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]
        ]
        assert main_calls == [], 'Main batch should have been skipped under resume=True'

    def test_completed_batch_not_skipped_when_resume_false(self, tmp_path):
        """A pre-existing batch XML is NOT skipped when resume=False."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        self._write_batch_xml(batch_xml)

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')
        import os
        os.utime(str(targets_file), (0, 0))

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=10, resume=False)

        main_calls = [
            c for c in mock_b.call_args_list
            if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]
        ]
        assert len(main_calls) >= 1, 'Main batch should run when resume=False'

    def test_live_hosts_loaded_from_file_when_batch_skipped(self, tmp_path):
        """When a batch is skipped, IPs from live_hosts/portN.txt are loaded into port_ips."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        self._write_batch_xml(batch_xml)

        live_dir = tmp_path / 'discovery' / 'live_hosts'
        live_dir.mkdir(parents=True)
        (live_dir / 'port80.txt').write_text('10.0.0.1\n10.0.0.2\n')

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')
        _write_target_stamp(batch_xml, targets_file)
        import os
        import time as _time
        os.utime(str(targets_file), (0, 0))
        os.utime(str(batch_xml), (_time.time(), _time.time()))

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            result = mass_scan('All', ['80'], '53', '10000',
                               str(targets_file), '', batch_size=10, resume=True)

        # Assert the batch was actually skipped, not just that the count is
        # right: a re-run batch merges the same leftover file and produces an
        # identical summary, so the count alone does not exercise this path.
        main_calls = [c for c in mock_b.call_args_list
                      if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]]
        assert main_calls == []
        # The summary should reflect the 2 pre-existing hosts on port 80
        assert 'Hosts Found on Port 80: 2' in result

    def test_partial_resume_only_skips_completed_batches(self, tmp_path):
        """Only batches with existing XML are skipped; missing ones run normally."""
        spoonmap.output_path = str(tmp_path)
        results_dir = tmp_path / 'discovery' / 'masscan_results'
        results_dir.mkdir(parents=True)
        # batch_0 exists (ports 80, 443); batch_1 does NOT exist
        batch0_xml = results_dir / 'batch_0.xml'
        self._write_batch_xml(batch0_xml)

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')
        import os
        import time as _time
        _write_target_stamp(batch0_xml, targets_file)
        os.utime(str(targets_file), (0, 0))
        os.utime(str(batch0_xml), (_time.time(), _time.time()))

        # 4 ports split into 2 batches of 2 (batch_size=2); none are SLOW_PORTS
        # External probe priority: ['443','80','8080','8443'] → probe=['443','80'],
        # remaining=['8080','8443'] → 1 batch of 2
        dest_ports = ['443', '80', '8080', '8443']
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', dest_ports, '53', '10000',
                      str(targets_file), '', batch_size=2, resume=True)

        main_calls = [
            c for c in mock_b.call_args_list
            if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]
        ]
        # batch_0 is skipped; the remaining batch (8080, 8443) must run
        assert len(main_calls) == 1, (
            f'Expected exactly 1 main-batch call (batch_1), got {len(main_calls)}'
        )

    def test_batch_not_skipped_when_targets_file_is_newer(self, tmp_path):
        """If resolved_targets.txt is newer than batch XML, the batch re-runs."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        self._write_batch_xml(batch_xml)

        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True, exist_ok=True)
        targets_file.write_text('10.0.0.1\n')

        import os
        import time as _time
        # Make batch XML *older* than targets (simulates ranges.txt change)
        os.utime(str(batch_xml), (0, 0))
        os.utime(str(targets_file), (_time.time(), _time.time()))

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=10, resume=True)

        main_calls = [
            c for c in mock_b.call_args_list
            if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]
        ]
        assert len(main_calls) >= 1, 'Batch must re-run when targets file is newer'

    def _setup_batch_cache(self, tmp_path, xml_text):
        """Fresh-mtime batch_0.xml holding *xml_text*, plus a targets file."""
        spoonmap.output_path = str(tmp_path)
        batch_xml = tmp_path / 'discovery' / 'masscan_results' / 'batch_0.xml'
        batch_xml.parent.mkdir(parents=True)
        batch_xml.write_text(xml_text)
        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.write_text('10.0.0.1\n')
        _write_target_stamp(batch_xml, targets_file)
        os.utime(str(targets_file), (1000, 1000))
        os.utime(str(batch_xml), (2000, 2000))  # fresh mtime
        return batch_xml, targets_file

    @staticmethod
    def _main_batch_calls(mock_b):
        return [c for c in mock_b.call_args_list
                if 'probe_fast' not in c[0][2] and 'probe_slow' not in c[0][2]]

    def test_batch_rerun_when_cached_xml_is_zero_length(self, tmp_path, capsys):
        """An empty batch_0.xml (masscan killed mid-batch) must not be trusted."""
        self._setup_batch_cache(tmp_path, '')

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=10, resume=True)

        assert len(self._main_batch_calls(mock_b)) >= 1
        out = capsys.readouterr().out
        assert 're-running batch 1/' in out
        assert 'skipping completed batch' not in out

    def test_batch_rerun_when_cached_xml_is_unparseable(self, tmp_path, capsys):
        self._setup_batch_cache(tmp_path, '<nmaprun><host>')  # unclosed tags

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=10, resume=True)

        assert len(self._main_batch_calls(mock_b)) >= 1
        assert 're-running batch 1/' in capsys.readouterr().out

    def test_batch_still_skipped_when_cached_xml_is_valid_and_fresh(self, tmp_path, capsys):
        """Load-bearing direction: a genuinely completed batch stays skipped."""
        _batch_xml, targets_file = self._setup_batch_cache(
            tmp_path, '<?xml version="1.0"?><nmaprun></nmaprun>')

        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_b:
            mass_scan('All', ['80', '443'], '53', '10000',
                      str(targets_file), '', batch_size=10, resume=True)

        assert self._main_batch_calls(mock_b) == []
        assert 'skipping completed batch' in capsys.readouterr().out

    def test_completed_but_empty_batch_skipped_on_resume(self, tmp_path, capsys):
        """End-to-end: a batch that ran and found nothing must stay skipped.

        This is the common case on an internal segmentation test — most port
        batches legitimately find nothing — so if "completed, found nothing"
        were not representable on disk, every resume would redo every batch.
        Uses the real _run_masscan_batch() so the placeholder it writes is what
        the second pass's resume gate actually reads.
        """
        spoonmap.output_path = str(tmp_path)
        targets_file = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets_file.parent.mkdir(parents=True)
        targets_file.write_text('10.0.0.1\n')
        os.utime(str(targets_file), (1000, 1000))

        batch_cmds = []

        def fake_popen(cmd, **kwargs):
            out_path = cmd[cmd.index('-oX') + 1]
            if '/batch_' in out_path:
                batch_cmds.append(cmd)
            Path(out_path).write_text('')  # masscan found no open ports
            proc = MagicMock()
            proc.wait.return_value = 0
            proc.returncode = 0
            proc.pid = 12345
            # Finite stderr so _stream_masscan_progress()'s read(1) loop ends.
            proc.stderr = io.BytesIO(b'')
            return proc

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mass_scan('All', ['80', '443'], '53', '10000',
                      str(targets_file), '', batch_size=10, resume=False)
            first_pass_batches = len(batch_cmds)
            batch_cmds.clear()
            mass_scan('All', ['80', '443'], '53', '10000',
                      str(targets_file), '', batch_size=10, resume=True)

        assert first_pass_batches >= 1, 'first pass should have run a main batch'
        assert batch_cmds == [], 'an empty-but-completed batch must not re-run'
        assert 'skipping completed batch' in capsys.readouterr().out

    def test_leftover_live_hosts_file_merged_into_fresh_batch_results(self, tmp_path):
        """A pre-existing live_hosts file for a port (e.g. left over from an
        interrupted prior run) is merged with, not replaced by, this batch's
        fresh masscan results — even when resume=False.

        Uses batch_size=1 with an extra priority port ('443') so '3306' is
        never itself selected as a probe port (_select_probe_ports() falls
        back to filling probe slots from dest_ports when the priority list
        doesn't have enough matches) — otherwise 3306 would be resolved via
        the probe-merge code path instead of the main batch-merge path this
        test targets.
        """
        spoonmap.output_path = str(tmp_path)
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        live_dir.mkdir(parents=True)
        (live_dir / 'port3306.txt').write_text('10.0.0.100\n')

        responses = iter([
            {},                              # probe_fast(443) — miss
            {},                              # probe_slow(443) — miss
            {'3306': {'10.0.0.200'}},        # main batch (3306)
        ])
        with patch('spoonmap._run_masscan_batch',
                   side_effect=lambda *a, **k: next(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1, resume=False)

        content = (live_dir / 'port3306.txt').read_text()
        assert '10.0.0.100' in content  # preserved from the leftover file
        assert '10.0.0.200' in content  # from this run's fresh batch result

    def test_probe_and_batch_writes_leave_no_temp_files(self, tmp_path):
        """Neither the probe nor the main-batch live_hosts write may leave a temp file.

        The resume path and _combine_live_hosts() both enumerate live_hosts/,
        so a stray temp file there would be read as a port's host list.
        """
        spoonmap.output_path = str(tmp_path)
        responses = iter([
            {'443': {'10.0.0.1'}},           # probe_fast(443) — hit, stops probing
            {'3306': {'10.0.0.2'}},          # main batch (3306)
        ])
        with patch('spoonmap._run_masscan_batch',
                   side_effect=lambda *a, **k: next(responses)):
            mass_scan('All', ['443', '3306'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1, resume=False)

        live_dir = tmp_path / 'discovery' / 'live_hosts'
        assert sorted(p.name for p in live_dir.iterdir()) == ['port3306.txt', 'port443.txt']

    def test_failed_batch_write_keeps_prior_live_hosts_file(self, tmp_path):
        """A failed main-batch live_hosts write leaves the prior host list complete.

        Truncation here makes the next resume run scan that port against fewer
        hosts with no visible error.
        """
        spoonmap.output_path = str(tmp_path)
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        live_dir.mkdir(parents=True)
        (live_dir / 'port3306.txt').write_text('10.0.0.100\n10.0.0.101\n')

        responses = iter([
            {},                              # probe_fast(443) — miss
            {},                              # probe_slow(443) — miss
            {'3306': {'10.0.0.200'}},        # main batch (3306)
        ])
        with patch('spoonmap._run_masscan_batch',
                   side_effect=lambda *a, **k: next(responses)), \
             patch('spoonmap.os.replace', side_effect=OSError('ENOSPC')):
            with pytest.raises(OSError):
                mass_scan('All', ['443', '3306'], '53', '10000',
                          '/fake/targets.txt', '', batch_size=1, resume=False)

        assert (live_dir / 'port3306.txt').read_text() == '10.0.0.100\n10.0.0.101\n'
        assert [p.name for p in live_dir.iterdir()] == ['port3306.txt']


# ── _merge_host_xml ───────────────────────────────────────────────────────────

def _make_host(ip, ports, hostscripts=None):
    """Build a minimal nmap <host> element for testing."""
    host = etree.Element('host')
    addr = etree.SubElement(host, 'address')
    addr.set('addr', ip)
    addr.set('addrtype', 'ipv4')
    ports_elem = etree.SubElement(host, 'ports')
    for proto, portid in ports:
        p = etree.SubElement(ports_elem, 'port')
        p.set('protocol', proto)
        p.set('portid', portid)
    if hostscripts:
        hs = etree.SubElement(host, 'hostscript')
        for sid, output in hostscripts.items():
            s = etree.SubElement(hs, 'script')
            s.set('id', sid)
            s.set('output', output)
    return host


class TestMergeHostXml:
    def test_new_ports_appended(self):
        base = _make_host('10.0.0.1', [('tcp', '80')])
        other = _make_host('10.0.0.1', [('tcp', '443')])
        _merge_host_xml(base, other)
        portids = [p.get('portid') for p in base.find('ports').findall('port')]
        assert set(portids) == {'80', '443'}

    def test_duplicate_port_not_added_twice(self):
        base = _make_host('10.0.0.1', [('tcp', '80')])
        other = _make_host('10.0.0.1', [('tcp', '80')])
        _merge_host_xml(base, other)
        assert len(base.find('ports').findall('port')) == 1

    def test_hostscripts_merged(self):
        base = _make_host('10.0.0.1', [], {'smb-security-mode': 'disabled'})
        other = _make_host('10.0.0.1', [], {'smb2-security-mode': 'enabled'})
        _merge_host_xml(base, other)
        script_ids = {s.get('id') for s in base.find('hostscript').findall('script')}
        assert script_ids == {'smb-security-mode', 'smb2-security-mode'}

    def test_duplicate_hostscript_not_added_twice(self):
        base = _make_host('10.0.0.1', [], {'smb-security-mode': 'v1'})
        other = _make_host('10.0.0.1', [], {'smb-security-mode': 'v2'})
        _merge_host_xml(base, other)
        scripts = base.find('hostscript').findall('script')
        assert len(scripts) == 1
        assert scripts[0].get('output') == 'v1'

    def test_base_without_ports_elem(self):
        """base has no <ports> at all — _merge_host_xml creates one."""
        base = etree.Element('host')
        addr = etree.SubElement(base, 'address')
        addr.set('addr', '10.0.0.1')
        addr.set('addrtype', 'ipv4')
        other = _make_host('10.0.0.1', [('tcp', '22')])
        _merge_host_xml(base, other)
        portids = [p.get('portid') for p in base.find('ports').findall('port')]
        assert portids == ['22']

    def test_other_without_hostscript_noop(self):
        """other has no <hostscript> — base is unchanged."""
        base = _make_host('10.0.0.1', [('tcp', '80')], {'smb-security-mode': 'ok'})
        other = _make_host('10.0.0.1', [('tcp', '443')])
        _merge_host_xml(base, other)
        scripts = base.find('hostscript').findall('script')
        assert len(scripts) == 1

    def test_base_without_hostscript_elem(self):
        """base has no <hostscript> at all — _merge_host_xml creates one."""
        base = _make_host('10.0.0.1', [('tcp', '80')])
        other = _make_host('10.0.0.1', [], {'smb-security-mode': 'ok'})
        _merge_host_xml(base, other)
        scripts = base.find('hostscript').findall('script')
        assert [s.get('id') for s in scripts] == ['smb-security-mode']


# ── ms-sql-info UDP 1434 ───────────────────────────────────────────────────────
# Real nmap XML for ms-sql-info when it fires as a *portscript* on UDP 1434.
# Structure: <table key="INSTANCE"> (instance table, direct child of <script>)
#              └── <table key="Version"> (version sub-table)
#              └── <elem key="TCP port">PORT</elem>  (key matches
#                    create_instance_output_table()'s instanceOutput["TCP port"]
#                    in nse/ms-sql-info.nse — NOT the bare key "tcp")
#              └── <elem key="Named pipe">...</elem>
_MS_SQL_INFO_UDP_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <ports>
          <port protocol="udp" portid="1434">
            <state state="open" reason="udp-response"/>
            <script id="ms-sql-info" output="SQL Server 2019 on 192.168.1.10">
              <table key="192.168.1.10\\MSSQLSERVER">
                <table key="Version">
                  <elem key="name">Microsoft SQL Server 2019</elem>
                  <elem key="number">15.00.2000.00</elem>
                </table>
                <elem key="TCP port">1433</elem>
                <elem key="Named pipe">\\\\192.168.1.10\\pipe\\sql\\query</elem>
              </table>
            </script>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

# Same structure but with a named instance on a non-standard TCP port (51234)
_MS_SQL_INFO_NAMED_INSTANCE_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <ports>
          <port protocol="udp" portid="1434">
            <state state="open" reason="udp-response"/>
            <script id="ms-sql-info" output="SQL Server Express on 192.168.1.10">
              <table key="192.168.1.10\\SQLEXPRESS">
                <table key="Version">
                  <elem key="name">Microsoft SQL Server 2019 Express</elem>
                </table>
                <elem key="TCP port">51234</elem>
                <elem key="Named pipe">\\\\192.168.1.10\\pipe\\MSSQL$SQLEXPRESS\\sql\\query</elem>
              </table>
            </script>
          </port>
        </ports>
      </host>
    </nmaprun>
""")


class TestMsSqlInfoUdp1434:
    """ms-sql-info parsing from UDP 1434 nmap output via portscript and hostscript."""

    def test_portscript_produces_finding(self, nmap_dir):
        """ms-sql-info as a port-level script in portU:1434.xml must generate a finding.

        When nmap runs ms-sql-info via its portrule against UDP 1434, the script
        output lands under <port>, not <hostscript>.  generate_findings() must
        check both locations.
        """
        (nmap_dir / 'nse_results' / 'portU:1434.xml').write_text(_MS_SQL_INFO_UDP_XML)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SQL Server Instance Discovered' in content
        assert '192.168.1.10' in content

    def test_hostscript_produces_finding(self, nmap_dir):
        """ms-sql-info under <hostscript> in portU:1434.xml (regression: existing path)."""
        xml = _nmap_xml_hostscript('192.168.1.10', 'udp', '1434',
                                   hostscripts={'ms-sql-info': 'SQL Server 2019'})
        (nmap_dir / 'nse_results' / 'portU:1434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'SQL Server Instance Discovered' in content
        assert '192.168.1.10' in content

    def test_no_finding_for_external_scan(self, nmap_dir):
        """ms-sql-info should not generate a finding for External scans."""
        (nmap_dir / 'nse_results' / 'portU:1434.xml').write_text(_MS_SQL_INFO_UDP_XML)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'SQL Server Instance Discovered' not in findings_file.read_text()


# ── _scan_extra_sql_ports ─────────────────────────────────────────────────────

class TestScanExtraSqlPorts:
    """_scan_extra_sql_ports() parsing of ms-sql-info XML output."""

    def test_finds_named_instance_on_non_standard_port(self, tmp_path):
        """Named instance on port 51234 triggers extra nmap scans.

        The ms-sql-info XML has <table key="Version"> as a direct child of the
        instance table.  <elem key="TCP port"> is a *sibling* of that version
        table (also a direct child of the instance table), not inside the
        version sub-table.  The correct XPath to reach instance tables is
        'table', not 'table/table' (which would navigate into the version
        sub-table).

        Two separate invocations are expected: a plain -sV scan (written to
        nmap_results/, merged into spoonmap_output) and a --script
        azure-sql-detect scan (written to nse_results/, picked up by
        generate_findings()) — mirroring the same nmap_results/nse_results
        split used for the main port scan.
        """
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(_MS_SQL_INFO_NAMED_INSTANCE_XML)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            _scan_extra_sql_ports(str(tmp_path), '88')

        assert mock_popen.call_count == 2, f'Expected 2 nmap invocations, got {mock_popen.call_count}'
        commands = [c[0][0] for c in mock_popen.call_args_list]
        assert all('51234' in cmd for cmd in commands)

        sv_cmd = next(cmd for cmd in commands if '-sV' in cmd)
        assert f'{tmp_path}/nmap_results/port51234_sql.xml' in sv_cmd

        script_cmd = next(cmd for cmd in commands if '--script' in cmd)
        assert any('azure-sql-detect.nse' in arg for arg in script_cmd)
        assert f'{tmp_path}/nse_results/port51234_sql.xml' in script_cmd
        assert '-sV' not in script_cmd

    def test_standard_1433_instance_not_rescanned(self, tmp_path):
        """An instance on the default port 1433 must not trigger an extra scan."""
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU:1434.xml').write_text(_MS_SQL_INFO_UDP_XML)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _scan_extra_sql_ports(str(tmp_path), '88')

        assert not mock_popen.called, 'nmap must NOT be called for a standard 1433 instance'

    def test_azure_sql_detect_scan_skipped_when_already_run(self, tmp_path):
        """Resume behavior: an existing nse_results/portN_sql.xml skips only that scan."""
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(_MS_SQL_INFO_NAMED_INSTANCE_XML)
        (nse_dir / 'port51234_sql.xml').write_text('<nmaprun></nmaprun>')

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            _scan_extra_sql_ports(str(tmp_path), '88')

        assert mock_popen.call_count == 1, 'Only the -sV scan should run; azure-sql-detect already has output'
        cmd = mock_popen.call_args[0][0]
        assert '-sV' in cmd

    def test_non_ms_sql_info_script_ignored(self, tmp_path):
        """A <script> with a different id in the same file is skipped."""
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun>
              <host>
                <address addr="192.168.1.10" addrtype="ipv4"/>
                <ports>
                  <port protocol="udp" portid="1434">
                    <script id="some-other-script" output="unrelated"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
        """)
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(xml)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _scan_extra_sql_ports(str(tmp_path), '88')

        assert not mock_popen.called

    def test_unusable_address_hosts_skipped_later_instance_still_scanned(self, tmp_path):
        """findall('address')[0] raised IndexError on a <host> with no <address>,
        and KeyError on one with no addr=.  The broad guard swallowed both and
        abandoned the rest of the file, losing every later named instance."""
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun>
              <host>
                <ports><port protocol="udp" portid="1434"/></ports>
              </host>
              <host>
                <address addrtype="ipv4"/>
                <ports><port protocol="udp" portid="1434"/></ports>
              </host>
              <host>
                <address addr="192.168.1.10" addrtype="ipv4"/>
                <ports>
                  <port protocol="udp" portid="1434">
                    <script id="ms-sql-info" output="SQL Server Express">
                      <table key="192.168.1.10\\SQLEXPRESS">
                        <elem key="TCP port">51234</elem>
                      </table>
                    </script>
                  </port>
                </ports>
              </host>
            </nmaprun>
        """)
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(xml)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            _scan_extra_sql_ports(str(tmp_path), '88')

        commands = [c[0][0] for c in mock_popen.call_args_list]
        assert commands, 'the third host\'s named instance must still be scanned'
        assert all('51234' in cmd for cmd in commands)

    def test_mac_address_is_not_used_as_the_scan_target(self, tmp_path):
        """ip becomes an nmap scan target, so it must be the IPv4 address and not
        whichever <address> child came first — an ARP-resolved internal host
        lists its MAC there, and a MAC is an unresolvable target."""
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun>
              <host>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
                <address addr="192.168.1.10" addrtype="ipv4"/>
                <ports>
                  <port protocol="udp" portid="1434">
                    <script id="ms-sql-info" output="SQL Server Express">
                      <table key="192.168.1.10\\SQLEXPRESS">
                        <elem key="TCP port">51234</elem>
                      </table>
                    </script>
                  </port>
                </ports>
              </host>
            </nmaprun>
        """)
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(xml)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            _scan_extra_sql_ports(str(tmp_path), '88')

        commands = [c[0][0] for c in mock_popen.call_args_list]
        assert commands
        for cmd in commands:
            assert '192.168.1.10' in cmd
            assert 'AA:BB:CC:DD:EE:FF' not in cmd

    def test_host_with_only_a_non_ipv4_address_is_skipped(self, tmp_path):
        """No IPv4 child means no scannable target: skip the host rather than
        handing nmap an IPv6 literal this IPv4-only tool cannot scan."""
        xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun>
              <host>
                <address addr="fe80::1" addrtype="ipv6"/>
                <ports>
                  <port protocol="udp" portid="1434">
                    <script id="ms-sql-info" output="SQL Server Express">
                      <table key="HOST\\SQLEXPRESS">
                        <elem key="TCP port">51234</elem>
                      </table>
                    </script>
                  </port>
                </ports>
              </host>
            </nmaprun>
        """)
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(xml)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _scan_extra_sql_ports(str(tmp_path), '88')

        assert not mock_popen.called

    def test_malformed_xml_logged_and_skipped(self, tmp_path, capsys):
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'port1433.xml').write_text('<nmaprun><host>')  # unclosed tags

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _scan_extra_sql_ports(str(tmp_path), '88')

        assert not mock_popen.called
        assert 'could not parse port1433.xml' in capsys.readouterr().out

    def test_sv_scan_popen_failure_is_logged(self, tmp_path, capsys):
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(_MS_SQL_INFO_NAMED_INSTANCE_XML)

        with patch('spoonmap.subprocess.Popen', side_effect=OSError('nmap not found')), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _scan_extra_sql_ports(str(tmp_path), '88')  # must not raise

        assert 'Error scanning SQL port 51234' in capsys.readouterr().out

    def test_azure_sql_detect_popen_failure_is_logged(self, tmp_path, capsys):
        """The -sV scan succeeds (existing output file) but the azure-sql-detect
        Popen call itself raises — exercises that branch's except clause."""
        nse_dir = tmp_path / 'nse_results'
        nse_dir.mkdir()
        (nse_dir / 'portU_1434.xml').write_text(_MS_SQL_INFO_NAMED_INSTANCE_XML)
        nmap_dir = tmp_path / 'nmap_results'
        nmap_dir.mkdir()
        (nmap_dir / 'port51234_sql.xml').write_text('<nmaprun></nmaprun>')

        with patch('spoonmap.subprocess.Popen', side_effect=OSError('nmap not found')), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _scan_extra_sql_ports(str(tmp_path), '88')  # must not raise

        assert 'Error running azure-sql-detect on port 51234' in capsys.readouterr().out


# ── Azure SQL Database vs on-prem classification ──────────────────────────────

class TestSqlVersionYear:
    """_sql_version_year() extracts a branded SQL Server year from script text."""

    def test_branded_name_with_service_pack(self):
        assert _sql_version_year('name: Microsoft SQL Server 2014 SP3') == '2014'

    def test_branded_name_r2(self):
        assert _sql_version_year('Product: Microsoft SQL Server 2008 R2') == '2008 R2'

    def test_falls_back_to_version_number_prefix(self):
        # No branded name present — only the raw PRELOGIN version number.
        assert _sql_version_year('version 12.0.2000.8') == '2014'

    def test_unrecognized_prefix_returns_none(self):
        assert _sql_version_year('version 99.9.1234') is None

    def test_empty_text_returns_none(self):
        assert _sql_version_year('') is None
        assert _sql_version_year(None) is None


class TestClassifySql:
    """_classify_sql() layers hostname/certificate (definitive) over PRELOGIN FEDAUTHREQUIRED (fedauth-only, corroborating)."""

    def test_azure_domain_suffixes_cover_public_and_sovereign_clouds(self):
        assert '.database.windows.net' in AZURE_SQL_DOMAIN_SUFFIXES
        assert '.database.chinacloudapi.cn' in AZURE_SQL_DOMAIN_SUFFIXES
        assert '.database.usgovcloudapi.net' in AZURE_SQL_DOMAIN_SUFFIXES

    def test_azure_hostname_is_definitive(self):
        is_azure, confidence, year = _classify_sql(
            'myserver.database.windows.net',
            ms_sql_output='name: Microsoft SQL Server 2014 SP3',
        )
        assert is_azure is True
        assert confidence == 'hostname'
        assert year == '2014'

    def test_azure_sovereign_cloud_hostname_is_definitive(self):
        is_azure, confidence, _year = _classify_sql('sql1.database.usgovcloudapi.net')
        assert is_azure is True
        assert confidence == 'hostname'

    def test_onprem_hostname_is_not_azure(self):
        is_azure, confidence, _year = _classify_sql(
            'sql01.corp.local', ms_sql_output='Microsoft SQL Server 2014 SP3')
        assert is_azure is False
        assert confidence is None

    def test_bare_ip_with_fedauthrequired_is_fedauth_only(self):
        # No hostname at all (bare-IP target) — the PRELOGIN probe is the only signal.
        is_azure, confidence, _year = _classify_sql(
            None, azure_output='FEDAUTHREQUIRED=1  ENCRYPT=REQUIRED  version 12.0.2000')
        assert is_azure is True
        assert confidence == 'fedauth'

    def test_bare_ip_without_fedauthrequired_is_onprem(self):
        is_azure, confidence, _year = _classify_sql(
            None, azure_output='FEDAUTHREQUIRED=0  ENCRYPT=ON  version 15.00.2000')
        assert is_azure is False
        assert confidence is None

    def test_hostname_overrides_missing_fedauthrequired(self):
        # Azure FQDN is definitive even if the PRELOGIN probe didn't run/failed.
        is_azure, confidence, _year = _classify_sql(
            'myserver.database.windows.net', azure_output='')
        assert is_azure is True
        assert confidence == 'hostname'

    # ── certificate SAN (works even on hostname-less/internal targets) ──────

    def test_bare_ip_cert_san_match_is_definitive(self):
        # No hostname, no FEDAUTHREQUIRED — the certificate SAN is the only
        # signal, exactly the internal-scan / private-endpoint scenario the
        # hostname check alone cannot cover.
        is_azure, confidence, _year = _classify_sql(
            None,
            azure_output='FEDAUTHREQUIRED=0 ENCRYPT=REQUIRED CERT_SAN=myserver.database.windows.net version 12.0.2000',
        )
        assert is_azure is True
        assert confidence == 'certificate'

    def test_cert_san_with_multiple_entries_matches_any(self):
        is_azure, confidence, _year = _classify_sql(
            None,
            azure_output='FEDAUTHREQUIRED=0 ENCRYPT=REQUIRED '
                          'CERT_SAN=other.internal.name,myserver.database.chinacloudapi.cn version 12.0.2000',
        )
        assert is_azure is True
        assert confidence == 'certificate'

    def test_cert_san_none_falls_back_to_fedauth(self):
        is_azure, confidence, _year = _classify_sql(
            None,
            azure_output='FEDAUTHREQUIRED=1 ENCRYPT=REQUIRED CERT_SAN=none version 12.0.2000',
        )
        assert is_azure is True
        assert confidence == 'fedauth'

    def test_cert_san_unavailable_falls_back_to_fedauth(self):
        is_azure, confidence, _year = _classify_sql(
            None,
            azure_output='FEDAUTHREQUIRED=1 ENCRYPT=REQUIRED CERT_SAN=unavailable version 12.0.2000',
        )
        assert is_azure is True
        assert confidence == 'fedauth'

    def test_cert_san_non_azure_hostnames_do_not_confirm(self):
        is_azure, confidence, _year = _classify_sql(
            None,
            azure_output='FEDAUTHREQUIRED=0 ENCRYPT=ON CERT_SAN=sql01.corp.local,sql01 version 15.00.2000',
        )
        assert is_azure is False
        assert confidence is None

    def test_cert_san_beats_missing_hostname_even_without_fedauth(self):
        # Confirms certificate check is independent of the FEDAUTHREQUIRED signal.
        is_azure, confidence, _year = _classify_sql(
            'sql-prod-01.internal.corp.com',  # internal alias, not an Azure FQDN
            azure_output='FEDAUTHREQUIRED=0 ENCRYPT=REQUIRED CERT_SAN=sql-mi.database.windows.net version 12.0.2000',
        )
        assert is_azure is True
        assert confidence == 'certificate'


class TestGenerateFindingsSqlEolAndAzure:
    """generate_findings() SQL branches: on-prem EOL detection + Azure exemption."""

    def test_corrupt_hostname_map_falls_back_gracefully(self, nmap_dir):
        """A malformed ip_hostname_map.json must not crash generate_findings()."""
        (nmap_dir / 'discovery').mkdir(parents=True)
        (nmap_dir / 'discovery' / 'ip_hostname_map.json').write_text('{not valid json')
        xml = _nmap_xml_hostscript(
            '10.0.0.26', 'tcp', '1434',
            hostscripts={'ms-sql-info': 'name: Microsoft SQL Server 2019 RTM'})
        (nmap_dir / 'nse_results' / 'port1434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')  # must not raise
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'SQL Server Instance Discovered' in txt

    def test_onprem_eol_sql_2014_is_high(self, nmap_dir):
        xml = _nmap_xml_hostscript(
            '10.0.0.20', 'tcp', '1434',
            hostscripts={'ms-sql-info': 'name: Microsoft SQL Server 2014 SP3'})
        (nmap_dir / 'nse_results' / 'port1434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        eol = [r for r in records if r['title'] == 'End-of-Life SQL Server']
        assert eol and eol[0]['severity'] == 'HIGH'
        assert '10.0.0.20' in eol[0]['host']
        assert '2024-07-09' in eol[0]['detail']

    def test_onprem_supported_sql_2019_no_eol_finding(self, nmap_dir):
        xml = _nmap_xml_hostscript(
            '10.0.0.21', 'tcp', '1434',
            hostscripts={'ms-sql-info': 'name: Microsoft SQL Server 2019 RTM'})
        (nmap_dir / 'nse_results' / 'port1434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'End-of-Life SQL Server' not in txt

    def test_azure_hostname_exempts_frozen_12_0_from_eol(self, nmap_dir):
        # Azure SQL Database reports a frozen 12.0 (SQL 2014) version, but is a
        # managed evergreen service — it must NOT be flagged End-of-Life.
        (nmap_dir / 'discovery').mkdir(parents=True)
        (nmap_dir / 'discovery' / 'ip_hostname_map.json').write_text(
            json.dumps({'10.0.0.22': 'myserver.database.windows.net'}))
        xml = _nmap_xml_hostscript(
            '10.0.0.22', 'tcp', '1434',
            hostscripts={'ms-sql-info': 'name: Microsoft SQL Server 2014 SP3'})
        (nmap_dir / 'nse_results' / 'port1434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        assert not [r for r in records if r['title'] == 'End-of-Life SQL Server']
        azure = [r for r in records if r['title'] == 'Azure SQL Database Detected']
        assert azure and azure[0]['severity'] == 'LOW'
        assert 'NOT end-of-life' in azure[0]['detail']

    def test_azure_sql_detect_portscript_bare_ip_likely_azure(self, nmap_dir):
        """azure-sql-detect on TCP 1433 with FEDAUTHREQUIRED=1 and no hostname."""
        xml = _nmap_xml('10.0.0.23', 'tcp', '1433', scripts={
            'azure-sql-detect': 'FEDAUTHREQUIRED=1 ENCRYPT=REQUIRED version 12.0.2000',
        })
        (nmap_dir / 'nse_results' / 'port1433.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        azure = [r for r in records if r['title'] == 'Azure SQL Database Detected']
        assert azure and azure[0]['severity'] == 'LOW'
        assert 'Likely' in azure[0]['detail']

    def test_azure_sql_detect_portscript_no_fedauth_is_onprem_probe(self, nmap_dir):
        xml = _nmap_xml('10.0.0.24', 'tcp', '1433', scripts={
            'azure-sql-detect': 'FEDAUTHREQUIRED=0 ENCRYPT=ON version 15.00.2000',
        })
        (nmap_dir / 'nse_results' / 'port1433.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'SQL Server PRELOGIN Probe' in txt
        assert 'Azure SQL Database Detected' not in txt

    def test_azure_sql_detect_runs_on_external_scan_too(self, nmap_dir):
        """Unlike ms-sql-info, azure-sql-detect findings are not Internal-only."""
        xml = _nmap_xml('10.0.0.25', 'tcp', '1433', scripts={
            'azure-sql-detect': 'FEDAUTHREQUIRED=1 ENCRYPT=REQUIRED version 12.0.2000',
        })
        (nmap_dir / 'nse_results' / 'port1433.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'Azure SQL Database Detected' in txt

    def test_azure_sql_detect_cert_san_confirms_on_bare_ip_internal_target(self, nmap_dir):
        """Certificate SAN confirms Azure even with no hostname at all (private
        endpoint / custom internal DNS scenario the hostname check can't cover)."""
        xml = _nmap_xml('10.0.0.27', 'tcp', '1433', scripts={
            'azure-sql-detect': 'FEDAUTHREQUIRED=0 ENCRYPT=REQUIRED '
                                 'CERT_SAN=myserver.database.windows.net version 12.0.2000.8',
        })
        (nmap_dir / 'nse_results' / 'port1433.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        azure = [r for r in records if r['title'] == 'Azure SQL Database Detected']
        assert azure and azure[0]['severity'] == 'LOW'
        assert 'Confirmed via certificate SAN' in azure[0]['detail']

    def test_azure_sql_detect_multiline_output_is_flattened_for_findings(self, nmap_dir):
        """azure-sql-detect.nse's real output is multi-line (screenshot-friendly
        headline + indented evidence lines). generate_findings() must flatten
        it to one line for the 'detail' field so findings.md's markdown table
        doesn't break on an embedded newline, while classification still uses
        the raw multi-line text unchanged."""
        real_multiline_output = (
            'Azure SQL Database / Managed Instance detected (certificate SAN confirms Azure)\n'
            '  Certificate SAN : myserver.database.windows.net\n'
            '  Reported version: 12.0.2000.8 (frozen at "SQL Server 2014" -- expected for Azure, NOT end-of-life)\n'
            '  Raw signals:\n'
            '    FEDAUTHREQUIRED=0\n'
            '    ENCRYPT=REQUIRED\n'
            '    CERT_SAN=myserver.database.windows.net'
        )
        xml = _nmap_xml('10.0.0.30', 'tcp', '1433', scripts={'azure-sql-detect': real_multiline_output})
        (nmap_dir / 'nse_results' / 'port1433.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')

        records = json.loads((nmap_dir / 'findings.json').read_text())
        azure = [r for r in records if r['title'] == 'Azure SQL Database Detected']
        assert azure and azure[0]['severity'] == 'LOW'
        assert '\n' not in azure[0]['detail']
        assert 'CERT_SAN=myserver.database.windows.net' in azure[0]['detail']

        # findings.md must stay valid: this finding's row is a single,
        # well-formed table line (not split across lines by an embedded
        # newline from the raw multi-line NSE output).
        md = (nmap_dir / 'findings.md').read_text()
        matching_lines = [ln for ln in md.splitlines() if '10.0.0.30' in ln]
        assert len(matching_lines) == 1
        row = matching_lines[0]
        assert row.startswith('| `10.0.0.30`') and row.endswith('|')
        assert row.count('|') == 4

    def test_azure_sql_detect_fires_on_managed_instance_port_3342(self, nmap_dir):
        """Azure SQL Managed Instance's public endpoint (3342), not just 1433."""
        xml = _nmap_xml('10.0.0.28', 'tcp', '3342', scripts={
            'azure-sql-detect': 'FEDAUTHREQUIRED=1 ENCRYPT=REQUIRED CERT_SAN=none version 12.0.2000',
        })
        (nmap_dir / 'nse_results' / 'port3342.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        azure = [r for r in records if r['title'] == 'Azure SQL Database Detected']
        assert azure and azure[0]['port'] == 'tcp/3342'

    def test_azure_sql_detect_fires_on_non_standard_named_instance_port(self, nmap_dir):
        """A named instance SpooNMAP discovered on a dynamic port (via
        _scan_extra_sql_ports's follow-up scan, written as portN_sql.xml) is
        still classified — the finding isn't gated to a fixed port list."""
        xml = _nmap_xml('10.0.0.29', 'tcp', '51234', scripts={
            'azure-sql-detect': 'FEDAUTHREQUIRED=0 ENCRYPT=REQUIRED '
                                 'CERT_SAN=myserver.database.windows.net version 12.0.2000.8',
        })
        (nmap_dir / 'nse_results' / 'port51234_sql.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        azure = [r for r in records if r['title'] == 'Azure SQL Database Detected']
        assert azure and azure[0]['port'] == 'tcp/51234'


class TestAzureSqlDetectWiring:
    """azure-sql-detect.nse is registered on TCP 1433 and 3342 (Managed
    Instance public endpoint) for both scan types."""

    def test_wired_into_internal_port_scripts(self):
        assert 'nse/azure-sql-detect.nse' in INTERNAL_PORT_SCRIPTS['1433']

    def test_wired_into_external_port_scripts(self):
        assert 'nse/azure-sql-detect.nse' in EXTERNAL_PORT_SCRIPTS['1433']

    def test_get_scripts_for_port_includes_it_both_scans(self):
        for scan in ('External', 'Internal'):
            assert 'azure-sql-detect.nse' in _get_scripts_for_port('1433', scan)

    def test_wired_into_port_3342_both_scans(self):
        for scan in ('External', 'Internal'):
            assert 'azure-sql-detect.nse' in _get_scripts_for_port('3342', scan)

    def test_port_3342_in_database_category(self):
        assert '3342' in SERVICE_CATEGORIES['Database']

    def test_port_3342_in_external_sensitive_ports(self):
        keys = {t[0] for t in EXTERNAL_SENSITIVE_PORTS}
        assert '3342' in keys


# ── TestInternalNseFindings ───────────────────────────────────────────────────

class TestInternalNseFindings:
    """Per-port NSE-validated findings that replaced INTERNAL_RISK_PORTS."""

    def test_jdwp_finding(self, nmap_dir):
        """jdwp-info output with content triggers JDWP finding."""
        xml = _nmap_xml('10.0.1.1', 'tcp', '5005',
                        scripts={'jdwp-info': 'Protocol version: 1.1\nVM name: Java HotSpot'})
        (nmap_dir / 'nse_results' / 'port5005.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'JDWP Java Debugger Exposed' in content
        assert '10.0.1.1' in content

    def test_nodejs_inspector_finding(self, nmap_dir):
        """nodejs-inspector output triggers Node.js Inspector finding."""
        xml = _nmap_xml('10.0.1.2', 'tcp', '9229',
                        scripts={'nodejs-inspector': 'Node.js Inspector accessible — version: node.js/v18.17.0'})
        (nmap_dir / 'nse_results' / 'port9229.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Node.js Inspector Port Exposed' in content
        assert '10.0.1.2' in content

    def test_delve_finding(self, nmap_dir):
        """delve-debugger output triggers Delve finding."""
        xml = _nmap_xml('10.0.1.3', 'tcp', '2345',
                        scripts={'delve-debugger': 'Delve debugger responding to DAP requests'})
        (nmap_dir / 'nse_results' / 'port2345.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Delve Go Debugger Exposed' in content
        assert '10.0.1.3' in content

    def test_kubelet_anon_finding(self, nmap_dir):
        """kubelet-anon-check output triggers Kubelet Anonymous Access finding."""
        xml = _nmap_xml('10.0.1.4', 'tcp', '10250',
                        scripts={'kubelet-anon-check': 'Anonymous access enabled — /pods returned HTTP 200 without credentials'})
        (nmap_dir / 'nse_results' / 'port10250.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Kubernetes Kubelet Anonymous Access' in content
        assert '10.0.1.4' in content

    def test_k8s_dashboard_finding(self, nmap_dir):
        """http-title containing 'Kubernetes Dashboard' triggers k8s dashboard finding."""
        xml = _nmap_xml('10.0.1.5', 'tcp', '8001',
                        scripts={'http-title': 'Kubernetes Dashboard'})
        (nmap_dir / 'nse_results' / 'port8001.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Kubernetes Dashboard Accessible' in content
        assert '10.0.1.5' in content

    def test_activemq_banner_finding(self, nmap_dir):
        """banner containing 'ActiveMQ' triggers ActiveMQ Broker Exposed finding."""
        xml = _nmap_xml('10.0.1.6', 'tcp', '61616',
                        scripts={'banner': 'STOMP\nActiveMQ/5.15.9'})
        (nmap_dir / 'nse_results' / 'port61616.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'ActiveMQ Broker Exposed' in content
        assert '10.0.1.6' in content

    def test_no_finding_without_script_output(self, nmap_dir):
        """Port 5005 open but jdwp-info returns empty string — no JDWP finding."""
        xml = _nmap_xml('10.0.1.7', 'tcp', '5005',
                        scripts={'jdwp-info': ''})
        (nmap_dir / 'nse_results' / 'port5005.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'JDWP Java Debugger Exposed' not in findings_file.read_text()

    # ── Local LLM findings ─────────────────────────────────────────────────────

    def test_ollama_internal_medium(self, nmap_dir):
        """ollama-detect output on internal scan → MEDIUM finding."""
        xml = _nmap_xml('10.0.2.1', 'tcp', '11434',
                        scripts={'ollama-detect': 'Ollama API accessible without authentication \u2014 models: llama2 (version: 0.1.33)'})
        (nmap_dir / 'nse_results' / 'port11434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Ollama LLM API Unauthenticated' in content
        assert 'MEDIUM' in content
        assert '10.0.2.1' in content

    def test_ollama_external_high(self, nmap_dir):
        """ollama-detect output on external scan → HIGH finding."""
        xml = _nmap_xml('1.2.3.4', 'tcp', '11434',
                        scripts={'ollama-detect': 'Ollama API accessible without authentication \u2014 models: llama2 (version: 0.1.33)'})
        (nmap_dir / 'nse_results' / 'port11434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Ollama LLM API Unauthenticated' in content
        assert 'HIGH' in content

    def test_openai_api_internal_medium(self, nmap_dir):
        """openai-api-detect output on internal scan → MEDIUM finding."""
        xml = _nmap_xml('10.0.2.2', 'tcp', '1234',
                        scripts={'openai-api-detect': 'OpenAI-compatible LLM API accessible without authentication \u2014 product: LM Studio, models: Mistral-7B'})
        (nmap_dir / 'nse_results' / 'port1234.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'OpenAI-Compatible LLM API Unauthenticated' in content
        assert 'MEDIUM' in content

    def test_openai_api_external_high(self, nmap_dir):
        """openai-api-detect output on external scan → HIGH finding."""
        xml = _nmap_xml('1.2.3.5', 'tcp', '1234',
                        scripts={'openai-api-detect': 'OpenAI-compatible LLM API accessible without authentication \u2014 product: LM Studio, models: Mistral-7B'})
        (nmap_dir / 'nse_results' / 'port1234.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'OpenAI-Compatible LLM API Unauthenticated' in content
        assert 'HIGH' in content

    def test_gradio_internal_medium(self, nmap_dir):
        """gradio-detect output on internal scan → MEDIUM finding."""
        xml = _nmap_xml('10.0.2.3', 'tcp', '7860',
                        scripts={'gradio-detect': 'Gradio web UI accessible \u2014 version: 3.50.2'})
        (nmap_dir / 'nse_results' / 'port7860.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Gradio LLM Web UI Accessible' in content
        assert 'MEDIUM' in content

    def test_koboldcpp_internal_medium(self, nmap_dir):
        """koboldcpp-detect output on internal scan → MEDIUM finding."""
        xml = _nmap_xml('10.0.2.4', 'tcp', '5001',
                        scripts={'koboldcpp-detect': 'KoboldCpp API accessible without authentication \u2014 model: llama-2-7b-chat.Q4_K_M.gguf'})
        (nmap_dir / 'nse_results' / 'port5001.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'KoboldCpp LLM API Unauthenticated' in content
        assert 'MEDIUM' in content

    def test_llm_no_finding_for_empty_output(self, nmap_dir):
        """ollama-detect with empty output → no finding generated."""
        xml = _nmap_xml('10.0.2.5', 'tcp', '11434',
                        scripts={'ollama-detect': ''})
        (nmap_dir / 'nse_results' / 'port11434.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'Ollama LLM API Unauthenticated' not in findings_file.read_text()

    def test_high_risk_service_detected_never_fires(self, nmap_dir):
        """The old 'High-Risk Service Detected' title must never appear in output."""
        # Write XML for all ports that used to trigger INTERNAL_RISK_PORTS
        for port in ('9229', '2345', '5005', '10250', '8001', '61616'):
            xml = _nmap_xml(f'10.0.2.{port[-1]}', 'tcp', port)
            (nmap_dir / 'nse_results' / f'port{port}.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'High-Risk Service Detected' not in findings_file.read_text()


# ── _build_nmap_cmd ───────────────────────────────────────────────────────────

class TestBuildNmapCmd:
    """Unit tests for _build_nmap_cmd source-port behaviour."""

    def test_smb_port_with_scripts_omits_source_port(self):
        """Port 445 + script_scan=True → no --source-port in command."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal')
        assert '--source-port' not in cmd

    def test_smb_port_139_with_scripts_omits_source_port(self):
        """Port 139 + script_scan=True → no --source-port in command."""
        cmd = _build_nmap_cmd('139', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal')
        assert '--source-port' not in cmd

    def test_smb_port_banner_only_keeps_source_port(self):
        """Port 445 + script_scan=False (banner only) → --source-port 88 present."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '88',
                               script_scan=False, target_scan='Internal')
        assert '--source-port' in cmd
        assert '88' in cmd

    def test_non_smb_port_with_scripts_keeps_source_port(self):
        """Port 22 + script_scan=True → --source-port 88 present."""
        cmd = _build_nmap_cmd('22', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal')
        assert '--source-port' in cmd
        assert '88' in cmd

    def test_udp_port_keeps_source_port(self):
        """UDP port always uses -sU and keeps --source-port."""
        cmd = _build_nmap_cmd('U:161', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal')
        assert '--source-port' in cmd
        assert '-sU' in cmd
        assert '-sS' not in cmd

    def test_smb_port_external_scan_with_scripts_omits_source_port(self):
        """Port 445 + External scan → --source-port 53 also omitted."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '53',
                               script_scan=True, target_scan='External')
        assert '--source-port' not in cmd

    def test_banner_pass_never_includes_script(self):
        """script_only=False (default) → --script never present regardless of script_scan."""
        for port in ('22', '445', 'U:161'):
            cmd = _build_nmap_cmd(port, '/in.txt', '/out.xml', '88',
                                   script_scan=True, target_scan='Internal')
            assert '--script' not in cmd, f'--script should not appear in banner pass for port {port}'

    def test_script_only_uses_ss_not_sn(self):
        """script_only=True → -sS for TCP, -sU for UDP; -sn and -sV absent.

        -sn (no port scan) conflicts with -p (explicit port selection) and
        causes nmap to error: 'You cannot use -F or -p when not doing a port scan'.
        The script pass must use a real scan type so -p is accepted.
        """
        tcp_cmd = _build_nmap_cmd('22', '/in.txt', '/out.xml', '88',
                                   script_scan=True, target_scan='Internal',
                                   script_only=True)
        assert '-sS' in tcp_cmd
        assert '-sn' not in tcp_cmd
        assert '-sV' not in tcp_cmd

        udp_cmd = _build_nmap_cmd('U:161', '/in.txt', '/out.xml', '88',
                                   script_scan=True, target_scan='Internal',
                                   script_only=True)
        assert '-sU' in udp_cmd
        assert '-sn' not in udp_cmd
        assert '-sV' not in udp_cmd

    def test_script_only_includes_script_when_port_has_scripts(self):
        """script_only=True on a port with scripts → --script present."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal',
                               script_only=True)
        assert '--script' in cmd

    def test_script_only_smb_omits_source_port(self):
        """script_only=True + SMB port → --source-port omitted."""
        cmd = _build_nmap_cmd('445', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal',
                               script_only=True)
        assert '--source-port' not in cmd

    def test_script_only_non_smb_keeps_source_port(self):
        """script_only=True + non-SMB port → --source-port present."""
        cmd = _build_nmap_cmd('22', '/in.txt', '/out.xml', '88',
                               script_scan=True, target_scan='Internal',
                               script_only=True)
        assert '--source-port' in cmd
        assert '88' in cmd


class TestCreateHostnameTargetFile:
    def test_maps_known_ips_to_hostnames(self, tmp_path):
        ip_file = tmp_path / 'ips.txt'
        ip_file.write_text('10.0.0.1\n10.0.0.2\n')
        hostname_file = tmp_path / 'hostnames.txt'
        create_hostname_target_file(str(ip_file), str(hostname_file),
                                    {'10.0.0.1': 'host1.internal'})
        content = hostname_file.read_text()
        assert content == 'host1.internal\n10.0.0.2\n'

    def test_unmapped_ip_kept_as_is(self, tmp_path):
        ip_file = tmp_path / 'ips.txt'
        ip_file.write_text('10.0.0.5\n')
        hostname_file = tmp_path / 'hostnames.txt'
        create_hostname_target_file(str(ip_file), str(hostname_file), {})
        assert hostname_file.read_text() == '10.0.0.5\n'


class TestQuarantineFailedOutput:
    """_quarantine_failed_output() renames a failed pass's XML out of the way."""

    def test_existing_output_is_renamed_and_rejected_by_the_resume_gate(self, tmp_path):
        # A failed nmap can still leave a valid, hostless XML: parseable, so the
        # gate accepted it and the port was never re-scanned.
        target = tmp_path / 'hosts.txt'
        target.write_text('10.0.0.1\n')
        out = tmp_path / 'port80.xml'
        out.write_text('<nmaprun/>')
        _write_target_stamp(out, target)
        assert _resume_cache_usable(str(out), 0, 'port 80 banner scan',
                                    target_file=str(target),
                                    exclusions_file=None) is True

        failed = _quarantine_failed_output(str(out))

        assert failed == str(out) + '.failed'
        assert not out.exists()
        assert (tmp_path / 'port80.xml.failed').read_text() == '<nmaprun/>'
        # Rejected on the output's absence, even though its coverage record
        # survives the rename — the gate tests existence first.
        assert _resume_cache_usable(str(out), 0, 'port 80 banner scan',
                                    target_file=str(target),
                                    exclusions_file=None) is False

    def test_quarantined_name_is_invisible_to_result_parsing(self, tmp_path):
        # The suffix must not end in .xml, or aggregation would pick the failed
        # run's partial hosts back up.
        out = tmp_path / 'port80.xml'
        out.write_text('<nmaprun/>')
        failed = _quarantine_failed_output(str(out))
        assert _parse_result_xml(failed) is None

    def test_missing_output_returns_none(self, tmp_path):
        # nmap exiting before it created any file at all — already fails the gate.
        assert _quarantine_failed_output(str(tmp_path / 'gone.xml')) is None

    def test_rename_failure_is_swallowed(self, tmp_path):
        """A read-only output dir must not turn a reportable nmap failure into
        an exception that takes down the worker thread."""
        out = tmp_path / 'port80.xml'
        out.write_text('<nmaprun/>')
        with patch('spoonmap.os.replace', side_effect=OSError('read-only')):
            assert _quarantine_failed_output(str(out)) is None
        assert out.exists()


class TestNmapWorker:
    """Unit tests for nmap_worker() — the per-port scan worker thread function.

    Called directly (not in a background thread): the queue holds exactly one
    work item followed by a poison pill (None), so the worker's internal
    `while not interrupt_event.is_set()` loop processes one item and returns.
    """

    def _make_finished_proc(self, poll_side_effect=None, returncode=0, stderr=''):
        proc = MagicMock()
        proc.poll.return_value = 0
        if poll_side_effect is not None:
            proc.poll.side_effect = poll_side_effect
        proc.wait.return_value = 0
        # Real returncode/stderr: nmap_worker inspects both to decide whether a
        # port actually completed. A bare MagicMock returncode would compare
        # unequal to 0 and look like a failure on every happy-path test.
        proc.returncode = returncode
        proc.stderr = io.StringIO(stderr)
        return proc

    def _run(self, tmp_path, ip_to_hostname=None, script_scan=False,
             target_scan='Internal', popen_side_effect=None, scripts_for_port=''):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/nse_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')

        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)  # poison pill
        completed_count = [0]
        lock = threading.Lock()
        interrupt_event = threading.Event()

        if popen_side_effect is None:
            def popen_side_effect(*a, **k):
                return self._make_finished_proc()

        with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']) as mock_build, \
             patch('spoonmap._get_scripts_for_port', return_value=scripts_for_port), \
             patch('spoonmap.create_hostname_target_file') as mock_hostname_file, \
             patch('spoonmap.subprocess.Popen', side_effect=popen_side_effect) as mock_popen:
            nmap_worker(work_queue, completed_count, 1, '88', lock, interrupt_event,
                       ip_to_hostname, script_scan=script_scan, target_scan=target_scan)

        return completed_count, mock_popen, mock_build, mock_hostname_file, interrupt_event

    def test_normal_scan_completes_and_increments_count(self, tmp_path):
        completed_count, mock_popen, _, mock_hostname_file, _ = self._run(tmp_path)
        assert completed_count[0] == 1
        assert mock_popen.call_count == 1
        assert not mock_hostname_file.called

    def test_hostname_mapping_used_as_input_file(self, tmp_path):
        completed_count, mock_popen, mock_build, mock_hostname_file, _ = self._run(
            tmp_path, ip_to_hostname={'10.0.0.1': 'host1.internal'})
        assert mock_hostname_file.called
        hostname_file_arg = mock_hostname_file.call_args[0][1]
        assert hostname_file_arg.endswith('port80_hostnames.txt')
        # _build_nmap_cmd's input_file positional arg must be the hostname file
        build_args = mock_build.call_args[0]
        assert build_args[1] == hostname_file_arg

    def test_script_scan_runs_second_pass_when_scripts_available(self, tmp_path):
        completed_count, mock_popen, _, _, _ = self._run(
            tmp_path, script_scan=True, scripts_for_port='ftp-anon')
        assert mock_popen.call_count == 2

    def test_script_scan_skips_second_pass_without_scripts(self, tmp_path):
        completed_count, mock_popen, _, _, _ = self._run(
            tmp_path, script_scan=True, scripts_for_port='')
        assert mock_popen.call_count == 1

    def test_interrupt_during_banner_scan_kills_process(self, tmp_path):
        created_procs = []
        poll_calls = {'n': 0}

        def fake_popen(*a, **k):
            def poll_side_effect():
                # Let the polling loop actually iterate a couple of times
                # (exercising interrupt_event.wait()) before the interrupt lands.
                poll_calls['n'] += 1
                if poll_calls['n'] >= 3:
                    interrupt_event.set()
                return None  # still "running" on every poll() call
            proc = self._make_finished_proc(poll_side_effect=poll_side_effect)
            created_procs.append(proc)
            return proc

        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')
        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)
        completed_count = [0]
        lock = threading.Lock()
        interrupt_event = threading.Event()

        with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']), \
             patch('spoonmap.subprocess.Popen', side_effect=fake_popen):
            nmap_worker(work_queue, completed_count, 1, '88', lock, interrupt_event, None)

        assert created_procs[0].kill.called
        # completed_count must NOT increment — the item was interrupted, not completed
        assert completed_count[0] == 0

    def test_file_not_found_error_is_logged(self, tmp_path, capsys):
        completed_count, mock_popen, _, _, _ = self._run(
            tmp_path, popen_side_effect=FileNotFoundError)
        assert 'nmap not found' in capsys.readouterr().out
        assert completed_count[0] == 0

    def test_generic_popen_exception_is_logged(self, tmp_path, capsys):
        completed_count, mock_popen, _, _, _ = self._run(
            tmp_path, popen_side_effect=RuntimeError('boom'))
        out = capsys.readouterr().out
        assert 'Error running nmap for port' in out
        assert completed_count[0] == 0

    def test_exception_before_inner_try_logged_as_worker_error(self, tmp_path, capsys):
        """An exception raised while building the nmap command (before the
        inner try/except) is caught by the outer handler."""
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')
        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)
        completed_count = [0]
        lock = threading.Lock()
        interrupt_event = threading.Event()

        with patch('spoonmap._build_nmap_cmd', side_effect=RuntimeError('bad cmd')):
            nmap_worker(work_queue, completed_count, 1, '88', lock, interrupt_event, None)

        assert 'Worker thread error' in capsys.readouterr().out

    def test_exception_inside_inner_handler_calls_task_done_once(self, tmp_path, capsys):
        """An exception raised *inside* an inner except handler must not double
        up task_done().

        The inner `finally` and the outer `except Exception` both called it, so
        this path decremented the queue's unfinished counter twice for a single
        get().  The second call raises ValueError('task_done() called too many
        times') and kills the worker while the counter has been over-decremented,
        so work_queue.join() returns as though every port had been scanned —
        turning a visible hang into a silently incomplete scan.
        """
        class _CountingQueue(Queue):
            """Records unfinished_tasks after each task_done()."""
            def __init__(self):
                super().__init__()
                self.task_done_calls = 0
                self.remaining_after = []

            def task_done(self):
                self.task_done_calls += 1
                super().task_done()
                self.remaining_after.append(self.unfinished_tasks)

        class _ExplodingLock:
            """Raises on the Nth acquisition, to blow up inside a print()."""
            def __init__(self, fail_on):
                self.fail_on = fail_on
                self.calls = 0

            def __enter__(self):
                self.calls += 1
                if self.calls == self.fail_on:
                    raise RuntimeError('print inside handler blew up')
                return self

            def __exit__(self, *exc_info):
                return False

        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        live = Path(tmp_path) / 'discovery' / 'live_hosts'
        (live / 'port80.txt').write_text('10.0.0.1\n')
        (live / 'port443.txt').write_text('10.0.0.1\n')

        work_queue = _CountingQueue()
        work_queue.put('port80.txt')
        work_queue.put('port443.txt')
        work_queue.put(None)  # poison pill
        completed_count = [0]
        interrupt_event = threading.Event()

        # Acquisition 1: port80's "Grabbing service banners".  Acquisition 2: the
        # inner `except Exception` handler reporting the Popen failure — that is
        # the one that must not leave task_done() to the outer handler as well.
        lock = _ExplodingLock(fail_on=2)
        popen_calls = []

        def fake_popen(*args, **kwargs):
            popen_calls.append(args)
            if len(popen_calls) == 1:
                raise RuntimeError('boom')
            return self._make_finished_proc()

        with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']), \
             patch('spoonmap._get_scripts_for_port', return_value=''), \
             patch('spoonmap.subprocess.Popen', side_effect=fake_popen):
            nmap_worker(work_queue, completed_count, 2, '88', lock,
                        interrupt_event, None)

        assert work_queue.task_done_calls == 3   # one per get(), no more
        # Decisive: after port80 finished, port443 and the pill were still
        # outstanding.  A doubled task_done() would show 1 here, and
        # work_queue.join() would have returned with port443 unscanned.
        assert work_queue.remaining_after == [2, 1, 0]
        assert work_queue.unfinished_tasks == 0
        out = capsys.readouterr().out
        assert 'Worker thread error' in out

    def test_poison_pill_stops_worker_without_processing(self, tmp_path):
        """A lone poison pill (no work item) exits the loop cleanly."""
        spoonmap.output_path = str(tmp_path)
        work_queue = Queue()
        work_queue.put(None)
        completed_count = [0]
        lock = threading.Lock()
        interrupt_event = threading.Event()

        with patch('spoonmap.subprocess.Popen') as mock_popen:
            nmap_worker(work_queue, completed_count, 1, '88', lock, interrupt_event, None)

        assert not mock_popen.called
        assert completed_count[0] == 0

    def test_empty_queue_timeout_continues_loop(self, tmp_path):
        """A queue.Empty from the timed get() is swallowed and the loop retries."""
        spoonmap.output_path = str(tmp_path)
        work_queue = MagicMock()
        work_queue.get.side_effect = [Empty(), None]  # empty once, then poison pill
        completed_count = [0]
        lock = threading.Lock()
        interrupt_event = threading.Event()

        with patch('spoonmap.subprocess.Popen') as mock_popen:
            nmap_worker(work_queue, completed_count, 1, '88', lock, interrupt_event, None)

        assert not mock_popen.called
        assert work_queue.get.call_count == 2
        assert work_queue.task_done.call_count == 1  # only for the poison pill

    def test_non_empty_exception_from_get_is_reported_not_swallowed(self, tmp_path, capsys):
        """The handler around the timed get() used to be a bare `except:`, so it
        caught BaseException: SystemExit, KeyboardInterrupt and any genuine
        failure inside get() alike all became a silent `continue`. Only
        queue.Empty is expected there; anything else must reach the worker's own
        error handler and be printed."""
        spoonmap.output_path = str(tmp_path)
        work_queue = MagicMock()
        # Fails once, then hands over the poison pill so the worker can exit.
        work_queue.get.side_effect = [RuntimeError('queue is broken'), None]
        interrupt_event = threading.Event()

        with patch('spoonmap.subprocess.Popen') as mock_popen:
            nmap_worker(work_queue, [0], 1, '88', threading.Lock(),
                        interrupt_event, None)

        assert not mock_popen.called
        assert 'Worker thread error: queue is broken' in capsys.readouterr().out
        assert work_queue.get.call_count == 2

    def test_interrupt_during_nse_scan_kills_nse_process(self, tmp_path):
        """Banner pass completes normally; the NSE pass gets interrupted mid-run."""
        created_procs = []
        call_count = {'n': 0}
        poll_calls = {'n': 0}

        def fake_popen(*a, **k):
            call_count['n'] += 1
            if call_count['n'] == 1:
                proc = self._make_finished_proc()  # banner pass completes immediately
            else:
                def poll_side_effect():
                    # Let the polling loop iterate a couple of times
                    # (exercising interrupt_event.wait()) before interrupting.
                    poll_calls['n'] += 1
                    if poll_calls['n'] >= 3:
                        interrupt_event.set()
                    return None
                proc = self._make_finished_proc(poll_side_effect=poll_side_effect)
            created_procs.append(proc)
            return proc

        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/nse_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')
        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)
        completed_count = [0]
        lock = threading.Lock()
        interrupt_event = threading.Event()

        with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']), \
             patch('spoonmap._get_scripts_for_port', return_value='ftp-anon'), \
             patch('spoonmap.subprocess.Popen', side_effect=fake_popen):
            nmap_worker(work_queue, completed_count, 1, '88', lock, interrupt_event, None,
                       script_scan=True)

        assert len(created_procs) == 2
        assert created_procs[1].kill.called

    def test_nonzero_exit_reports_failure_and_is_not_counted(self, tmp_path, capsys):
        """A failed banner scan prints a diagnostic naming the port plus nmap's
        stderr, and must not advance the completion counter."""
        completed_count, _, _, _, _ = self._run(
            tmp_path,
            popen_side_effect=lambda *a, **k: self._make_finished_proc(
                returncode=1, stderr='nmap: Illegal port specification\n'))
        out = capsys.readouterr().out
        assert 'port 80 exited with code 1' in out
        assert 'Illegal port specification' in out
        assert completed_count[0] == 0

    def test_failed_banner_pass_quarantines_its_xml_for_resume(self, tmp_path, capsys):
        """A non-zero banner pass that still finalised a valid XML must not
        satisfy the resume gate: nmap exiting non-zero after writing a hostless
        but parseable file (target resolution failure, missing privileges) left
        that port looking scanned forever."""
        def fake_popen(*a, **k):
            # nmap finalises the XML, then exits non-zero.
            Path(f'{tmp_path}/nmap_results/port80.xml').write_text('<nmaprun/>')
            return self._make_finished_proc(returncode=1, stderr='QUITTING!\n')

        self._run(tmp_path, popen_side_effect=fake_popen)

        banner_xml = f'{tmp_path}/nmap_results/port80.xml'
        assert not os.path.exists(banner_xml)
        assert Path(banner_xml + '.failed').read_text() == '<nmaprun/>'
        assert _resume_cache_usable(
            banner_xml, 0, 'port 80 banner scan',
            target_file=f'{tmp_path}/discovery/live_hosts/port80.txt',
            exclusions_file=None) is False
        out = capsys.readouterr().out
        assert 'WILL be re-scanned on resume' in out
        assert 'port80.xml.failed' in out

    def test_failed_nse_pass_quarantines_its_own_xml(self, tmp_path):
        """The NSE pass quarantines nse_results/, not the banner output."""
        call_count = {'n': 0}

        def fake_popen(*a, **k):
            call_count['n'] += 1
            if call_count['n'] == 1:
                Path(f'{tmp_path}/nmap_results/port80.xml').write_text('<nmaprun/>')
                return self._make_finished_proc()
            Path(f'{tmp_path}/nse_results/port80.xml').write_text('<nmaprun/>')
            return self._make_finished_proc(returncode=2, stderr='NSE failed\n')

        self._run(tmp_path, script_scan=True, scripts_for_port='ftp-anon',
                  popen_side_effect=fake_popen)

        # Banner pass succeeded, so its XML stays put.
        assert os.path.exists(f'{tmp_path}/nmap_results/port80.xml')
        assert not os.path.exists(f'{tmp_path}/nse_results/port80.xml')
        assert os.path.exists(f'{tmp_path}/nse_results/port80.xml.failed')

    def test_zero_exit_prints_no_failure_diagnostic(self, tmp_path, capsys):
        """A clean exit counts as completed and prints no failure text."""
        completed_count, _, _, _, _ = self._run(tmp_path)
        assert 'exited with code' not in capsys.readouterr().out
        assert completed_count[0] == 1

    def test_interrupted_nonzero_exit_is_not_reported_as_failure(self, tmp_path, capsys):
        """A process that exits non-zero because it was interrupted must not be
        reported as an nmap failure — otherwise every Ctrl-C spams one error
        per in-flight port."""
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')
        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)
        completed_count = [0]
        lock = threading.Lock()
        interrupt_event = threading.Event()
        poll_calls = {'n': 0}

        def poll_side_effect():
            # Running on the first poll; by the second the interrupt has landed
            # and the process is already gone (killed by signal → rc -9), so
            # the worker takes the normal-exit branch with a non-zero rc.
            poll_calls['n'] += 1
            if poll_calls['n'] == 1:
                return None
            interrupt_event.set()
            return -9

        proc = self._make_finished_proc(poll_side_effect=poll_side_effect,
                                        returncode=-9, stderr='')

        with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']), \
             patch('spoonmap.subprocess.Popen', return_value=proc):
            nmap_worker(work_queue, completed_count, 1, '88', lock, interrupt_event, None)

        assert 'exited with code' not in capsys.readouterr().out
        assert completed_count[0] == 0

    def test_nse_nonzero_exit_reports_failure(self, tmp_path, capsys):
        """The NSE pass gets the same diagnostic; the banner pass still counts."""
        call_count = {'n': 0}

        def fake_popen(*a, **k):
            call_count['n'] += 1
            if call_count['n'] == 1:
                return self._make_finished_proc()
            return self._make_finished_proc(
                returncode=2, stderr="NSE: failed to initialize the script engine\n")

        completed_count, _, _, _, _ = self._run(
            tmp_path, script_scan=True, scripts_for_port='ftp-anon',
            popen_side_effect=fake_popen)
        out = capsys.readouterr().out
        assert 'NSE script pass for port 80 exited with code 2' in out
        assert 'failed to initialize the script engine' in out
        assert completed_count[0] == 1

    def test_interrupted_nse_nonzero_exit_is_not_reported_as_failure(self, tmp_path, capsys):
        """A killed NSE process exits non-zero too — no failure diagnostic."""
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/nse_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')
        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)
        completed_count = [0]
        lock = threading.Lock()
        interrupt_event = threading.Event()
        call_count = {'n': 0}
        poll_calls = {'n': 0}

        def fake_popen(*a, **k):
            call_count['n'] += 1
            if call_count['n'] == 1:
                return self._make_finished_proc()

            def poll_side_effect():
                poll_calls['n'] += 1
                if poll_calls['n'] == 1:
                    return None
                interrupt_event.set()
                return -9

            return self._make_finished_proc(poll_side_effect=poll_side_effect,
                                            returncode=-9, stderr='')

        with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']), \
             patch('spoonmap._get_scripts_for_port', return_value='ftp-anon'), \
             patch('spoonmap.subprocess.Popen', side_effect=fake_popen):
            nmap_worker(work_queue, completed_count, 1, '88', lock, interrupt_event, None,
                       script_scan=True)

        assert 'exited with code' not in capsys.readouterr().out
        assert completed_count[0] == 1

    def test_stderr_is_captured_not_discarded(self, tmp_path):
        """stderr must be piped (so failures are diagnosable) while stdout stays
        DEVNULL, and start_new_session must survive the change.

        Piping alone is not enough — an undrained pipe is worse than DEVNULL —
        so the behavioural half of this contract lives in
        test_stderr_is_drained_while_the_worker_polls below.
        """
        _, mock_popen, _, _, _ = self._run(tmp_path)
        kwargs = mock_popen.call_args[1]
        assert kwargs['stderr'] is spoonmap.subprocess.PIPE
        assert kwargs['stdout'] is spoonmap.subprocess.DEVNULL
        assert kwargs['start_new_session'] is True

    def test_stderr_is_drained_while_the_worker_polls(self, tmp_path):
        """Regression: the same deadlock as #25, reintroduced in nmap_worker.

        Piping stderr without draining it means nmap blocks in write() once the
        ~64 KB pipe buffer fills (a -sV pass against a few thousand hosts on a
        filtered port emits one line per retransmission-cap hit). The worker's
        poll() then never returns non-None and work_queue.join() in nmap_scan()
        hangs forever — a scan that silently stops progressing. A MagicMock is
        not a real pipe, so this models the kernel's behaviour instead: the
        child cannot exit until a reader has arrived, i.e. poll() keeps
        returning None until something consumes stderr. With the pre-fix code
        (read only inside the failure path, after wait()) the worker never
        leaves the poll loop and is still alive after the bounded join.
        """
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')

        stderr_touched = threading.Event()

        class _WatchedStderr(io.StringIO):
            """Signals as soon as anything starts consuming the stream."""

            def __iter__(self):
                stderr_touched.set()
                return io.StringIO.__iter__(self)

            def read(self, *args, **kwargs):
                stderr_touched.set()
                return io.StringIO.read(self, *args, **kwargs)

        proc = MagicMock()
        proc.returncode = 0
        proc.wait.return_value = 0
        proc.stderr = _WatchedStderr(
            'nmap: giving up on port 445 after 10 retransmissions\n' * 1200)
        proc.poll.side_effect = lambda: 0 if stderr_touched.is_set() else None

        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)
        completed_count = [0]
        interrupt_event = threading.Event()

        def _run():
            with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']), \
                 patch('spoonmap._get_scripts_for_port', return_value=''), \
                 patch('spoonmap.subprocess.Popen', return_value=proc):
                nmap_worker(work_queue, completed_count, 1, '88', threading.Lock(),
                            interrupt_event, None)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=5)

        assert not thread.is_alive()
        assert stderr_touched.is_set()
        assert completed_count[0] == 1

    def test_worker_survives_a_stderr_reader_that_never_finishes(self, tmp_path):
        """The stderr reader joins are bounded, so an fd held open past the
        child's exit cannot strand the worker.

        The child is reaped before every join, so the reader has normally already
        ended — but nmap's own helper processes can inherit the stderr fd, and an
        inherited write end keeps the read end from ever seeing EOF. An unbounded
        join() there parks this worker for the rest of the scan while
        work_queue.join() waits on it. The thread is a daemon and its lines are
        already collected, so the wait was only ever a courtesy.
        """
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')

        release_reader = threading.Event()

        class _NeverClosedStderr:
            """Models an inherited write end: iteration blocks, never hits EOF."""

            def __iter__(self):
                release_reader.wait(30)
                return iter(())

        proc = MagicMock()
        proc.returncode = 0
        proc.wait.return_value = 0
        proc.poll.return_value = 0
        proc.stderr = _NeverClosedStderr()

        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)
        completed_count = [0]
        interrupt_event = threading.Event()

        def _run():
            with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']), \
                 patch('spoonmap._get_scripts_for_port', return_value=''), \
                 patch('spoonmap._STDERR_JOIN_TIMEOUT', 0.2), \
                 patch('spoonmap.subprocess.Popen', return_value=proc):
                nmap_worker(work_queue, completed_count, 1, '88', threading.Lock(),
                            interrupt_event, None)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=5)
        try:
            assert not thread.is_alive()
            assert completed_count[0] == 1
        finally:
            # Let the reader thread exit so it does not outlive the test.
            release_reader.set()


def _fake_worker_drain(work_queue, completed_count, total_count, source_port, lock,
                       interrupt_event, ip_to_hostname, script_scan, target_scan, start_time):
    """Stand-in for nmap_worker() used by TestNmapScan — drains real queue
    items instantly instead of spawning subprocesses, so nmap_scan()'s own
    orchestration logic (queuing, resume-skip, join/poison-pill, thread
    lifecycle) is exercised without any real nmap invocation."""
    while True:
        item = work_queue.get()
        if item is None:
            work_queue.task_done()
            break
        completed_count[0] += 1
        work_queue.task_done()


class TestNmapScan:
    """Unit tests for nmap_scan() — worker-pool orchestration around nmap_worker()."""

    def test_no_live_hosts_dir_returns_early(self, tmp_path, capsys):
        spoonmap.output_path = str(tmp_path)
        nmap_scan('88', max_threads=2)
        assert 'skipping nmap scan' in capsys.readouterr().out

    def test_empty_live_hosts_dir_returns_early(self, tmp_path, capsys):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        nmap_scan('88', max_threads=2)
        assert 'No open ports found' in capsys.readouterr().out

    def test_already_scanned_ports_skipped(self, tmp_path, capsys):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        os.makedirs(f'{tmp_path}/nmap_results')
        live = Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt'
        live.write_text('10.0.0.1\n')
        cached = Path(tmp_path) / 'nmap_results' / 'port80.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, live)

        with patch('spoonmap.nmap_worker') as mock_worker:
            nmap_scan('88', max_threads=2, script_scan=False)

        assert not mock_worker.called
        assert 'already been scanned' in capsys.readouterr().out

    def test_only_hostname_files_reports_no_open_ports(self, tmp_path, capsys):
        """A live_hosts/ holding nothing but derived _hostnames.txt files means
        discovery found no open ports. The message was chosen from the raw
        listdir while the scan list was filtered, so it claimed everything had
        already been scanned."""
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80_hostnames.txt').write_text(
            'host1.internal\n')

        with patch('spoonmap.nmap_worker') as mock_worker:
            nmap_scan('88', max_threads=2)

        assert not mock_worker.called
        out = capsys.readouterr().out
        assert 'No open ports found' in out
        assert 'already been scanned' not in out

    def _setup_banner_cache(self, tmp_path, xml_text):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        os.makedirs(f'{tmp_path}/nmap_results')
        os.makedirs(f'{tmp_path}/nse_results')
        live = Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt'
        live.write_text('10.0.0.1\n')
        cached = Path(tmp_path) / 'nmap_results' / 'port80.xml'
        cached.write_text(xml_text)
        # Stamped so these fixtures isolate the condition they name: without a
        # coverage record the gate rejects for that reason instead, and every
        # "stays skipped" assertion would pass or hang for the wrong cause.
        _write_target_stamp(cached, live)
        return live

    def test_zero_length_banner_xml_is_rescanned(self, tmp_path, capsys):
        # nmap_worker's own docstring notes an individual nmap PID can be killed
        # externally; that leaves a zero-length portN.xml which the old
        # existence-only check treated as done forever.
        self._setup_banner_cache(tmp_path, '')

        with patch('spoonmap.nmap_worker', side_effect=_fake_worker_drain) as mock_worker:
            nmap_scan('88', max_threads=2, script_scan=False)

        assert mock_worker.called
        out = capsys.readouterr().out
        assert 're-running port 80 banner scan' in out
        assert 'already been scanned' not in out

    def test_unparseable_banner_xml_is_rescanned(self, tmp_path, capsys):
        self._setup_banner_cache(tmp_path, '<nmaprun><host>')  # unclosed tags

        with patch('spoonmap.nmap_worker', side_effect=_fake_worker_drain) as mock_worker:
            nmap_scan('88', max_threads=2, script_scan=False)

        assert mock_worker.called
        out = capsys.readouterr().out
        assert 're-running port 80 banner scan' in out
        assert 'already been scanned' not in out

    def _setup_nse_cache(self, tmp_path, nse_xml_text):
        """Complete banner result plus an NSE result holding *nse_xml_text*."""
        live = self._setup_banner_cache(tmp_path, '<nmaprun/>')
        cached = Path(tmp_path) / 'nse_results' / 'port80.xml'
        cached.write_text(nse_xml_text)
        _write_target_stamp(cached, live)
        return live

    def test_both_passes_complete_skips_port(self, tmp_path, capsys):
        # Load-bearing direction for the NSE half: valid banner + valid NSE
        # output must stay skipped under script_scan=True.
        self._setup_nse_cache(tmp_path, '<nmaprun/>')

        with patch('spoonmap.nmap_worker') as mock_worker, \
             patch('spoonmap._get_scripts_for_port', return_value='ftp-anon'):
            nmap_scan('88', max_threads=2, script_scan=True)

        assert not mock_worker.called
        assert 'already been scanned' in capsys.readouterr().out

    def test_zero_length_nse_xml_is_rescanned(self, tmp_path, capsys):
        self._setup_nse_cache(tmp_path, '')

        with patch('spoonmap.nmap_worker', side_effect=_fake_worker_drain) as mock_worker, \
             patch('spoonmap._get_scripts_for_port', return_value='ftp-anon'):
            nmap_scan('88', max_threads=2, script_scan=True)

        assert mock_worker.called
        out = capsys.readouterr().out
        assert 're-running port 80 NSE scan' in out
        assert 'already been scanned' not in out

    def test_unparseable_nse_xml_is_rescanned(self, tmp_path, capsys):
        self._setup_nse_cache(tmp_path, '<nmaprun><host>')  # unclosed tags

        with patch('spoonmap.nmap_worker', side_effect=_fake_worker_drain) as mock_worker, \
             patch('spoonmap._get_scripts_for_port', return_value='ftp-anon'):
            nmap_scan('88', max_threads=2, script_scan=True)

        assert mock_worker.called
        assert 're-running port 80 NSE scan' in capsys.readouterr().out

    def test_unscanned_ports_dispatched_to_workers(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        os.makedirs(f'{tmp_path}/nmap_results')
        os.makedirs(f'{tmp_path}/nse_results')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')

        with patch('spoonmap.nmap_worker', side_effect=_fake_worker_drain):
            nmap_scan('88', max_threads=2, script_scan=False)
        # No exception / hang == the queue was correctly drained and joined.

    def test_file_not_found_error_logged(self, tmp_path, capsys):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        with patch('spoonmap.os.listdir', side_effect=FileNotFoundError):
            nmap_scan('88', max_threads=2)
        assert 'live_hosts directory not found' in capsys.readouterr().out

    def test_generic_exception_logged(self, tmp_path, capsys):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        with patch('spoonmap.os.listdir', side_effect=RuntimeError('boom')):
            nmap_scan('88', max_threads=2)
        assert 'Error during nmap scan' in capsys.readouterr().out

    def test_keyboard_interrupt_sets_event_and_reraises(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        os.makedirs(f'{tmp_path}/nmap_results')
        os.makedirs(f'{tmp_path}/nse_results')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')

        captured_event = {}

        def fake_worker(work_queue, completed_count, total_count, source_port, lock,
                        interrupt_event, ip_to_hostname, script_scan, target_scan, start_time):
            captured_event['event'] = interrupt_event
            # Never drains the queue — join() below will block until we
            # interrupt it via the patched Queue.join raising KeyboardInterrupt.

        with patch('spoonmap.nmap_worker', side_effect=fake_worker), \
             patch('spoonmap.Queue') as mock_queue_cls:
            mock_queue = MagicMock()
            mock_queue.join.side_effect = KeyboardInterrupt
            mock_queue_cls.return_value = mock_queue
            with pytest.raises(KeyboardInterrupt):
                nmap_scan('88', max_threads=1, script_scan=False)

        assert captured_event['event'].is_set()

    def test_hostnames_txt_file_filtered_out(self, tmp_path):
        """port80_hostnames.txt should not be queued; only port80.txt should be."""
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        os.makedirs(f'{tmp_path}/nmap_results')
        os.makedirs(f'{tmp_path}/nse_results')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80_hostnames.txt').write_text('host1.internal\n')

        queued_files = []

        def fake_worker_capture(work_queue, completed_count, total_count, source_port, lock,
                                interrupt_event, ip_to_hostname, script_scan, target_scan, start_time):
            while True:
                item = work_queue.get()
                if item is None:
                    work_queue.task_done()
                    break
                queued_files.append(item)
                completed_count[0] += 1
                work_queue.task_done()

        with patch('spoonmap.nmap_worker', side_effect=fake_worker_capture):
            nmap_scan('88', max_threads=2, script_scan=False)

        assert queued_files == ['port80.txt']
        assert 'port80_hostnames.txt' not in queued_files

    def test_udp_port_with_hostnames_filtered(self, tmp_path):
        """portU_500.txt should queue U:500; portU_500_hostnames.txt should not."""
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        os.makedirs(f'{tmp_path}/nmap_results')
        os.makedirs(f'{tmp_path}/nse_results')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'portU_500.txt').write_text('10.0.0.2\n')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'portU_500_hostnames.txt').write_text('host2.internal\n')

        queued_files = []

        def fake_worker_capture(work_queue, completed_count, total_count, source_port, lock,
                                interrupt_event, ip_to_hostname, script_scan, target_scan, start_time):
            while True:
                item = work_queue.get()
                if item is None:
                    work_queue.task_done()
                    break
                queued_files.append(item)
                completed_count[0] += 1
                work_queue.task_done()

        with patch('spoonmap.nmap_worker', side_effect=fake_worker_capture):
            nmap_scan('88', max_threads=2, script_scan=False)

        assert queued_files == ['portU_500.txt']
        assert 'portU_500_hostnames.txt' not in queued_files

    def test_stray_ds_store_filtered_out(self, tmp_path):
        """Stray .DS_Store file should not be queued."""
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        os.makedirs(f'{tmp_path}/nmap_results')
        os.makedirs(f'{tmp_path}/nse_results')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt').write_text('10.0.0.3\n')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / '.DS_Store').write_text('junk\n')

        queued_files = []

        def fake_worker_capture(work_queue, completed_count, total_count, source_port, lock,
                                interrupt_event, ip_to_hostname, script_scan, target_scan, start_time):
            while True:
                item = work_queue.get()
                if item is None:
                    work_queue.task_done()
                    break
                queued_files.append(item)
                completed_count[0] += 1
                work_queue.task_done()

        with patch('spoonmap.nmap_worker', side_effect=fake_worker_capture):
            nmap_scan('88', max_threads=2, script_scan=False)

        assert queued_files == ['port80.txt']
        assert '.DS_Store' not in queued_files

    def test_already_scanned_ports_still_skipped_with_filter(self, tmp_path, capsys):
        """Existing test_already_scanned_ports_skipped behavior still works with the new filter."""
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts')
        os.makedirs(f'{tmp_path}/nmap_results')
        live = Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt'
        live.write_text('10.0.0.1\n')
        (Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80_hostnames.txt').write_text('host.internal\n')
        cached = Path(tmp_path) / 'nmap_results' / 'port80.xml'
        cached.write_text('<nmaprun/>')
        # Recorded against the IP list, not the _hostnames.txt variant: the gate
        # keys on the canonical per-port list even when nmap gets the other one.
        _write_target_stamp(cached, live)

        with patch('spoonmap.nmap_worker') as mock_worker:
            nmap_scan('88', max_threads=2, script_scan=False)

        assert not mock_worker.called
        assert 'already been scanned' in capsys.readouterr().out


# ── cucm-detect finding ───────────────────────────────────────────────────────

class TestCucmDetectFinding:
    def test_confirmed_cucm_generates_high_finding(self, nmap_dir):
        """cucm-detect script output → HIGH 'Cisco CUCM TFTP Server Confirmed'."""
        xml = _nmap_xml('10.0.0.1', 'tcp', '6970',
                        scripts={'cucm-detect': 'Product: Cisco UCM\nConfigFileCacheList: Accessible \u2014 100 entries'})
        (nmap_dir / 'nse_results' / 'port6970.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'CUCM TFTP Server Confirmed' in txt
        assert 'HIGH' in txt

    def test_port_open_no_script_generates_medium_finding(self, nmap_dir):
        """Port 6970 open, no cucm-detect output → MEDIUM 'Possible Cisco CUCM'."""
        xml = _nmap_xml('10.0.0.2', 'tcp', '6970')
        (nmap_dir / 'nse_results' / 'port6970.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'Possible Cisco CUCM' in txt
        assert 'MEDIUM' in txt

    def test_confirmed_cucm_not_medium(self, nmap_dir):
        """Confirmed CUCM does not also emit the MEDIUM unconfirmed finding."""
        xml = _nmap_xml('10.0.0.3', 'tcp', '6970',
                        scripts={'cucm-detect': 'Product: Cisco UCM\nConfigFileCacheList: Accessible \u2014 50 entries'})
        (nmap_dir / 'nse_results' / 'port6970.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'Possible Cisco CUCM' not in txt


class TestLdapSecurityFindings:
    """Custom NSE-validated LDAP security findings."""

    def test_ldap_signing_not_required_high(self, nmap_dir):
        """ldap-signing-check returning 'Signing: NOT REQUIRED' -> HIGH finding."""
        xml = _nmap_xml('10.10.0.1', 'tcp', '389',
                        scripts={'ldap-signing-check': 'Signing: NOT REQUIRED'})
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAP Signing Not Required' in content
        assert 'HIGH' in content
        assert '10.10.0.1' in content

    def test_ldap_signing_required_no_finding(self, nmap_dir):
        """ldap-signing-check absent (signing enforced, script returned nil) -> no finding."""
        xml = _nmap_xml('10.10.0.2', 'tcp', '389')
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'LDAP Signing Not Required' not in findings_file.read_text()

    def test_ldap_channel_binding_not_required_high(self, nmap_dir):
        """ldap-channel-binding-check returning 'NOT REQUIRED' -> HIGH finding."""
        xml = _nmap_xml('10.10.0.3', 'tcp', '636',
                        scripts={'ldap-channel-binding-check': 'Channel Binding: NOT REQUIRED'})
        (nmap_dir / 'nse_results' / 'port636.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAPS Channel Binding Not Required' in content
        assert 'HIGH' in content

    def test_ldap_anon_enum_users_medium(self, nmap_dir):
        """ldap-anon-enum with Users found -> MEDIUM finding."""
        xml = _nmap_xml('10.10.0.4', 'tcp', '389',
                        scripts={'ldap-anon-enum':
                                 'Anonymous bind: success\n'
                                 'Base DN: DC=pwnt,DC=lab\n'
                                 'Sample Users Found: j.smith, k.jones'})
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAP Anonymous Enumeration' in content
        assert 'MEDIUM' in content

    def test_ldap_anon_enum_computers_medium(self, nmap_dir):
        """ldap-anon-enum with Computers found -> MEDIUM finding."""
        xml = _nmap_xml('10.10.0.5', 'tcp', '389',
                        scripts={'ldap-anon-enum':
                                 'Anonymous bind: success\n'
                                 'Base DN: DC=pwnt,DC=lab\n'
                                 'Sample Computers Found: WS-SALES01$'})
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAP Anonymous Enumeration' in content

    def test_ldap_anon_enum_no_results_no_finding(self, nmap_dir):
        """ldap-anon-enum script absent (bind ok but 0 results) -> no finding."""
        xml = _nmap_xml('10.10.0.6', 'tcp', '389')
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'LDAP Anonymous Enumeration' not in findings_file.read_text()

    def test_ldap_findings_not_on_external(self, nmap_dir):
        """LDAP signing finding must not fire for External scans."""
        xml = _nmap_xml('1.2.3.4', 'tcp', '389',
                        scripts={'ldap-signing-check': 'Signing: NOT REQUIRED',
                                 'ldap-anon-enum': 'Users found: 5'})
        (nmap_dir / 'nse_results' / 'port389.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        # External scan only triggers the 'LDAP -- should not be internet-facing' finding
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'LDAP Signing Not Required' not in content
        assert 'LDAP Anonymous Enumeration' not in content

    def test_ldap_global_catalog_signing_port_3268(self, nmap_dir):
        """Port 3268 with ldap-signing-check -> 'Global Catalog Signing Not Required'."""
        xml = _nmap_xml('10.10.0.7', 'tcp', '3268',
                        scripts={'ldap-signing-check': 'Signing: NOT REQUIRED'})
        (nmap_dir / 'nse_results' / 'port3268.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Global Catalog Signing Not Required' in content


class TestIPMIFindings:
    """IPMI findings from ipmi-cipher-zero, ipmi-hashdump, and ipmi-version scripts."""

    def test_cipher_zero_vulnerable_critical(self, nmap_dir):
        """ipmi-cipher-zero output contains VULNERABLE -> CRITICAL finding."""
        xml = _nmap_xml('10.0.1.1', 'udp', '623',
                        scripts={'ipmi-cipher-zero': 'VULNERABLE (cipher suite 0)'})
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IPMI Cipher Zero Authentication Bypass' in content
        # CVE-2013-4786 is the RAKP hash-disclosure CVE, not cipher zero — must not be attached here
        assert 'CVE-2013-4786' not in content
        assert 'CRITICAL' in content
        assert '10.0.1.1' in content

    def test_cipher_zero_not_vulnerable_no_finding(self, nmap_dir):
        """ipmi-cipher-zero output does not contain VULNERABLE -> no CRITICAL finding."""
        xml = _nmap_xml('10.0.1.2', 'udp', '623',
                        scripts={'ipmi-cipher-zero': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'IPMI Cipher Zero Authentication Bypass' not in findings_file.read_text()

    def test_hashdump_hash_captured_high(self, nmap_dir):
        """ipmi-hashdump output contains $rakp$ -> HIGH finding."""
        xml = _nmap_xml(
            '10.0.1.3', 'udp', '623',
            scripts={'ipmi-hashdump': 'Username: admin\nHash: $rakp$aabbcc$ddeeff'})
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IPMI RAKP Hash Disclosure (CVE-2013-4786)' in content
        assert 'HIGH' in content
        assert '10.0.1.3' in content

    def test_hashdump_empty_no_finding(self, nmap_dir):
        """ipmi-hashdump absent (no hash returned) -> no HIGH finding."""
        xml = _nmap_xml('10.0.1.4', 'udp', '623')
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'IPMI RAKP Hash Disclosure' not in findings_file.read_text()

    def test_ipmi_version_detected_info(self, nmap_dir):
        """ipmi-version non-empty output -> LOW finding."""
        xml = _nmap_xml(
            '10.0.1.5', 'udp', '623',
            scripts={'ipmi-version': 'Version: 2.0\nUser Level: Administrator'})
        (nmap_dir / 'nse_results' / 'portU:623.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IPMI Service Detected' in content
        assert 'LOW' in content
        assert '10.0.1.5' in content


class TestExternalExposureVulnScripts:
    """External sensitive ports are layered with curated + broad vuln checks."""

    def test_sensitive_port_gets_curated_and_categories(self):
        scripts = _get_scripts_for_port('445', 'External')
        assert 'smb-vuln-ms17-010' in scripts
        assert 'vuln' in scripts.split(',')
        assert 'vulners' in scripts.split(',')

    def test_no_duplicate_scripts(self):
        # U:623 already lists ipmi-cipher-zero in EXTERNAL_PORT_SCRIPTS and the
        # curated set — it must appear only once.
        toks = _get_scripts_for_port('U:623', 'External').split(',')
        assert toks.count('ipmi-cipher-zero') == 1

    def test_internal_scan_not_augmented(self):
        scripts = _get_scripts_for_port('445', 'Internal')
        assert 'vulners' not in scripts

    def test_non_sensitive_external_port_unchanged(self):
        # 80 is not in EXTERNAL_SENSITIVE_PORTS and has no external scripts
        assert _get_scripts_for_port('80', 'External') is None

    def test_external_exposure_scripts_empty_for_non_sensitive(self):
        assert _external_exposure_scripts('80') == ''

    def test_script_only_cmd_adds_sv_for_vulners(self):
        cmd = _build_nmap_cmd('445', 'in.txt', 'out.xml', '',
                              script_scan=True, target_scan='External', script_only=True)
        assert '-sV' in cmd
        joined = ' '.join(cmd)
        assert 'vulners' in joined and 'smb-vuln-ms17-010' in joined

    def test_internal_script_only_cmd_has_no_vulners(self):
        cmd = _build_nmap_cmd('445', 'in.txt', 'out.xml', '',
                              script_scan=True, target_scan='Internal', script_only=True)
        assert 'vulners' not in ' '.join(cmd)


class TestSummarizeVulns:
    def test_vulnerable_with_cve(self):
        hits = _summarize_vulns({'smb-vuln-ms17-010': 'State: VULNERABLE\nIDs: CVE:CVE-2017-0143'})
        assert hits == ['smb-vuln-ms17-010: VULNERABLE (CVE-2017-0143)']

    def test_not_vulnerable_ignored(self):
        assert _summarize_vulns({'smb-vuln-ms08-067': 'NOT VULNERABLE'}) == []

    def test_vulners_cve_listing(self):
        hits = _summarize_vulns({'vulners': 'cpe:/a:x\n\tCVE-2021-1234\t7.5\n\tCVE-2020-9999\t5.0'})
        assert hits == ['vulners: CVE-2020-9999, CVE-2021-1234']

    def test_non_vuln_script_ignored(self):
        assert _summarize_vulns({'ssl-cert': 'Subject: commonName=example'}) == []

    def test_empty_output_ignored(self):
        assert _summarize_vulns({'smb-vuln-ms17-010': ''}) == []


class TestExternalExposureVulnEmbed:
    """'Service Exposed Externally' findings embed vuln-check results."""

    def test_exposed_smb_embeds_vulnerable_result(self, nmap_dir):
        xml = _nmap_xml('10.0.0.5', 'tcp', '445',
                        scripts={'smb-vuln-ms17-010': 'State: VULNERABLE\nIDs: CVE:CVE-2017-0143'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Service Exposed Externally' in content
        assert 'Vuln check:' in content
        assert 'VULNERABLE' in content
        assert 'CVE-2017-0143' in content

    def test_exposed_service_without_vuln_notes_clean(self, nmap_dir):
        xml = _nmap_xml('10.0.0.6', 'tcp', '445',
                        scripts={'smb-security-mode': 'message signing enabled and required'})
        (nmap_dir / 'nse_results' / 'port445.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Service Exposed Externally' in content
        assert 'no known vulnerabilities detected' in content

    def test_external_ftp_exposure_rated_low_plaintext(self, nmap_dir):
        xml = _nmap_xml('10.0.0.7', 'tcp', '21', scripts={})
        (nmap_dir / 'nse_results' / 'port21.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        exp = [r for r in records
               if r['title'] == 'Service Exposed Externally' and r['host'] == '10.0.0.7']
        assert exp and exp[0]['severity'] == 'LOW'
        assert 'plaintext' in exp[0]['detail'].lower()

    def test_external_telnet_exposure_rated_low_plaintext(self, nmap_dir):
        xml = _nmap_xml('10.0.0.8', 'tcp', '23', scripts={})
        (nmap_dir / 'nse_results' / 'port23.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        records = json.loads((nmap_dir / 'findings.json').read_text())
        exp = [r for r in records
               if r['title'] == 'Service Exposed Externally' and r['host'] == '10.0.0.8']
        assert exp and exp[0]['severity'] == 'LOW'
        assert 'plaintext' in exp[0]['detail'].lower()


class TestWsusDetection:
    """WSUS ports are registered and wsus-detect emits a LOW identification finding."""

    def test_wsus_ports_in_specialized_category(self):
        assert '8530' in SERVICE_CATEGORIES['Specialized']
        assert '8531' in SERVICE_CATEGORIES['Specialized']

    def test_wsus_ports_in_sensitive_list(self):
        keys = {t[0] for t in EXTERNAL_SENSITIVE_PORTS}
        assert '8530' in keys and '8531' in keys

    def test_wsus_scripts_mapped_both_scans(self):
        for scan in ('External', 'Internal'):
            for port in ('8530', '8531'):
                scripts = _get_scripts_for_port(port, scan)
                assert 'wsus-detect.nse' in scripts

    def test_wsus_finding_is_low_with_cve_review_pointer(self, nmap_dir):
        xml = _nmap_xml('10.0.0.9', 'tcp', '8530',
                        scripts={'wsus-detect': 'Microsoft WSUS detected (/ClientWebService/client.asmx)'})
        (nmap_dir / 'nse_results' / 'port8530.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        txt = (nmap_dir / 'findings.txt').read_text()
        assert 'WSUS Service Detected' in txt
        assert '10.0.0.9' in txt
        records = json.loads((nmap_dir / 'findings.json').read_text())
        wsus = [r for r in records if r['title'] == 'WSUS Service Detected']
        assert wsus and wsus[0]['severity'] == 'LOW'
        assert 'CVE-2025-59287' in wsus[0]['detail']

    def test_no_wsus_finding_without_script_output(self, nmap_dir):
        xml = _nmap_xml('10.0.0.9', 'tcp', '8530', scripts={})
        (nmap_dir / 'nse_results' / 'port8530.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        if (nmap_dir / 'findings.txt').exists():
            assert 'WSUS Service Detected' not in (nmap_dir / 'findings.txt').read_text()


class TestVNCFindings:
    """VNC findings from vnc-info, realvnc-auth-bypass and vnc-title scripts."""

    def test_vnc_no_auth_critical(self, nmap_dir):
        """vnc-info output with security type None -> CRITICAL finding."""
        xml = _nmap_xml(
            '10.0.2.1', 'tcp', '5900',
            scripts={'vnc-info': 'Protocol version: 3.8\nSecurity types:\n  None (1)\n  VNC Authentication (2)'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'VNC No Authentication Required' in content
        assert 'CRITICAL' in content
        assert '10.0.2.1' in content

    def test_vnc_auth_required_no_finding(self, nmap_dir):
        """vnc-info output with only VNC Authentication -> no CRITICAL finding."""
        xml = _nmap_xml(
            '10.0.2.2', 'tcp', '5900',
            scripts={'vnc-info': 'Protocol version: 3.8\nSecurity types:\n  VNC Authentication (2)'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'VNC No Authentication Required' not in findings_file.read_text()

    def test_realvnc_bypass_vulnerable_high(self, nmap_dir):
        """realvnc-auth-bypass output contains VULNERABLE -> HIGH finding."""
        xml = _nmap_xml(
            '10.0.2.3', 'tcp', '5900',
            scripts={'realvnc-auth-bypass': 'VULNERABLE\n  RealVNC 4.1.1 Authentication Bypass'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'RealVNC Authentication Bypass' in content
        assert 'HIGH' in content
        assert '10.0.2.3' in content

    def test_realvnc_bypass_not_vulnerable_no_finding(self, nmap_dir):
        """realvnc-auth-bypass output contains NOT VULNERABLE -> no finding."""
        xml = _nmap_xml(
            '10.0.2.4', 'tcp', '5900',
            scripts={'realvnc-auth-bypass': 'NOT VULNERABLE'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'RealVNC Authentication Bypass' not in findings_file.read_text()

    def test_vnc_on_port_5901(self, nmap_dir):
        """vnc-info no-auth on port 5901 -> CRITICAL finding."""
        xml = _nmap_xml(
            '10.0.2.5', 'tcp', '5901',
            scripts={'vnc-info': 'Protocol version: 3.8\nSecurity types:\n  None (1)'})
        (nmap_dir / 'nse_results' / 'port5901.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'VNC No Authentication Required' in content
        assert 'CRITICAL' in content
        assert '10.0.2.5' in content

    def test_vnc_title_output_low_finding(self, nmap_dir):
        """vnc-title returning a desktop name -> LOW finding carrying the name."""
        xml = _nmap_xml(
            '10.0.2.6', 'tcp', '5900',
            scripts={'vnc-title': '\n  name: root\'s X desktop (kiosk01:0)'
                                  '\n  geometry: 1024 x 768\n  color_depth: 24'})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'VNC Desktop Name Disclosed' in content
        assert 'LOW' in content
        assert '10.0.2.6' in content
        assert 'kiosk01:0' in content
        # Multi-line NSE table must be collapsed to one line in findings.txt
        assert 'color_depth: 24' in content
        for line in content.splitlines():
            if 'kiosk01:0' in line:
                assert 'geometry: 1024 x 768' in line

    def test_vnc_title_on_port_5901(self, nmap_dir):
        """vnc-title finding also fires on 5901 and on Internal scans."""
        xml = _nmap_xml(
            '10.0.2.7', 'tcp', '5901',
            scripts={'vnc-title': '\n  name: build-agent\n  geometry: 800 x 600'})
        (nmap_dir / 'nse_results' / 'port5901.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'VNC Desktop Name Disclosed' in content
        assert '10.0.2.7' in content

    def test_vnc_title_blank_output_no_finding(self, nmap_dir):
        """Whitespace-only vnc-title output -> no finding."""
        xml = _nmap_xml('10.0.2.8', 'tcp', '5900', scripts={'vnc-title': '   \n  '})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'VNC Desktop Name Disclosed' not in findings_file.read_text()

    def test_vnc_title_error_output_no_finding(self, nmap_dir):
        """vnc-title ERROR output (login failed) -> no finding."""
        xml = _nmap_xml(
            '10.0.2.9', 'tcp', '5900',
            scripts={'vnc-title': "ERROR: Couldn't log in: Authentication failed"})
        (nmap_dir / 'nse_results' / 'port5900.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            assert 'VNC Desktop Name Disclosed' not in findings_file.read_text()


class TestVNCTitleScriptWiring:
    """vnc-title is mapped to 5900/5901 and does not collide on --source-port."""

    @pytest.mark.parametrize('port', ['5900', '5901'])
    @pytest.mark.parametrize('scan', ['External', 'Internal'])
    def test_vnc_title_mapped_both_scans(self, port, scan):
        scripts = _get_scripts_for_port(port, scan).split(',')
        assert 'vnc-title' in scripts
        assert 'vnc-info' in scripts
        assert 'realvnc-auth-bypass' in scripts

    @pytest.mark.parametrize('port', ['5900', '5901'])
    def test_vnc_script_pass_omits_source_port(self, port):
        """Three concurrent RFB scripts on one port must not share a 4-tuple."""
        cmd = _build_nmap_cmd(port, '/in.txt', '/out.xml', '53',
                              script_scan=True, target_scan='External',
                              script_only=True)
        assert '--source-port' not in cmd
        assert 'vnc-title' in cmd[cmd.index('--script') + 1]

    @pytest.mark.parametrize('port', ['5900', '5901'])
    def test_vnc_banner_pass_keeps_source_port(self, port):
        """Banner pass runs no scripts, so the source port is still usable."""
        cmd = _build_nmap_cmd(port, '/in.txt', '/out.xml', '53',
                              script_scan=False, target_scan='External')
        assert '--source-port' in cmd


class TestIKEFindings:
    """IKE findings from ike-version script on U:500."""

    def test_ike_aggressive_psk_high(self, nmap_dir):
        """ike-version output with 'aggressive' and 'psk' -> HIGH finding."""
        xml = _nmap_xml(
            '10.0.3.1', 'udp', '500',
            scripts={'ike-version': 'Aggressive mode: yes\n  auth: PSK\n  vendor: strongSwan'})
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IKE Aggressive Mode with Pre-Shared Key' in content
        assert 'HIGH' in content
        assert '10.0.3.1' in content

    def test_ike_main_mode_only_info(self, nmap_dir):
        """ike-version output without 'aggressive' keyword -> LOW, no HIGH."""
        xml = _nmap_xml(
            '10.0.3.2', 'udp', '500',
            scripts={'ike-version': 'Main mode: supported\n  vendor: Cisco'})
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IKE/IPsec Service Detected' in content
        assert 'IKE Aggressive Mode with Pre-Shared Key' not in content

    def test_ike_aggressive_no_psk_info(self, nmap_dir):
        """ike-version output with 'aggressive' but auth RSA (not PSK) -> LOW, no HIGH."""
        xml = _nmap_xml(
            '10.0.3.3', 'udp', '500',
            scripts={'ike-version': 'Aggressive mode: yes\n  auth: RSA\n  vendor: OpenSwan'})
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'IKE/IPsec Service Detected' in content
        assert 'IKE Aggressive Mode with Pre-Shared Key' not in content

    def test_ike_empty_output_no_finding(self, nmap_dir):
        """ike-version absent -> no finding at all."""
        xml = _nmap_xml('10.0.3.4', 'udp', '500')
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            content = findings_file.read_text()
            assert 'IKE' not in content

    def test_ike_port_not_flagged_as_service_exposed(self, nmap_dir):
        """U:500 must not produce a 'Service Exposed Externally' finding even when confirmed open."""
        xml = _nmap_xml(
            '10.0.3.5', 'udp', '500',
            scripts={'ike-version': 'Main mode: supported\n  vendor: Cisco'})
        (nmap_dir / 'nse_results' / 'portU_500.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Service Exposed Externally' not in content
        assert 'IKE/IPsec Service Detected' in content


class TestOpenVPNFindings:
    """OpenVPN findings from the custom openvpn-detect script on 1194 (UDP + TCP)."""

    def test_openvpn_udp_detected_low(self, nmap_dir):
        """openvpn-detect's multi-line output on udp/1194 -> flattened LOW finding."""
        xml = _nmap_xml(
            '10.0.4.1', 'udp', '1194',
            scripts={'openvpn-detect':
                     'OpenVPN server confirmed via control-channel handshake\n'
                     '  Handshake: P_CONTROL_HARD_RESET_SERVER_V2\n'
                     '  Transport: udp\n'
                     '  Version  : not disclosed pre-authentication (requires the TLS control channel)'})
        (nmap_dir / 'nse_results' / 'portU_1194.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'OpenVPN Service Detected' in content
        assert 'LOW' in content
        assert '10.0.4.1' in content

        # Multi-line NSE output must be flattened to one line for the 'detail'
        # field so findings.md's markdown table doesn't break on an embedded
        # newline (mirrors the azure-sql-detect flattening fix).
        records = json.loads((nmap_dir / 'findings.json').read_text())
        openvpn = [r for r in records if r['title'] == 'OpenVPN Service Detected']
        assert openvpn and openvpn[0]['severity'] == 'LOW'
        assert '\n' not in openvpn[0]['detail']
        assert 'Handshake: P_CONTROL_HARD_RESET_SERVER_V2; Transport: udp' in openvpn[0]['detail']

        md = (nmap_dir / 'findings.md').read_text()
        matching_lines = [ln for ln in md.splitlines() if '10.0.4.1' in ln]
        assert len(matching_lines) == 1
        row = matching_lines[0]
        assert row.startswith('| `10.0.4.1`') and row.endswith('|')

    def test_openvpn_tcp_detected_low(self, nmap_dir):
        """openvpn-detect's multi-line output on tcp/1194 -> flattened LOW finding."""
        xml = _nmap_xml(
            '10.0.4.2', 'tcp', '1194',
            scripts={'openvpn-detect':
                     'OpenVPN server confirmed via control-channel handshake\n'
                     '  Handshake: P_CONTROL_HARD_RESET_SERVER_V1\n'
                     '  Transport: tcp\n'
                     '  Version  : not disclosed pre-authentication (requires the TLS control channel)'})
        (nmap_dir / 'nse_results' / 'port1194.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'Internal')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'OpenVPN Service Detected' in content
        assert 'LOW' in content
        assert '10.0.4.2' in content

    def test_openvpn_empty_output_no_finding(self, nmap_dir):
        """openvpn-detect absent/empty -> no finding at all."""
        xml = _nmap_xml('10.0.4.3', 'udp', '1194')
        (nmap_dir / 'nse_results' / 'portU_1194.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        findings_file = nmap_dir / 'findings.txt'
        if findings_file.exists():
            content = findings_file.read_text()
            assert 'OpenVPN' not in content

    def test_openvpn_port_not_flagged_as_service_exposed(self, nmap_dir):
        """1194 must never produce a 'Service Exposed Externally' finding — VPN exposure is expected."""
        xml = _nmap_xml(
            '10.0.4.4', 'udp', '1194',
            scripts={'openvpn-detect':
                     'OpenVPN server confirmed via control-channel handshake\n'
                     '  Handshake: P_CONTROL_HARD_RESET_SERVER_V2\n'
                     '  Transport: udp\n'
                     '  Version  : not disclosed pre-authentication (requires the TLS control channel)'})
        (nmap_dir / 'nse_results' / 'portU_1194.xml').write_text(xml)
        generate_findings(str(nmap_dir), 'External')
        content = (nmap_dir / 'findings.txt').read_text()
        assert 'Service Exposed Externally' not in content
        assert 'OpenVPN Service Detected' in content

    def test_openvpn_1194_not_in_external_sensitive_ports(self):
        """1194/U:1194 must not be registered as an externally-sensitive port."""
        assert '1194' not in spoonmap._EXTERNAL_SENSITIVE_PORT_KEYS
        assert 'U:1194' not in spoonmap._EXTERNAL_SENSITIVE_PORT_KEYS

    def test_openvpn_wired_into_both_port_script_tables(self):
        """1194 (both transports) must be wired into external and internal script tables."""
        for table in (spoonmap.EXTERNAL_PORT_SCRIPTS, spoonmap.INTERNAL_PORT_SCRIPTS):
            assert 'openvpn-detect.nse' in table['1194']
            assert 'openvpn-detect.nse' in table['U:1194']


# ── _parse_masscan_ping_xml ───────────────────────────────────────────────────

def _masscan_ping_xml(*ips):
    """Minimal masscan --ping XML with one <host> per IP."""
    hosts = ''.join(
        f'<host><address addr="{ip}" addrtype="ipv4"/></host>'
        for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'


class TestParseMasscanPingXml:
    def test_returns_ips_from_valid_xml(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text(_masscan_ping_xml('192.168.1.1'))
        assert _parse_masscan_ping_xml(str(f)) == {'192.168.1.1'}

    def test_multiple_hosts(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text(_masscan_ping_xml('10.0.0.1', '10.0.0.2', '10.0.0.3'))
        assert _parse_masscan_ping_xml(str(f)) == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}

    def test_empty_file_returns_empty_set(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text('')
        assert _parse_masscan_ping_xml(str(f)) == set()

    def test_missing_file_returns_empty_set(self, tmp_path):
        assert _parse_masscan_ping_xml(str(tmp_path / 'nonexistent.xml')) == set()

    def test_malformed_xml_returns_empty_set(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text('<nmaprun><host>')  # unclosed tags
        assert _parse_masscan_ping_xml(str(f)) == set()

    def test_ipv6_host_excluded(self, tmp_path):
        """An IPv6 address admitted here reached the address sort keys and the
        masscan -iL target file, neither of which handles IPv6."""
        f = tmp_path / 'ping.xml'
        f.write_text(
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="fe80::1" addrtype="ipv6"/></host>'
            '<host><address addr="10.0.0.1" addrtype="ipv4"/></host>'
            '</nmaprun>'
        )
        assert _parse_masscan_ping_xml(str(f)) == {'10.0.0.1'}

    def test_ipv6_listed_first_does_not_shadow_ipv4(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text(
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="fe80::1" addrtype="ipv6"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            '</host></nmaprun>'
        )
        assert _parse_masscan_ping_xml(str(f)) == {'10.0.0.1'}

    def test_address_without_addr_attribute_skipped(self, tmp_path):
        f = tmp_path / 'ping.xml'
        f.write_text(
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addrtype="ipv4"/></host>'
            '</nmaprun>'
        )
        assert _parse_masscan_ping_xml(str(f)) == set()


# ── _parse_nmap_sn_xml ────────────────────────────────────────────────────────

def _nmap_sn_xml(*entries):
    """Minimal nmap -sn XML.  entries is a list of (ip, state) tuples."""
    hosts = ''.join(
        f'<host><status state="{state}"/><address addr="{ip}" addrtype="ipv4"/></host>'
        for ip, state in entries
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'


class TestParseNmapSnXml:
    def test_returns_only_up_hosts(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text(_nmap_sn_xml(('10.1.1.1', 'up'), ('10.1.1.2', 'down')))
        assert _parse_nmap_sn_xml(str(f)) == {'10.1.1.1'}

    def test_all_up_hosts(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text(_nmap_sn_xml(('10.0.0.1', 'up'), ('10.0.0.2', 'up'), ('10.0.0.3', 'up')))
        assert _parse_nmap_sn_xml(str(f)) == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}

    def test_empty_file_returns_empty_set(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text('')
        assert _parse_nmap_sn_xml(str(f)) == set()

    def test_missing_file_returns_empty_set(self, tmp_path):
        assert _parse_nmap_sn_xml(str(tmp_path / 'nonexistent.xml')) == set()

    def test_malformed_xml_returns_empty_set(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text('<nmaprun><host>')  # unclosed tags
        assert _parse_nmap_sn_xml(str(f)) == set()

    def test_ipv6_up_host_excluded(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text(
            '<?xml version="1.0"?><nmaprun>'
            '<host><status state="up"/><address addr="fe80::1" addrtype="ipv6"/></host>'
            '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>'
            '</nmaprun>'
        )
        assert _parse_nmap_sn_xml(str(f)) == {'10.0.0.1'}

    def test_mac_address_first_does_not_shadow_ipv4(self, tmp_path):
        """An -sn sweep on the local segment emits <address addrtype="mac"> too."""
        f = tmp_path / 'sn.xml'
        f.write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            '</host></nmaprun>'
        )
        assert _parse_nmap_sn_xml(str(f)) == {'10.0.0.1'}

    def test_up_host_with_no_ipv4_address_skipped(self, tmp_path):
        f = tmp_path / 'sn.xml'
        f.write_text(
            '<?xml version="1.0"?><nmaprun>'
            '<host><status state="up"/><address addrtype="ipv4"/></host>'
            '</nmaprun>'
        )
        assert _parse_nmap_sn_xml(str(f)) == set()


# ── TestParseResultXml ────────────────────────────────────────────────────────

def _result_xml(*ips):
    hosts = ''.join(
        f'<host><address addr="{ip}" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="445"><state state="open"/></port></ports>'
        '</host>'
        for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'


class TestParseResultXml:
    """_parse_result_xml() skips files that carry no parseable results."""

    def test_parses_valid_file(self, tmp_path):
        f = tmp_path / 'batch_0.xml'
        f.write_text(_result_xml('10.0.0.1'))
        root = _parse_result_xml(str(f))
        assert [h.find('address').attrib['addr'] for h in root.findall('host')] == ['10.0.0.1']

    def test_empty_file_returns_none(self, tmp_path):
        # A zero-length -oX file means the scan died before writing: masscan
        # writes nothing when it finds nothing, but _run_masscan_batch() stamps
        # _EMPTY_RESULT_XML over that on its success path, so a file still empty
        # here was never completed.
        f = tmp_path / 'batch_0.xml'
        f.write_text('')
        assert _parse_result_xml(str(f)) is None

    def test_empty_result_placeholder_parses_to_zero_hosts(self, tmp_path):
        # The placeholder must be usable output that yields no hosts, so every
        # consumer behaves as it did for the old zero-length file.
        f = tmp_path / 'batch_0.xml'
        f.write_text(spoonmap._EMPTY_RESULT_XML)
        root = _parse_result_xml(str(f))
        assert root is not None
        assert root.findall('host') == []

    def test_truncated_file_returns_none(self, tmp_path):
        # A killed nmap leaves the prologue with no closing </nmaprun>.
        f = tmp_path / 'port443.xml'
        f.write_text('<?xml version="1.0"?>\n<nmaprun><host>')
        assert _parse_result_xml(str(f)) is None

    def test_non_xml_file_returns_none(self, tmp_path):
        f = tmp_path / 'batch_0.txt'
        f.write_text('not xml at all')
        assert _parse_result_xml(str(f)) is None

    def test_directory_returns_none(self, tmp_path):
        d = tmp_path / 'nested.xml'
        d.mkdir()
        assert _parse_result_xml(str(d)) is None

    def test_missing_file_returns_none(self, tmp_path):
        assert _parse_result_xml(str(tmp_path / 'nope.xml')) is None


class TestAggregateResultDir:
    """_aggregate_result_dir() must survive empty result files (regression)."""

    def test_empty_batch_files_are_skipped(self, tmp_path):
        # Mirrors the real failure: masscan_results/ where batch_0.xml sorts
        # first and is empty, which used to abort the whole run with
        # "ParseError: no element found: line 1, column 0".
        for idx in range(3):
            (tmp_path / f'batch_{idx}.xml').write_text('')
        (tmp_path / 'batch_3.xml').write_text(_result_xml('10.0.0.7'))

        hosts_json, xml_hosts = _aggregate_result_dir(str(tmp_path), {})

        assert list(xml_hosts) == ['10.0.0.7']
        assert [h['ip'] for h in hosts_json] == ['10.0.0.7']

    def test_all_files_empty_yields_nothing(self, tmp_path):
        (tmp_path / 'batch_0.xml').write_text('')
        assert _aggregate_result_dir(str(tmp_path), {}) == ([], {})

    def test_merges_same_ip_across_files(self, tmp_path):
        (tmp_path / 'batch_0.xml').write_text('')
        (tmp_path / 'port22.xml').write_text(_result_xml('10.0.0.1'))
        (tmp_path / 'port80.xml').write_text(_result_xml('10.0.0.1', '10.0.0.2'))

        hosts_json, xml_hosts = _aggregate_result_dir(str(tmp_path), {})

        assert sorted(xml_hosts) == ['10.0.0.1', '10.0.0.2']
        merged = next(h for h in hosts_json if h['ip'] == '10.0.0.1')
        assert len(merged['ports']) == 2

    def test_trailing_slash_result_dir(self, tmp_path):
        # main() builds result_dir with a trailing separator.
        (tmp_path / 'batch_0.xml').write_text(_result_xml('10.0.0.5'))
        _, xml_hosts = _aggregate_result_dir(str(tmp_path) + os.sep, {})
        assert list(xml_hosts) == ['10.0.0.5']


# ── _combine_live_hosts ───────────────────────────────────────────────────────

class TestCombineLiveHosts:
    """_combine_live_hosts() unions every per-port live-host file."""

    def _make_live_hosts(self, tmp_path, files):
        disc = tmp_path / 'discovery'
        (disc / 'live_hosts').mkdir(parents=True)
        for name, body in files.items():
            (disc / 'live_hosts' / name).write_text(body)
        return str(disc)

    def test_unions_and_deduplicates_across_files(self, tmp_path):
        disc = self._make_live_hosts(tmp_path, {
            'port80.txt': '10.0.0.1\n10.0.0.2\n',
            'port443.txt': '10.0.0.2\n10.0.0.3\n',
        })
        _combine_live_hosts(disc, str(tmp_path))
        written = (tmp_path / 'all_live_hosts.txt').read_text()
        assert sorted(written.split()) == ['10.0.0.1', '10.0.0.2', '10.0.0.3']

    def test_empty_live_hosts_dir_writes_empty_file(self, tmp_path):
        disc = self._make_live_hosts(tmp_path, {})
        _combine_live_hosts(disc, str(tmp_path))
        assert (tmp_path / 'all_live_hosts.txt').read_text() == ''

    def test_missing_trailing_newline_does_not_duplicate_an_ip(self, tmp_path):
        """Dedup used to run on raw lines, so '10.0.0.2' and '10.0.0.2\\n' were
        different set members and an unterminated last line listed that IP twice
        in a file documented as deduplicated.  Internal writers always terminate
        via _atomic_write(), so it takes an externally authored port file."""
        disc = self._make_live_hosts(tmp_path, {
            'port80.txt': '10.0.0.1\n10.0.0.2',    # no trailing newline
            'port443.txt': '10.0.0.2\n',
        })
        _combine_live_hosts(disc, str(tmp_path))
        written = (tmp_path / 'all_live_hosts.txt').read_text()
        assert written.split() == ['10.0.0.1', '10.0.0.2']
        assert written.count('10.0.0.2') == 1

    def test_blank_lines_are_dropped(self, tmp_path):
        disc = self._make_live_hosts(tmp_path, {'port80.txt': '10.0.0.1\n\n   \n'})
        _combine_live_hosts(disc, str(tmp_path))
        assert (tmp_path / 'all_live_hosts.txt').read_text() == '10.0.0.1\n'

    def test_output_is_newline_terminated_and_ip_sorted(self, tmp_path):
        disc = self._make_live_hosts(tmp_path, {
            'port80.txt': '10.0.0.10\n10.0.0.2\n',
        })
        _combine_live_hosts(disc, str(tmp_path))
        # Numeric IP order, not lexical, and a trailing newline like every other
        # host list this tool writes.
        assert (tmp_path / 'all_live_hosts.txt').read_text() == '10.0.0.2\n10.0.0.10\n'

    def test_hostname_files_are_excluded(self, tmp_path):
        # create_hostname_target_file() writes port{N}_hostnames.txt into the
        # same directory; those hold hostnames, not IPs, so all_live_hosts.txt
        # used to interleave them and list every resolved host twice.
        disc = self._make_live_hosts(tmp_path, {
            'port80.txt': '10.0.0.1\n10.0.0.2\n',
            'port80_hostnames.txt': 'web1.corp.local\nweb2.corp.local\n',
        })
        _combine_live_hosts(disc, str(tmp_path))
        written = (tmp_path / 'all_live_hosts.txt').read_text()
        assert sorted(written.split()) == ['10.0.0.1', '10.0.0.2']
        assert 'web1.corp.local' not in written

    def test_non_port_files_are_ignored(self, tmp_path):
        disc = self._make_live_hosts(tmp_path, {
            'port80.txt': '10.0.0.1\n',
            'notes.md': 'scratch\n',
        })
        _combine_live_hosts(disc, str(tmp_path))
        written = (tmp_path / 'all_live_hosts.txt').read_text()
        assert sorted(written.split()) == ['10.0.0.1']

    def test_unreadable_entry_does_not_lose_other_ports(self, tmp_path, capsys):
        # A directory named portNN.txt raises IsADirectoryError on open().
        disc = self._make_live_hosts(tmp_path, {'port80.txt': '10.0.0.1\n'})
        (tmp_path / 'discovery' / 'live_hosts' / 'port443.txt').mkdir()
        _combine_live_hosts(disc, str(tmp_path))
        written = (tmp_path / 'all_live_hosts.txt').read_text()
        assert sorted(written.split()) == ['10.0.0.1']
        assert 'port443.txt' in capsys.readouterr().out

    def test_unlistable_live_hosts_dir_is_reported(self, tmp_path, capsys):
        disc = self._make_live_hosts(tmp_path, {})
        with patch('spoonmap.os.listdir',
                   side_effect=PermissionError('Permission denied')):
            _combine_live_hosts(disc, str(tmp_path))
        out = capsys.readouterr().out
        assert 'could not list' in out
        assert 'live_hosts' in out
        assert not (tmp_path / 'all_live_hosts.txt').exists()

    def test_write_failure_is_reported_not_raised(self, tmp_path, capsys):
        disc = self._make_live_hosts(tmp_path, {'port80.txt': '10.0.0.1\n'})
        with patch('spoonmap._atomic_write', side_effect=OSError('No space left on device')):
            _combine_live_hosts(disc, str(tmp_path))
        out = capsys.readouterr().out
        assert 'all_live_hosts.txt' in out
        assert 'No space left on device' in out


# ── _write_combined_results ───────────────────────────────────────────────────

class TestWriteCombinedResults:
    """_write_combined_results() writes the merged XML and JSON output."""

    def test_writes_xml_and_json(self, tmp_path, capsys):
        host = etree.fromstring('<host><address addr="10.0.0.1"/></host>')
        hosts_json = [{'ip': '10.0.0.1', 'ports': [], 'hostscripts': {}}]
        _write_combined_results(str(tmp_path), hosts_json, {'10.0.0.1': host})
        xml_text = (tmp_path / 'spoonmap_output.xml').read_text()
        assert xml_text.startswith('<?xml version="1.0"?>\n<!-- SpooNMAP -->\n<nmaprun>\n')
        assert xml_text.endswith('</nmaprun>')
        assert '10.0.0.1' in xml_text
        with open(str(tmp_path / 'spoonmap_output.json')) as fh:
            assert json.load(fh) == hosts_json
        assert 'Results written to' in capsys.readouterr().out

    def test_no_hosts_writes_empty_document(self, tmp_path):
        _write_combined_results(str(tmp_path), [], {})
        assert (tmp_path / 'spoonmap_output.xml').read_text() == (
            '<?xml version="1.0"?>\n<!-- SpooNMAP -->\n<nmaprun>\n</nmaprun>')
        with open(str(tmp_path / 'spoonmap_output.json')) as fh:
            assert json.load(fh) == []

    def test_output_is_reparseable_with_every_host(self, tmp_path):
        hosts = {ip: etree.fromstring(f'<host><address addr="{ip}"/></host>')
                 for ip in ('10.0.0.1', '10.0.0.2')}
        _write_combined_results(str(tmp_path), [], hosts)
        root = etree.parse(str(tmp_path / 'spoonmap_output.xml')).getroot()
        assert {h.find('address').get('addr') for h in root.findall('host')} == set(hosts)

    def _fail_one(self, tmp_path, failing_name):
        """side_effect that fails _atomic_write for one artifact only."""
        failing = f'{tmp_path}/{failing_name}'
        real_atomic_write = spoonmap._atomic_write

        def side_effect(path, content):
            if path == failing:
                raise OSError('No space left on device')
            return real_atomic_write(path, content)
        return side_effect

    def test_xml_failure_still_writes_json(self, tmp_path, capsys):
        # The two expensive artifacts are guarded independently: losing the XML
        # must not also lose the JSON.
        with patch('spoonmap._atomic_write',
                   side_effect=self._fail_one(tmp_path, 'spoonmap_output.xml')):
            _write_combined_results(str(tmp_path), [{'ip': '10.0.0.1'}], {})
        assert not (tmp_path / 'spoonmap_output.xml').exists()
        with open(str(tmp_path / 'spoonmap_output.json')) as fh:
            assert json.load(fh) == [{'ip': '10.0.0.1'}]
        out = capsys.readouterr().out
        assert 'spoonmap_output.xml' in out
        assert 'No space left on device' in out

    def test_json_failure_still_writes_xml(self, tmp_path, capsys):
        with patch('spoonmap._atomic_write',
                   side_effect=self._fail_one(tmp_path, 'spoonmap_output.json')):
            _write_combined_results(str(tmp_path), [], {})
        assert (tmp_path / 'spoonmap_output.xml').exists()
        assert not (tmp_path / 'spoonmap_output.json').exists()
        assert 'could not write' in capsys.readouterr().out

    def test_both_failures_suppress_success_message(self, tmp_path, capsys):
        with patch('spoonmap._atomic_write', side_effect=OSError('Read-only file system')):
            _write_combined_results(str(tmp_path), [], {})
        out = capsys.readouterr().out
        assert 'Results written to' not in out
        assert out.count('could not write') == 2


# ── TestRunMasscanBatchWaitMinimum ─────────────────────────────────────────────

class TestRunMasscanBatchWaitMinimum:
    """_run_masscan_batch must always pass --wait >= 3 to masscan regardless of wait_secs."""

    def _make_mock_proc(self):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.returncode = 0
        mock_proc.pid = 12345
        # Finite stderr so _stream_masscan_progress()'s read(1) loop terminates;
        # a bare MagicMock would return truthy bytes forever and hang the join.
        mock_proc.stderr = io.BytesIO(b'')
        return mock_proc

    def _captured_wait_arg(self, mock_popen):
        """Return the integer value passed as --wait in the masscan command."""
        cmd = mock_popen.call_args[0][0]
        idx = cmd.index('--wait')
        return int(cmd[idx + 1])

    def test_wait_zero_becomes_three(self, tmp_path):
        """When _calc_scan_wait returns 0 (small host set), masscan still gets --wait 3."""
        output_xml = str(tmp_path / 'out.xml')
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['445'], '2000', output_xml,
                               '/fake/targets.txt', '88', None, wait_secs=0)
        assert self._captured_wait_arg(mock_popen) >= 3

    def test_wait_one_becomes_three(self, tmp_path):
        """wait_secs < 3 is raised to 3."""
        output_xml = str(tmp_path / 'out.xml')
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['139'], '1000', output_xml,
                               '/fake/targets.txt', '88', None, wait_secs=1)
        assert self._captured_wait_arg(mock_popen) >= 3

    def test_wait_large_value_preserved(self, tmp_path):
        """wait_secs > 3 is passed through unchanged."""
        output_xml = str(tmp_path / 'out.xml')
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['445'], '1000', output_xml,
                               '/fake/targets.txt', '88', None, wait_secs=29)
        assert self._captured_wait_arg(mock_popen) == 29

    def test_default_wait_secs_passes_minimum(self, tmp_path):
        """Default wait_secs=2 is still raised to 3."""
        output_xml = str(tmp_path / 'out.xml')
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['80'], '10000', output_xml,
                               '/fake/targets.txt', '53', None)
        assert self._captured_wait_arg(mock_popen) >= 3


class TestRunMasscanBatchBehavior:
    """_run_masscan_batch() result parsing and error handling."""

    def _make_mock_proc(self, returncode=0):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.returncode = returncode
        mock_proc.pid = 12345
        # Finite stderr so _stream_masscan_progress()'s read(1) loop terminates;
        # a bare MagicMock would return truthy bytes forever and hang the join.
        mock_proc.stderr = io.BytesIO(b'')
        return mock_proc

    def test_parses_tcp_and_udp_results(self, tmp_path):
        output_xml = tmp_path / 'out.xml'
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="445"/></ports></host>'
            '<host><address addr="10.0.0.2" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="53"/></ports></host>'
            '</nmaprun>'
        )

        def fake_popen(cmd, **kwargs):
            output_xml.write_text(xml)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            results = _run_masscan_batch(['445', 'U:53'], '1000', str(output_xml),
                                         '/fake/targets.txt', None, None)

        assert results == {'445': {'10.0.0.1'}, 'U:53': {'10.0.0.2'}}

    def test_exclusions_file_added_to_command(self, tmp_path):
        output_xml = tmp_path / 'out.xml'
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.9\n')
        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            output_xml.write_text('<nmaprun/>')
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['445'], '1000', str(output_xml),
                               '/fake/targets.txt', None, str(excl))

        assert captured_cmds[0][captured_cmds[0].index('--excludefile') + 1] == str(excl)

    def test_missing_output_file_returns_empty_dict(self, tmp_path):
        output_xml = tmp_path / 'out.xml'  # never written
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            results = _run_masscan_batch(['445'], '1000', str(output_xml),
                                         '/fake/targets.txt', None, None)
        assert results == {}

    def test_malformed_xml_logged_and_empty_dict_returned(self, tmp_path, capsys):
        output_xml = tmp_path / 'out.xml'

        def fake_popen(cmd, **kwargs):
            output_xml.write_text('<nmaprun><host>')  # unclosed tags
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            results = _run_masscan_batch(['445'], '1000', str(output_xml),
                                         '/fake/targets.txt', None, None)

        assert results == {}
        assert 'Error parsing masscan XML' in capsys.readouterr().out

    def test_ipv6_host_excluded_from_results(self, tmp_path):
        """findall('address')[0] took whatever address came first, so an IPv6
        host became a live_hosts entry and then a masscan -iL target."""
        output_xml = tmp_path / 'out.xml'
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="fe80::1" addrtype="ipv6"/>'
            '<ports><port protocol="tcp" portid="445"/></ports></host>'
            '<host><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="445"/></ports></host>'
            '</nmaprun>'
        )

        def fake_popen(cmd, **kwargs):
            output_xml.write_text(xml)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            results = _run_masscan_batch(['445'], '1000', str(output_xml),
                                         '/fake/targets.txt', None, None)

        assert results == {'445': {'10.0.0.1'}}

    def test_host_with_no_address_element_does_not_discard_batch(self, tmp_path):
        """findall('address')[0] raised IndexError outside the parse guard, so a
        single malformed <host> threw away every other host's open ports."""
        output_xml = tmp_path / 'out.xml'
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><ports><port protocol="tcp" portid="445"/></ports></host>'
            '<host><address addr="10.0.0.2" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="445"/></ports></host>'
            '</nmaprun>'
        )

        def fake_popen(cmd, **kwargs):
            output_xml.write_text(xml)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            results = _run_masscan_batch(['445'], '1000', str(output_xml),
                                         '/fake/targets.txt', None, None)

        assert results == {'445': {'10.0.0.2'}}

    def test_returncode_1_exits(self, tmp_path):
        output_xml = tmp_path / 'out.xml'
        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc(returncode=1)), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(SystemExit) as exc:
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   '/fake/targets.txt', None, None)
        assert exc.value.code == 1

    def test_masscan_not_found_exits(self, tmp_path, capsys):
        output_xml = tmp_path / 'out.xml'
        with patch('spoonmap.subprocess.Popen', side_effect=FileNotFoundError), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(SystemExit) as exc:
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   '/fake/targets.txt', None, None)
        assert exc.value.code == 1
        assert 'masscan not found' in capsys.readouterr().out

    def test_generic_exception_logged_and_exits(self, tmp_path, capsys):
        output_xml = tmp_path / 'out.xml'
        with patch('spoonmap.subprocess.Popen', side_effect=RuntimeError('boom')), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(SystemExit) as exc:
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   '/fake/targets.txt', None, None)
        assert exc.value.code == 1
        assert 'Error running masscan' in capsys.readouterr().out

    def test_keyboard_interrupt_kills_proc_and_reraises(self, tmp_path):
        output_xml = tmp_path / 'out.xml'
        mock_proc = self._make_mock_proc()
        mock_proc.wait.side_effect = [KeyboardInterrupt, None]
        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   '/fake/targets.txt', None, None)
        assert mock_proc.kill.called

    def test_interrupt_inside_popen_reraises_and_restores_terminal(self, tmp_path):
        """SIGINT in the fork/exec window left masscan_process unbound, so the
        handler's `Killing PID {masscan_process.pid}` read raised
        UnboundLocalError in place of the KeyboardInterrupt."""
        output_xml = tmp_path / 'out.xml'
        with patch('spoonmap.subprocess.Popen', side_effect=KeyboardInterrupt), \
             patch('spoonmap.save_terminal_state', return_value='TERM'), \
             patch('spoonmap.restore_terminal_state') as mock_restore:
            with pytest.raises(KeyboardInterrupt):
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   '/fake/targets.txt', None, None)
        assert mock_restore.called

    def test_returncode_1_prints_diagnostic_with_stderr(self, tmp_path, capsys):
        output_xml = tmp_path / 'out.xml'
        mock_proc = self._make_mock_proc(returncode=1)
        mock_proc.stderr = io.BytesIO(b'Error: failed to detect IP of interface')

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(SystemExit) as exc:
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   '/fake/targets.txt', None, None)

        assert exc.value.code == 1
        output = capsys.readouterr().out
        assert 'masscan exited with code 1' in output
        assert 'failed to detect IP of interface' in output

    def test_returncode_2_prints_diagnostic_with_stderr(self, tmp_path, capsys):
        output_xml = tmp_path / 'out.xml'
        mock_proc = self._make_mock_proc(returncode=2)
        mock_proc.stderr = io.BytesIO(b'Fatal error: invalid argument')

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(SystemExit) as exc:
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   '/fake/targets.txt', None, None)

        assert exc.value.code == 1
        output = capsys.readouterr().out
        assert 'masscan exited with code 2' in output
        assert 'Fatal error: invalid argument' in output

    def test_returncode_0_parses_normally(self, tmp_path):
        output_xml = tmp_path / 'out.xml'
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="445"/></ports></host>'
            '</nmaprun>'
        )

        def fake_popen(cmd, **kwargs):
            output_xml.write_text(xml)
            return self._make_mock_proc(returncode=0)

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            results = _run_masscan_batch(['445'], '1000', str(output_xml),
                                         '/fake/targets.txt', None, None)

        assert results == {'445': {'10.0.0.1'}}

    def test_empty_output_after_success_gets_placeholder(self, tmp_path):
        """A successful batch that found nothing must leave usable empty XML.

        masscan writes nothing to -oX when no port is open, which is
        indistinguishable on disk from being killed before the first write.
        Stamping a minimal document lets the resume gates skip an
        honestly-empty batch instead of redoing it on every resume.
        """
        output_xml = tmp_path / 'out.xml'
        # A readable target file, so the batch's own coverage record is written
        # and the gate below turns on the placeholder, not a missing record.
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        def fake_popen(cmd, **kwargs):
            output_xml.write_text('')  # masscan found nothing
            return self._make_mock_proc(returncode=0)

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            results = _run_masscan_batch(['445'], '1000', str(output_xml),
                                         str(targets), None, None)

        assert results == {}
        # Still reads as "no results" downstream, but now as usable output.
        assert _parse_result_xml(str(output_xml)).findall('host') == []
        assert _resume_cache_usable(str(output_xml), 0, 'batch 1/1 (445)',
                                    target_file=str(targets),
                                    exclusions_file=None) is True

    def test_placeholder_write_leaves_no_temp_file(self, tmp_path):
        """The placeholder goes through _atomic_write, so no .tmp is left behind."""
        output_xml = tmp_path / 'out.xml'

        def fake_popen(cmd, **kwargs):
            output_xml.write_text('')
            return self._make_mock_proc(returncode=0)

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _run_masscan_batch(['445'], '1000', str(output_xml),
                               '/fake/targets.txt', None, None)

        assert [p.name for p in tmp_path.iterdir()] == ['out.xml']

    def test_nonzero_exit_leaves_empty_output_empty(self, tmp_path):
        """A failed run must NOT be stamped — that would cache the failure."""
        output_xml = tmp_path / 'out.xml'
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        def fake_popen(cmd, **kwargs):
            output_xml.write_text('')
            return self._make_mock_proc(returncode=1)

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(SystemExit):
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   str(targets), None, None)

        assert output_xml.read_text() == ''
        assert not Path(str(output_xml) + '.coverage').exists()
        assert _resume_cache_usable(str(output_xml), 0, 'batch 1/1 (445)',
                                    target_file=str(targets),
                                    exclusions_file=None) is False

    def test_interrupt_leaves_empty_output_empty(self, tmp_path):
        """Same for a Ctrl-C: the batch did not complete, so no placeholder."""
        output_xml = tmp_path / 'out.xml'
        output_xml.write_text('')

        def fake_popen(cmd, **kwargs):
            proc = self._make_mock_proc(returncode=0)
            proc.wait.side_effect = KeyboardInterrupt
            return proc

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                _run_masscan_batch(['445'], '1000', str(output_xml),
                                   '/fake/targets.txt', None, None)

        assert output_xml.read_text() == ''


class TestFlagSuspectedTarpits:
    """Unit tests for _flag_suspected_tarpits()."""

    def test_host_open_on_all_ports_flagged(self):
        tcp_ports = [str(p) for p in range(20)]
        port_ips = {p: {'10.0.0.1'} for p in tcp_ports}
        result = _flag_suspected_tarpits(port_ips, len(tcp_ports))
        assert result == {'10.0.0.1': (20, 20)}

    def test_host_open_on_few_ports_not_flagged(self):
        tcp_ports = [str(p) for p in range(20)]
        port_ips = {p: set() for p in tcp_ports}
        port_ips['0'] = {'10.0.0.1'}
        port_ips['1'] = {'10.0.0.1'}
        result = _flag_suspected_tarpits(port_ips, len(tcp_ports))
        assert result == {}

    def test_below_minimum_ports_scanned_never_flags(self):
        # Even a host open on every scanned port is not flagged when the sample
        # size is too small to trust (HONEYPOT_MIN_PORTS_SCANNED not met).
        tcp_port_count = HONEYPOT_MIN_PORTS_SCANNED - 1
        port_ips = {str(p): {'10.0.0.1'} for p in range(tcp_port_count)}
        result = _flag_suspected_tarpits(port_ips, tcp_port_count)
        assert result == {}

    def test_udp_ports_ignored(self):
        tcp_port_count = HONEYPOT_MIN_PORTS_SCANNED
        port_ips = {str(p): {'10.0.0.1'} for p in range(tcp_port_count)}
        # A pile of UDP entries for the same host must not count toward the ratio.
        port_ips.update({f'U:{p}': {'10.0.0.1'} for p in range(100)})
        result = _flag_suspected_tarpits(port_ips, tcp_port_count)
        assert result == {'10.0.0.1': (tcp_port_count, tcp_port_count)}

    def test_fraction_boundary_just_under_threshold_not_flagged(self):
        tcp_port_count = 100
        open_count = int(tcp_port_count * HONEYPOT_OPEN_PORT_FRACTION) - 1
        port_ips = {str(p): {'10.0.0.1'} for p in range(open_count)}
        for p in range(open_count, tcp_port_count):
            port_ips[str(p)] = set()
        result = _flag_suspected_tarpits(port_ips, tcp_port_count)
        assert result == {}


class TestReportSuspectedTarpits:
    """Unit tests for _report_suspected_tarpits()."""

    def test_writes_file_and_warns(self, tmp_path, capsys):
        suspected = {'10.0.0.1': (19, 20)}
        _report_suspected_tarpits(suspected, str(tmp_path))
        content = (tmp_path / 'suspected_tarpits.txt').read_text()
        assert content.strip() == '10.0.0.1,19,20'
        out = capsys.readouterr().out
        assert '10.0.0.1' in out
        assert '19/20' in out
        assert 'tarpit' in out.lower()

    def test_non_ipv4_host_does_not_crash_the_report(self, tmp_path, capsys):
        """A tarpit report is written mid-scan; a ValueError in the sort key
        aborted the scan instead of just mis-ordering one line."""
        suspected = {'10.0.0.10': (19, 20), '10.0.0.2': (20, 20), 'fe80::1': (18, 20)}
        _report_suspected_tarpits(suspected, str(tmp_path))
        lines = (tmp_path / 'suspected_tarpits.txt').read_text().split()
        assert lines == ['10.0.0.2,20,20', '10.0.0.10,19,20', 'fe80::1,18,20']
        assert 'fe80::1' in capsys.readouterr().out

    def test_empty_suspected_writes_nothing(self, tmp_path, capsys):
        _report_suspected_tarpits({}, str(tmp_path))
        assert not (tmp_path / 'suspected_tarpits.txt').exists()
        assert capsys.readouterr().out == ''

    def test_write_leaves_no_temp_file_behind(self, tmp_path):
        """The atomic write must not leave its temp file in the discovery dir."""
        _report_suspected_tarpits({'10.0.0.1': (19, 20)}, str(tmp_path))
        assert [p.name for p in tmp_path.iterdir()] == ['suspected_tarpits.txt']

    def test_failed_write_keeps_previous_file_intact(self, tmp_path):
        """A mid-write failure must leave the prior report readable, not truncated.

        generate_findings() reads this file back; a truncated last line used to
        crash it, so the write has to be all-or-nothing.
        """
        tarpit_file = tmp_path / 'suspected_tarpits.txt'
        tarpit_file.write_text('10.0.0.1,19,20\n')
        with patch('spoonmap.os.replace', side_effect=OSError('ENOSPC')):
            with pytest.raises(OSError):
                _report_suspected_tarpits({'10.0.0.2': (18, 20)}, str(tmp_path))
        assert tarpit_file.read_text() == '10.0.0.1,19,20\n'
        assert [p.name for p in tmp_path.iterdir()] == ['suspected_tarpits.txt']


# ── TestSMBCoupling ────────────────────────────────────────────────────────────

class TestSMBCoupling:
    """mass_scan() SMB port coupling: hosts found on 139 propagate to 445 and vice versa."""

    @staticmethod
    def _make_batch_side_effect(port_map):
        """Return a side_effect function that yields port_map results keyed by call index."""
        calls = []

        def side_effect(batch, rate, output_file, target_file, source_port,
                        exclusions_file, wait_secs=2):
            idx = len(calls)
            calls.append(batch)
            return port_map.get(idx, {})

        return side_effect

    def test_hosts_on_139_propagate_to_445(self, tmp_path):
        """If masscan only finds hosts on 139, coupling writes them to port445.txt too."""
        spoonmap.output_path = str(tmp_path)
        # dest_ports=['139','445']; masscan finds 3 hosts on 139, 0 on 445
        responses = {
            0: {'139': {'10.0.0.1', '10.0.0.2', '10.0.0.3'}},  # probe batch (139)
            1: {'445': set()},                                    # probe batch (445)
        }
        with patch('spoonmap._run_masscan_batch',
                   side_effect=self._make_batch_side_effect(responses)):
            mass_scan('All', ['139', '445'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)

        port445_file = tmp_path / 'discovery' / 'live_hosts' / 'port445.txt'
        if port445_file.exists():
            written = {line.strip() for line in port445_file.read_text().splitlines()
                       if line.strip()}
            assert written == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}

    def test_smb_coupled_ports_constant(self):
        """_SMB_COUPLED_PORTS must contain exactly 139 and 445."""
        assert set(_SMB_COUPLED_PORTS) == {'139', '445'}

    def test_port139_internal_scripts_include_smb2(self):
        """INTERNAL_PORT_SCRIPTS['139'] must include smb2-security-mode for full SMB checks."""
        scripts = INTERNAL_PORT_SCRIPTS.get('139', '')
        assert 'smb2-security-mode' in scripts

    def test_port139_internal_scripts_include_ms17010(self):
        """INTERNAL_PORT_SCRIPTS['139'] must include smb-vuln-ms17-010."""
        scripts = INTERNAL_PORT_SCRIPTS.get('139', '')
        assert 'smb-vuln-ms17-010' in scripts


# ── TestSlowPortsSMB ──────────────────────────────────────────────────────────

class TestSlowPortsSMB:
    """SMB ports 139/445 always scan solo; probe misses trigger a solo retry."""

    def test_smb_ports_in_slow_ports(self):
        """139 and 445 must be in SLOW_PORTS so they always get solo scans."""
        assert '139' in SLOW_PORTS
        assert '445' in SLOW_PORTS

    def test_probe_missed_445_gets_solo_retry(self, tmp_path):
        """batch_size > 1: zero-result probe for 445 must produce a solo batch later.

        Uses dest_ports=['445','80','8888'] so that probe_ports=['445','80'] and
        remaining_ports=['8888'] → probe guard fires.  Both probe calls (fast/slow)
        return empty.  445 is probe-missed → _probe_missed=['445'] → re-queued →
        batches include a solo ['445'] invocation (445 ∈ SLOW_PORTS → solo via batch builder).
        """
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_batch:
            mass_scan('All', ['445', '80', '8888'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)
        solo = [c for c in mock_batch.call_args_list if c.args[0] == ['445']]
        assert len(solo) >= 1, "Expected solo masscan call for 445 after probe miss"

    def test_probe_found_445_always_gets_solo_scan(self, tmp_path):
        """batch_size=2: even when probe finds 445, it must still get a solo main-batch scan.

        The probe runs against probe_target (discovery narrowed); main batches use the
        combined target which may include additional hosts not in probe_target.
        batch_size=2 → probe_ports=['445','80'], remaining_ports=['8888'].
        """
        spoonmap.output_path = str(tmp_path)
        call_log = []

        def side_effect(batch, rate, output_file, target_file, source_port,
                        exclusions_file, wait_secs=2):
            call_log.append(list(batch))
            # First call is the fast probe — simulate finding 445
            return {'445': {'10.0.0.1'}} if len(call_log) == 1 else {}

        with patch('spoonmap._run_masscan_batch', side_effect=side_effect):
            mass_scan('All', ['445', '80', '8888'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=2)
        solo = [b for b in call_log if b == ['445']]
        assert len(solo) >= 1, "445 must always get a solo main-batch scan regardless of probe result"

    def test_probe_missed_3389_gets_rebatched(self, tmp_path):
        """batch_size > 1: zero-result probe for 3389 must re-queue it into a batch.

        3389 is in PROBE_PORT_PRIORITY (position 3) but NOT in SLOW_PORTS.
        When the combined probe returns 0 for 3389, it must appear in a subsequent
        masscan call so it isn't silently dropped.
        """
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_batch:
            mass_scan('All', ['3389', '80', '8888'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=5)
        # Any call whose batch contains '3389' (solo or grouped)
        calls_with_3389 = [c for c in mock_batch.call_args_list
                           if '3389' in c.args[0]]
        # Exclude the two probe calls (fast probe and slow probe)
        probe_batches = [c for c in calls_with_3389
                         if set(c.args[0]) <= {'3389', '80'}]
        main_3389_calls = [c for c in calls_with_3389
                           if c not in probe_batches]
        assert len(main_3389_calls) >= 1, \
            "Expected a main-batch masscan call for 3389 after probe miss"


class TestNmapUdpDiscovery:
    """Unit tests for _nmap_udp_discovery()."""

    def test_open_host_is_returned(self, tmp_path):
        """Host with UDP port 'open' → included in result."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports>'
            '</host></nmaprun>'
        )
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text(xml)
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path),
                                         '53', '')
        assert '10.0.0.1' in result

    def test_open_filtered_host_is_returned(self, tmp_path):
        """Host with UDP port 'open|filtered' → included in result for NSE confirmation."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="10.0.0.2" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open|filtered"/></port></ports>'
            '</host></nmaprun>'
        )
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text(xml)
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path),
                                         '53', '')
        assert '10.0.0.2' in result

    def test_closed_host_is_excluded(self, tmp_path):
        """Host with UDP port 'closed' → not included."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun><host>'
            '<address addr="10.0.0.3" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="closed"/></port></ports>'
            '</host></nmaprun>'
        )
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text(xml)
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path),
                                         '53', '')
        assert '10.0.0.3' not in result

    def test_resume_skips_scan_when_live_file_exists(self, tmp_path):
        """resume=True + existing live_hosts file → no subprocess call."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        (tmp_path / 'discovery' / 'live_hosts').mkdir(parents=True)
        targets = tmp_path / 'targets.txt'
        targets.write_text('192.168.1.0/24\n')
        xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
        xml_path.write_text('<nmaprun/>')
        _write_target_stamp(xml_path, targets)
        live_path = tmp_path / 'discovery' / 'live_hosts' / 'portU_500.txt'
        live_path.write_text('192.168.1.1\n')
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen:
            result = _nmap_udp_discovery('U:500', str(targets), str(tmp_path),
                                         '53', '', resume=True)
        mock_popen.assert_not_called()
        assert '192.168.1.1' in result

    def test_nmap_cmd_uses_sU_and_source_port(self, tmp_path):
        """nmap command uses -sU, -Pn, --open, and --source-port."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '')
        cmd = mock_popen.call_args[0][0]
        assert '-sU' in cmd
        assert '-Pn' in cmd
        assert '--open' in cmd
        assert '--source-port' in cmd
        assert '53' in cmd
        assert '500' in cmd
        assert 'masscan' not in cmd[0]   # must be nmap, not masscan

    def test_resume_with_missing_live_file_returns_empty_set(self, tmp_path):
        """Fresh cached masscan_results XML but no live_hosts file → empty set, no rescan."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        targets = tmp_path / 'targets.txt'
        targets.write_text('192.168.1.0/24\n')
        xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
        xml_path.write_text('<nmaprun/>')
        _write_target_stamp(xml_path, targets)
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen:
            result = _nmap_udp_discovery('U:500', str(targets), str(tmp_path),
                                         '53', '', resume=True)
        mock_popen.assert_not_called()
        assert result == set()

    def test_exclusions_file_added_to_command(self, tmp_path):
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '/excl.txt')
        cmd = mock_popen.call_args[0][0]
        assert cmd[cmd.index('--excludefile') + 1] == '/excl.txt'

    def test_host_without_ipv4_address_skipped(self, tmp_path):
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text(xml)
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '')
        assert result == set()

    def test_address_without_addr_attribute_skipped_others_kept(self, tmp_path):
        """attrib['addr'] raised KeyError past the ParseError guard, losing the
        whole UDP discovery pass over one unusable <address>."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.4" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '</nmaprun>'
        )
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text(xml)
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '')
        assert result == {'10.0.0.4'}

    def test_malformed_xml_logged_and_empty_set_returned(self, tmp_path, capsys):
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            xml_path = tmp_path / 'discovery' / 'masscan_results' / 'portU_500.xml'
            xml_path.write_text('<nmaprun><host>')  # unclosed tags
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '')
        assert result == set()
        assert 'Error parsing nmap UDP XML' in capsys.readouterr().out

    def test_nmap_not_found_returns_empty_set(self, tmp_path, capsys):
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen', side_effect=FileNotFoundError), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            result = _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '')
        assert result == set()
        assert 'nmap not found' in capsys.readouterr().out

    def test_keyboard_interrupt_kills_proc_and_reraises(self, tmp_path):
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        mock_proc = MagicMock()
        mock_proc.wait.side_effect = [KeyboardInterrupt, None]
        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '')
        assert mock_proc.kill.called

    def test_interrupt_inside_popen_reraises_and_restores_terminal(self, tmp_path):
        """SIGINT in the fork/exec window left proc unbound, so proc.kill() in the
        handler raised UnboundLocalError instead of letting the interrupt out."""
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap.subprocess.Popen', side_effect=KeyboardInterrupt), \
             patch('spoonmap.save_terminal_state', return_value='TERM'), \
             patch('spoonmap.restore_terminal_state') as mock_restore:
            with pytest.raises(KeyboardInterrupt):
                _nmap_udp_discovery('U:500', '/targets.txt', str(tmp_path), '53', '')
        assert mock_restore.called


class TestNmapPortDiscovery:
    """Unit tests for _nmap_port_discovery() — nmap-based port discovery
    used in place of masscan for small target sets."""

    def _make_mock_proc(self, returncode=0, stdout_lines=None, stderr=''):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.returncode = returncode
        mock_proc.stdout = stdout_lines or []
        # Iterable (not a bare MagicMock) because _nmap_port_discovery() drains
        # stderr line by line in a concurrent reader thread.
        mock_proc.stderr = io.StringIO(stderr)
        return mock_proc

    def _xml_with_open_ports(self, *entries):
        """entries: list of (ip, protocol, portid, state) tuples."""
        hosts = ''.join(
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="{proto}" portid="{portid}">'
            f'<state state="{state}"/></port></ports></host>'
            for ip, proto, portid, state in entries
        )
        return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'

    def test_resume_reloads_from_live_hosts_dir(self, tmp_path):
        # targets.txt must be created before portDirect.xml so that
        # os.path.getmtime(output_file) >= targets_mtime holds and the resume
        # branch in _nmap_port_discovery() is actually taken.
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        (disc / 'live_hosts').mkdir(parents=True)
        cached = disc / 'masscan_results' / 'portDirect.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, target)
        (disc / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n10.0.0.2\n')
        spoonmap.output_path = str(tmp_path)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, resume=True)

        assert not mock_popen.called
        assert 'Hosts Found on Port 80: 2' in summary

    def test_resume_skips_hostnames_file(self, tmp_path):
        # targets.txt must be created before portDirect.xml so that
        # os.path.getmtime(output_file) >= targets_mtime holds and the resume
        # branch in _nmap_port_discovery() is actually taken.
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        (disc / 'live_hosts').mkdir(parents=True)
        cached = disc / 'masscan_results' / 'portDirect.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, target)
        (disc / 'live_hosts' / 'port80_hostnames.txt').write_text('example.com\n')
        spoonmap.output_path = str(tmp_path)

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, resume=True)

        assert not mock_popen.called
        assert 'hostnames' not in summary

    def _setup_resume_cache(self, tmp_path, xml_text):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        (disc / 'live_hosts').mkdir(parents=True)
        cached = disc / 'masscan_results' / 'portDirect.xml'
        cached.write_text(xml_text)
        (disc / 'live_hosts' / 'port80.txt').write_text('10.0.0.1\n10.0.0.2\n')
        _write_target_stamp(cached, target)
        os.utime(str(target), (1000, 1000))
        os.utime(str(cached), (2000, 2000))  # fresh mtime
        spoonmap.output_path = str(tmp_path)
        return target

    def _fake_popen_writing_results(self):
        def fake_popen(cmd, **kwargs):
            Path(cmd[cmd.index('-oX') + 1]).write_text(self._xml_with_open_ports(
                ('10.0.0.7', 'tcp', '80', 'open'),
            ))
            return self._make_mock_proc()
        return fake_popen

    def test_zero_length_cached_xml_reruns_discovery(self, tmp_path, capsys):
        # A killed nmap leaves an empty portDirect.xml; a fresh mtime must not
        # make that count as completed discovery.
        target = self._setup_resume_cache(tmp_path, '')
        with patch('spoonmap.subprocess.Popen',
                   side_effect=self._fake_popen_writing_results()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, resume=True)

        assert mock_popen.called
        out = capsys.readouterr().out
        assert 're-running nmap port discovery' in out
        assert 'skipping completed nmap port discovery' not in out
        assert 'Hosts Found on Port 80: 1' in summary

    def test_unparseable_cached_xml_reruns_discovery(self, tmp_path, capsys):
        target = self._setup_resume_cache(tmp_path, '<nmaprun><host>')  # unclosed tags
        with patch('spoonmap.subprocess.Popen',
                   side_effect=self._fake_popen_writing_results()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, resume=True)

        assert mock_popen.called
        assert 're-running nmap port discovery' in capsys.readouterr().out
        assert 'Hosts Found on Port 80: 1' in summary

    def test_stale_cached_xml_reruns_discovery(self, tmp_path):
        target = self._setup_resume_cache(tmp_path, '<nmaprun/>')
        os.utime(str(target), (3000, 3000))  # targets newer than cache → stale
        with patch('spoonmap.subprocess.Popen',
                   side_effect=self._fake_popen_writing_results()) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, resume=True)

        assert mock_popen.called
        assert 'Hosts Found on Port 80: 1' in summary

    def test_valid_fresh_cached_xml_still_skips_discovery(self, tmp_path, capsys):
        # The load-bearing direction: resume must keep working, or an operator
        # re-scans everything on a resumed engagement.
        target = self._setup_resume_cache(tmp_path, '<nmaprun/>')
        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, resume=True)

        assert not mock_popen.called
        assert 'skipping completed nmap port discovery' in capsys.readouterr().out
        assert 'Hosts Found on Port 80: 2' in summary

    def test_full_scan_uses_full_port_range(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)
        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _nmap_port_discovery(['80'], str(target), '', None, scan_type='Full')

        cmd = captured_cmds[0]
        assert cmd[cmd.index('-p') + 1] == '1-65535'

    def test_custom_ports_joined(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)
        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _nmap_port_discovery(['80', '443'], str(target), '', None, scan_type='Custom')

        cmd = captured_cmds[0]
        assert cmd[cmd.index('-p') + 1] == '80,443'

    def test_max_rate_and_exclusions_flags_added(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.9\n')
        spoonmap.output_path = str(tmp_path)
        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _nmap_port_discovery(['80'], str(target), '', str(excl),
                                 scan_type='Custom', max_rate=5000)

        cmd = captured_cmds[0]
        assert cmd[cmd.index('--max-rate') + 1] == '5000'
        assert cmd[cmd.index('--excludefile') + 1] == str(excl)

    def test_successful_run_writes_live_hosts_and_summary(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text(self._xml_with_open_ports(
                ('10.0.0.1', 'tcp', '80', 'open'),
                ('10.0.0.2', 'tcp', '80', 'open|filtered'),
            ))
            return self._make_mock_proc(
                stdout_lines=['Scanning 10 hosts [1000 ports/host]\n', 'About 50.00% done\n'])

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None,
                                           scan_type='Custom', total_hosts=10)

        assert 'Hosts Found on Port 80: 2' in summary
        live_file = disc / 'live_hosts' / 'port80.txt'
        content = live_file.read_text()
        assert '10.0.0.1' in content and '10.0.0.2' in content

    def test_host_without_ipv4_address_skipped(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)

        xml = (
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            '<ports><port protocol="tcp" portid="80">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text(xml)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert 'Hosts Found' not in summary

    def test_address_without_addr_attribute_skipped_others_kept(self, tmp_path):
        """attrib['addr'] raised KeyError past the ParseError guard, discarding
        the results for every other host in the sweep."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)

        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80">'
            '<state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.3" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80">'
            '<state state="open"/></port></ports></host>'
            '</nmaprun>'
        )

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text(xml)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert 'Hosts Found on Port 80: 1' in summary
        live_file = tmp_path / 'discovery' / 'live_hosts' / 'port80.txt'
        assert live_file.read_text() == '10.0.0.3\n'

    def test_keyboard_interrupt_kills_proc_and_reraises(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)

        mock_proc = self._make_mock_proc()
        mock_proc.wait.side_effect = [KeyboardInterrupt, None]

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert mock_proc.kill.called

    def test_interrupt_inside_popen_reraises_and_restores_terminal(self, tmp_path):
        """SIGINT in the fork/exec window left proc unbound, so the handler's
        proc.kill() raised UnboundLocalError in place of the interrupt."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)

        with patch('spoonmap.subprocess.Popen', side_effect=KeyboardInterrupt), \
             patch('spoonmap.save_terminal_state', return_value='TERM'), \
             patch('spoonmap.restore_terminal_state') as mock_restore:
            with pytest.raises(KeyboardInterrupt):
                _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert mock_restore.called

    def test_nmap_not_found_returns_summary(self, tmp_path, capsys):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)

        with patch('spoonmap.subprocess.Popen', side_effect=FileNotFoundError), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert summary == '\nSummary'
        assert 'nmap not found' in capsys.readouterr().out

    def test_nonzero_returncode_with_privilege_hint(self, tmp_path, capsys):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)
        mock_proc = self._make_mock_proc(returncode=1, stderr='requires root privileges')

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert summary == '\nSummary'
        out = capsys.readouterr().out
        assert 'Run as root/sudo' in out

    def test_missing_output_file_returns_summary(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)
        mock_proc = self._make_mock_proc()  # never writes output XML

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert summary == '\nSummary'

    def test_malformed_xml_returns_summary(self, tmp_path, capsys):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text('<nmaprun><host>')  # unclosed tags
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert summary == '\nSummary'
        assert 'Error parsing nmap port discovery XML' in capsys.readouterr().out

    def test_missing_target_file_target_count_zero(self, tmp_path):
        """target_file that can't be opened for counting still proceeds (count=0)."""
        target = tmp_path / 'nonexistent.txt'  # never created
        spoonmap.output_path = str(tmp_path)

        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert summary == '\nSummary'

    def test_progress_reader_without_total_hosts_uses_plain_segment_label(self, tmp_path, capsys):
        """Without total_hosts, the scan-group label is just the segment number."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text(self._xml_with_open_ports(
                ('10.0.0.1', 'tcp', '80', 'open')))
            return self._make_mock_proc(
                stdout_lines=['Scanning 5 hosts [1000 ports/host]\n'])

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert 'Scan group 1:' in capsys.readouterr().out

    def test_stderr_is_drained_before_wait_returns(self, tmp_path):
        """Regression (#25): stderr must be drained concurrently with proc.wait().

        Real nmap writes per-packet errors to stderr; once it fills the ~64 KB
        pipe buffer it blocks in write() and never exits, so a wait() that runs
        before anything reads stderr never returns. A MagicMock is not a real
        pipe, so this asserts the structural property instead: wait() does not
        return until stderr has been touched. With the pre-fix code (read after
        wait) the call deadlocks and the worker thread is still alive after the
        bounded join.
        """
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)

        stderr_touched = threading.Event()

        class _WatchedStderr(io.StringIO):
            """Signals as soon as anything starts consuming the stream."""

            def __iter__(self):
                stderr_touched.set()
                return io.StringIO.__iter__(self)

            def read(self, *args, **kwargs):
                stderr_touched.set()
                return io.StringIO.read(self, *args, **kwargs)

        mock_proc = self._make_mock_proc()
        # ~64 KB+ of the errors a restrictive local firewall produces.
        mock_proc.stderr = _WatchedStderr(
            'sendto in send_ip_packet_sd: sendto(4, packet, 44, 0, 10.0.0.1, 16)'
            ' => Operation not permitted\n' * 1000)
        # Stand-in for the kernel blocking nmap's stderr write(): wait() cannot
        # complete until a reader has arrived. The 10 s cap is only so a
        # regression fails the assert below instead of wedging the suite.
        mock_proc.wait.side_effect = lambda *a, **kw: stderr_touched.wait(timeout=10)

        def _run():
            with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
                 patch('spoonmap.save_terminal_state', return_value=None), \
                 patch('spoonmap.restore_terminal_state'):
                _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=5)

        assert not thread.is_alive()
        assert stderr_touched.is_set()

    def test_multiline_stderr_preserved_for_privilege_hint(self, tmp_path, capsys):
        """The concurrent drain still yields stderr as one full string."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        spoonmap.output_path = str(tmp_path)
        mock_proc = self._make_mock_proc(
            returncode=1,
            stderr='sendto failed\nYou requested a scan type which requires'
                   ' root privileges.\nQUITTING!\n')

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            summary = _nmap_port_discovery(['80'], str(target), '', None, scan_type='Custom')

        assert summary == '\nSummary'
        out = capsys.readouterr().out
        assert 'Run as root/sudo' in out
        assert 'sendto failed' in out
        assert 'QUITTING!' in out


class TestMassScanUdp:
    """mass_scan() routes UDP ports to nmap, not masscan."""

    def test_udp_ports_not_passed_to_masscan(self, tmp_path):
        """dest_ports with U:500 → masscan never called with U:500."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}) as mock_m, \
             patch('spoonmap._nmap_udp_discovery', return_value=set()):
            mass_scan('All', ['443', 'U:500'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)
        for call in mock_m.call_args_list:
            batch = call[0][0]
            assert 'U:500' not in batch

    def test_udp_ports_trigger_nmap_udp_discovery(self, tmp_path):
        """dest_ports with U:500 → _nmap_udp_discovery called with 'U:500'."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}), \
             patch('spoonmap._nmap_udp_discovery', return_value=set()) as mock_u:
            mass_scan('All', ['443', 'U:500'], '53', '10000',
                      '/fake/targets.txt', '', batch_size=1)
        udp_calls = [c for c in mock_u.call_args_list if c[0][0] == 'U:500']
        assert len(udp_calls) == 1

    def test_udp_port_with_hosts_found_writes_live_file_and_summary(self, tmp_path):
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}), \
             patch('spoonmap._nmap_udp_discovery', return_value={'10.0.0.5', '10.0.0.6'}):
            result = mass_scan('All', ['U:500'], '53', '10000',
                               '/fake/targets.txt', '', batch_size=1)

        assert 'Hosts Found on Port U:500: 2' in result
        live_file = tmp_path / 'discovery' / 'live_hosts' / 'portU_500.txt'
        assert live_file.exists()
        assert '10.0.0.5' in live_file.read_text()
        assert '10.0.0.6' in live_file.read_text()
        assert [p.name for p in live_file.parent.iterdir()] == ['portU_500.txt']

    def test_udp_uses_discovery_file_when_available(self, tmp_path):
        """UDP discovery uses discovery_file (live hosts) when it exists, not full target list."""
        spoonmap.output_path = str(tmp_path)
        disc_file = tmp_path / 'live_hosts_discovery.txt'
        disc_file.write_text('10.0.0.1\n')
        with patch('spoonmap._run_masscan_batch', return_value={}), \
             patch('spoonmap._nmap_udp_discovery', return_value=set()) as mock_u:
            mass_scan('All', ['U:161'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=1,
                      discovery_file=str(disc_file))
        udp_call = mock_u.call_args_list[0]
        assert udp_call[0][1] == str(disc_file)

    def test_udp_falls_back_to_target_file_without_discovery(self, tmp_path):
        """UDP discovery falls back to full target file when no discovery file exists."""
        spoonmap.output_path = str(tmp_path)
        with patch('spoonmap._run_masscan_batch', return_value={}), \
             patch('spoonmap._nmap_udp_discovery', return_value=set()) as mock_u:
            mass_scan('All', ['U:161'], '88', '1000',
                      '/fake/targets.txt', '', batch_size=1)
        udp_call = mock_u.call_args_list[0]
        assert udp_call[0][1] == '/fake/targets.txt'


class TestFilterUdpLiveHosts:
    """Unit tests for _filter_udp_live_hosts()."""

    def _make_nmap_xml(self, ip, port, state):
        """Return minimal nmap XML with a single host/port entry."""
        return (
            '<?xml version="1.0"?>'
            '<nmaprun>'
            f'<host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="udp" portid="{port}">'
            f'<state state="{state}"/></port></ports>'
            '</host>'
            '</nmaprun>'
        )

    def test_confirmed_open_ip_kept(self, tmp_path):
        """IP with port state 'open' stays in live_hosts and nmap XML after filter."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(self._make_nmap_xml('10.0.0.1', '500', 'open'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')

        result = _filter_udp_live_hosts(str(tmp_path))

        assert (live_dir / 'portU_500.txt').read_text().strip() == '10.0.0.1'
        tree = etree.parse(str(nmap_dir / 'portU_500.xml'))
        hosts = tree.findall('host')
        assert len(hosts) == 1
        assert hosts[0].find('address').attrib['addr'] == '10.0.0.1'
        assert result == {'U:500': 1}

    def test_open_filtered_ip_removed(self, tmp_path):
        """IP with port state 'open|filtered' is removed from live_hosts and nmap XML."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(
            self._make_nmap_xml('10.0.0.2', '500', 'open|filtered'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.2\n')

        result = _filter_udp_live_hosts(str(tmp_path))

        assert (live_dir / 'portU_500.txt').read_text().strip() == ''
        tree = etree.parse(str(nmap_dir / 'portU_500.xml'))
        assert tree.findall('host') == []
        assert result == {'U:500': 0}

    def test_no_nmap_results_dir_is_noop(self, tmp_path):
        """Missing nmap_results/ directory → function returns empty dict without error."""
        result = _filter_udp_live_hosts(str(tmp_path))
        assert result == {}

    def test_removal_count_printed(self, tmp_path, capsys):
        """Removed IPs produce an info message with count."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(
            self._make_nmap_xml('10.0.0.3', '500', 'open|filtered'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.3\n')

        _filter_udp_live_hosts(str(tmp_path))

        captured = capsys.readouterr()
        assert 'UDP filter (U:500)' in captured.out
        assert '1' in captured.out

    def test_nmap_xml_rewritten_without_unconfirmed_hosts(self, tmp_path):
        """After filter, XML on disk has no host elements for unconfirmed IPs."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        # Two hosts: one open, one open|filtered
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun>'
            '<host><address addr="10.0.0.10" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.20" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open|filtered"/></port></ports></host>'
            '</nmaprun>'
        )
        (nmap_dir / 'portU_500.xml').write_text(xml)
        (live_dir / 'portU_500.txt').write_text('10.0.0.10\n10.0.0.20\n')

        result = _filter_udp_live_hosts(str(tmp_path))

        tree = etree.parse(str(nmap_dir / 'portU_500.xml'))
        remaining_ips = {
            h.find('address').attrib['addr'] for h in tree.findall('host')
        }
        assert '10.0.0.10' in remaining_ips
        assert '10.0.0.20' not in remaining_ips
        assert result == {'U:500': 1}

    def test_rewrites_leave_no_temp_files_behind(self, tmp_path):
        """Both atomic rewrites must clean up their temp files."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(self._make_nmap_xml('10.0.0.1', '500', 'open'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')

        _filter_udp_live_hosts(str(tmp_path))

        assert [p.name for p in nmap_dir.iterdir()] == ['portU_500.xml']
        assert [p.name for p in live_dir.iterdir()] == ['portU_500.txt']

    def test_failed_xml_rewrite_keeps_original_xml_intact(self, tmp_path):
        """A failure rewriting the nmap XML must leave the completed scan's XML parseable.

        This file is nmap's own output; truncating it loses the port/script data
        permanently and breaks every later aggregation.
        """
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        original = self._make_nmap_xml('10.0.0.1', '500', 'open')
        nmap_xml = nmap_dir / 'portU_500.xml'
        nmap_xml.write_text(original)
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')

        real_replace = spoonmap.os.replace

        def _replace(src, dst):
            if str(dst).endswith('.xml'):
                raise OSError('ENOSPC')
            return real_replace(src, dst)

        with patch('spoonmap.os.replace', side_effect=_replace):
            with pytest.raises(OSError):
                _filter_udp_live_hosts(str(tmp_path))

        assert nmap_xml.read_text() == original
        assert [p.name for p in nmap_dir.iterdir()] == ['portU_500.xml']

    def test_failed_live_hosts_rewrite_keeps_original_list_intact(self, tmp_path):
        """A failure rewriting live_hosts must not truncate the host list."""
        nmap_dir  = tmp_path / 'nmap_results'
        live_dir  = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(self._make_nmap_xml('10.0.0.1', '500', 'open'))
        live_file = live_dir / 'portU_500.txt'
        live_file.write_text('10.0.0.1\n10.0.0.2\n')

        with patch('spoonmap.os.replace', side_effect=OSError('ENOSPC')):
            with pytest.raises(OSError):
                _filter_udp_live_hosts(str(tmp_path))

        assert live_file.read_text() == '10.0.0.1\n10.0.0.2\n'
        assert [p.name for p in live_dir.iterdir()] == ['portU_500.txt']

    def test_summary_updated_after_filter(self, tmp_path):
        """status_summary lines for UDP ports reflect post-filter confirmed count."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        # One open, one open|filtered — only one confirmed
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.2" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open|filtered"/></port></ports></host>'
            '</nmaprun>'
        )
        (nmap_dir / 'portU_500.xml').write_text(xml)
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n10.0.0.2\n')

        udp_confirmed = _filter_udp_live_hosts(str(tmp_path))

        # Simulate the summary-patching logic from main()
        status_summary = '\nSummary\nHosts Found on Port 80: 3\nHosts Found on Port U:500: 2'
        for port_key, count in udp_confirmed.items():
            lines = status_summary.split('\n')
            updated = []
            for line in lines:
                if line.startswith(f'Hosts Found on Port {port_key}:'):
                    if count > 0:
                        updated.append(f'Hosts Found on Port {port_key}: {count}')
                else:
                    updated.append(line)
            status_summary = '\n'.join(updated)

        assert 'Hosts Found on Port U:500: 1' in status_summary
        assert 'Hosts Found on Port U:500: 2' not in status_summary
        assert 'Hosts Found on Port 80: 3' in status_summary

    def test_summary_drops_zero_count_udp_port(self, tmp_path):
        """A UDP port with 0 confirmed hosts is removed from status_summary."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(
            self._make_nmap_xml('10.0.0.1', '500', 'open|filtered'))
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')

        udp_confirmed = _filter_udp_live_hosts(str(tmp_path))

        status_summary = '\nSummary\nHosts Found on Port U:500: 1'
        for port_key, count in udp_confirmed.items():
            lines = status_summary.split('\n')
            updated = []
            for line in lines:
                if line.startswith(f'Hosts Found on Port {port_key}:'):
                    if count > 0:
                        updated.append(f'Hosts Found on Port {port_key}: {count}')
                else:
                    updated.append(line)
            status_summary = '\n'.join(updated)

        assert 'U:500' not in status_summary

    def test_rewrite_preserves_xml_declaration_and_doctype(self, tmp_path):
        """Rewritten UDP XML retains <?xml?> + <!DOCTYPE nmaprun> so Metasploit can import it."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        prologue = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE nmaprun PUBLIC "-//IDN nmap.org//DTD Nmap XML 1.04//EN"'
            ' "https://svn.nmap.org/nmap/docs/nmap.dtd">\n'
        )
        xml = (
            prologue
            + '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        # Use correct underscore-form filename so _filter_udp_live_hosts picks it up
        (nmap_dir / 'portU_500.xml').write_text(xml)
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')

        _filter_udp_live_hosts(str(tmp_path))

        rewritten = (nmap_dir / 'portU_500.xml').read_text()
        assert rewritten.startswith('<?xml'), 'XML declaration must be first line'
        assert '<!DOCTYPE nmaprun' in rewritten, 'DOCTYPE required for Metasploit import'

    def test_non_matching_filenames_ignored(self, tmp_path):
        """Files that aren't portU_*.xml are skipped (e.g. a TCP result file)."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'port80.xml').write_text(self._make_nmap_xml('10.0.0.1', '80', 'open'))
        result = _filter_udp_live_hosts(str(tmp_path))
        assert result == {}

    def test_missing_live_hosts_file_skipped(self, tmp_path):
        """A portU_*.xml with no matching live_hosts file is skipped, not errored."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text(self._make_nmap_xml('10.0.0.1', '500', 'open'))
        # No corresponding live_hosts/portU_500.txt written
        result = _filter_udp_live_hosts(str(tmp_path))
        assert result == {}

    def test_malformed_xml_logs_error_and_skips(self, tmp_path, capsys):
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        (nmap_dir / 'portU_500.xml').write_text('<nmaprun><host>')  # unclosed tags
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')
        result = _filter_udp_live_hosts(str(tmp_path))
        assert result == {}
        assert 'Error parsing portU_500.xml' in capsys.readouterr().out

    def test_host_without_ipv4_address_skipped(self, tmp_path):
        """A <host> lacking an ipv4-typed <address> is skipped, not KeyErrored."""
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '</nmaprun>'
        )
        (nmap_dir / 'portU_500.xml').write_text(xml)
        (live_dir / 'portU_500.txt').write_text('10.0.0.1\n')
        result = _filter_udp_live_hosts(str(tmp_path))
        assert result == {'U:500': 0}

    def test_address_without_addr_attribute_skipped_others_kept(self, tmp_path):
        """A KeyError from attrib['addr'] escaped both walks.

        In the first walk it escaped `except etree.ParseError`, so `confirmed`
        never got built; in the XML-rewrite walk it escaped the guard entirely,
        propagating out after live_hosts had already been rewritten.  Either way
        a genuinely confirmed host was lost.
        """
        nmap_dir = tmp_path / 'nmap_results'
        live_dir = tmp_path / 'discovery' / 'live_hosts'
        nmap_dir.mkdir()
        live_dir.mkdir(parents=True)
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.6" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="500">'
            '<state state="open"/></port></ports></host>'
            '</nmaprun>'
        )
        (nmap_dir / 'portU_500.xml').write_text(xml)
        (live_dir / 'portU_500.txt').write_text('10.0.0.6\n')

        result = _filter_udp_live_hosts(str(tmp_path))

        assert result == {'U:500': 1}
        assert (live_dir / 'portU_500.txt').read_text().strip() == '10.0.0.6'
        tree = etree.parse(str(nmap_dir / 'portU_500.xml'))
        hosts = tree.findall('host')
        assert len(hosts) == 1
        assert hosts[0].find('address').attrib['addr'] == '10.0.0.6'


# ── _discovery_wait ───────────────────────────────────────────────────────────

def _masscan_ping_xml(*ips):
    """Minimal masscan XML for host-discovery tests."""
    hosts = ''.join(
        f'<host><address addr="{ip}" addrtype="ipv4"/></host>'
        for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun>{hosts}</nmaprun>'


@pytest.mark.parametrize('count,expected', [
    (0,    '1'),
    (512,  '1'),
    (513,  '2'),
    (4096, '2'),
    (4097, '3'),
    (65536, '3'),
])
def test_discovery_wait(count, expected):
    assert _discovery_wait(count) == expected


# ── _discover_internal_masscan ────────────────────────────────────────────────

class TestDiscoverInternalMasscan:
    """Unit tests for _discover_internal_masscan()."""

    def _make_mock_proc(self):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.pid = 99999
        # Finite stderr so _stream_masscan_progress()'s read(1) loop terminates;
        # a bare MagicMock would return truthy bytes forever and hang the join.
        mock_proc.stderr = io.BytesIO(b'')
        return mock_proc

    def _write_xml(self, path, *ips):
        path.write_text(_masscan_ping_xml(*ips))

    def test_single_sweep_only(self, tmp_path):
        """Only one masscan invocation is made (no dual sweep)."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            xml_path = disc / cmd[out_idx].split('/')[-1]
            self._write_xml(xml_path, '10.0.0.1')
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        assert len(captured_cmds) == 1
        assert '10.0.0.1' in ips

    def test_no_source_port_flag(self, tmp_path):
        """masscan command must not include -g or --source-port."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        cmd = captured_cmds[0]
        assert '-g' not in cmd
        assert '--source-port' not in cmd

    def test_trims_ports_above_state_ceiling(self, tmp_path):
        """Port list is DISCOVERY_TCP_PORTS_INTERNAL (5 ports) for large target counts."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/8\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        large_count = INTERNAL_DISCOVERY_STATE_CEILING + 1
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, large_count)

        p_idx = captured_cmds[0].index('-p') + 1
        assert captured_cmds[0][p_idx] == DISCOVERY_TCP_PORTS_INTERNAL
        assert captured_cmds[0][p_idx] != DISCOVERY_MASSCAN_PORTS_INTERNAL

    def test_uses_broad_ports_below_state_ceiling(self, tmp_path):
        """Port list is DISCOVERY_MASSCAN_PORTS_INTERNAL (10 ports) for normal target counts."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        p_idx = captured_cmds[0].index('-p') + 1
        assert captured_cmds[0][p_idx] == DISCOVERY_MASSCAN_PORTS_INTERNAL

    def test_caps_rate_to_internal_max(self, tmp_path):
        """Rate is capped to INTERNAL_DISCOVERY_MAX_RATE even when user passes a higher rate."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        user_rate = str(INTERNAL_DISCOVERY_MAX_RATE * 10)
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), user_rate, None, 256)

        rate_idx = captured_cmds[0].index('--max-rate') + 1
        assert int(captured_cmds[0][rate_idx]) <= INTERNAL_DISCOVERY_MAX_RATE

    def test_respects_user_rate_below_cap(self, tmp_path):
        """Rate below INTERNAL_DISCOVERY_MAX_RATE is passed through unchanged."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        user_rate = str(INTERNAL_DISCOVERY_MAX_RATE // 2)
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), user_rate, None, 256)

        rate_idx = captured_cmds[0].index('--max-rate') + 1
        assert int(captured_cmds[0][rate_idx]) == int(user_rate)

    def test_uses_retries_1(self, tmp_path):
        """masscan sweep uses --retries 1."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        cmd = captured_cmds[0]
        retries_idx = cmd.index('--retries') + 1
        assert cmd[retries_idx] == '1'

    def test_adaptive_wait_applied(self, tmp_path):
        """--wait value reflects _discovery_wait(target_count)."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        small_count = 100  # expects _discovery_wait(100) == '1'
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', None, small_count)

        cmd = captured_cmds[0]
        wait_idx = cmd.index('--wait') + 1
        assert cmd[wait_idx] == _discovery_wait(small_count)

    def test_exclusions_file_added_when_provided(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.1\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_internal_masscan(str(targets), str(disc), '1000', str(excl), 256)

        cmd = captured_cmds[0]
        excl_idx = cmd.index('--excludefile') + 1
        assert cmd[excl_idx] == str(excl)

    def test_masscan_not_found_returns_empty_set(self, tmp_path, capsys):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        with patch('spoonmap.subprocess.Popen', side_effect=FileNotFoundError), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        assert ips == set()
        assert 'masscan not found' in capsys.readouterr().out

    def test_keyboard_interrupt_kills_proc_and_reraises(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        mock_proc = self._make_mock_proc()
        # First wait() (normal path) raises; the cleanup wait() inside the
        # except block must succeed so lines after it actually execute.
        mock_proc.wait.side_effect = [KeyboardInterrupt, None]

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        assert mock_proc.kill.called

    def test_interrupt_inside_popen_reraises_and_restores_terminal(self, tmp_path):
        """SIGINT in the fork/exec window left proc unbound, so the handler's
        proc.kill() raised UnboundLocalError in place of the interrupt — while
        the terminal still had to be restored out of masscan's raw mode."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/24\n')

        with patch('spoonmap.subprocess.Popen', side_effect=KeyboardInterrupt), \
             patch('spoonmap.save_terminal_state', return_value='TERM'), \
             patch('spoonmap.restore_terminal_state') as mock_restore:
            with pytest.raises(KeyboardInterrupt):
                _discover_internal_masscan(str(targets), str(disc), '1000', None, 256)

        assert mock_restore.called


class TestStreamMasscanProgress:
    """Unit tests for _stream_masscan_progress()."""

    def test_prints_line_on_carriage_return(self, capsys):
        proc = MagicMock()
        proc.stderr = io.BytesIO(b'rate: 500/s, 10% done\r')
        _stream_masscan_progress(proc)
        out = capsys.readouterr().out
        assert 'rate: 500/s, 10% done' in out

    def test_multiple_updates_only_last_kept_on_line(self, capsys):
        proc = MagicMock()
        proc.stderr = io.BytesIO(b'update one\rupdate two\r')
        _stream_masscan_progress(proc)
        out = capsys.readouterr().out
        assert 'update one' in out
        assert 'update two' in out

    def test_newline_bytes_dropped_not_buffered(self, capsys):
        """A bare \\n in the stream is neither printed nor accumulated into buf."""
        proc = MagicMock()
        proc.stderr = io.BytesIO(b'abc\ndef\r')
        _stream_masscan_progress(proc)
        out = capsys.readouterr().out
        assert 'abcdef' in out  # \n dropped, both halves land on the same line

    def test_empty_stderr_clears_line_and_returns(self, capsys):
        proc = MagicMock()
        proc.stderr = io.BytesIO(b'')
        _stream_masscan_progress(proc)  # must not raise or hang
        assert capsys.readouterr().out.startswith('\r')

    def test_consecutive_carriage_returns_no_blank_print(self, capsys):
        """An empty buffer at \\r time skips the print (nothing to show)."""
        proc = MagicMock()
        proc.stderr = io.BytesIO(b'\r\rsomething\r')
        _stream_masscan_progress(proc)  # must not raise
        assert 'something' in capsys.readouterr().out


# ── _discover_external_masscan ────────────────────────────────────────────────

class TestDiscoverExternalMasscan:
    """Unit tests for _discover_external_masscan()."""

    def _make_mock_proc(self):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.pid = 88888
        mock_proc.stderr = io.BytesIO(b'')
        return mock_proc

    def test_returns_ips_from_masscan_xml(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('1.2.3.0/24\n')

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml('1.2.3.4'))
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _discover_external_masscan(str(targets), str(disc), '10000', None, 256)

        assert ips == {'1.2.3.4'}

    def test_uses_external_ports_and_retries_2(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('1.2.3.0/24\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_external_masscan(str(targets), str(disc), '10000', None, 256)

        cmd = captured_cmds[0]
        p_idx = cmd.index('-p') + 1
        assert cmd[p_idx] == DISCOVERY_MASSCAN_PORTS_EXTERNAL
        retries_idx = cmd.index('--retries') + 1
        assert cmd[retries_idx] == '2'

    def test_exclusions_file_added_when_provided(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('1.2.3.0/24\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('1.2.3.4\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            (disc / cmd[out_idx].split('/')[-1]).write_text(_masscan_ping_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _discover_external_masscan(str(targets), str(disc), '10000', str(excl), 256)

        cmd = captured_cmds[0]
        excl_idx = cmd.index('--excludefile') + 1
        assert cmd[excl_idx] == str(excl)

    def test_masscan_not_found_returns_empty_set(self, tmp_path, capsys):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('1.2.3.0/24\n')

        with patch('spoonmap.subprocess.Popen', side_effect=FileNotFoundError), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _discover_external_masscan(str(targets), str(disc), '10000', None, 256)

        assert ips == set()
        assert 'masscan not found' in capsys.readouterr().out

    def test_keyboard_interrupt_kills_proc_and_reraises(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('1.2.3.0/24\n')

        mock_proc = self._make_mock_proc()
        # First wait() (normal path) raises; the cleanup wait() inside the
        # except block must succeed so lines after it actually execute.
        mock_proc.wait.side_effect = [KeyboardInterrupt, None]

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                _discover_external_masscan(str(targets), str(disc), '10000', None, 256)

        assert mock_proc.kill.called

    def test_interrupt_inside_popen_reraises_and_restores_terminal(self, tmp_path):
        """SIGINT in the fork/exec window left proc unbound, so the handler's
        proc.kill() raised UnboundLocalError in place of the interrupt — while
        the terminal still had to be restored out of masscan's raw mode."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('1.2.3.0/24\n')

        with patch('spoonmap.subprocess.Popen', side_effect=KeyboardInterrupt), \
             patch('spoonmap.save_terminal_state', return_value='TERM'), \
             patch('spoonmap.restore_terminal_state') as mock_restore:
            with pytest.raises(KeyboardInterrupt):
                _discover_external_masscan(str(targets), str(disc), '10000', None, 256)

        assert mock_restore.called


class TestExternalHostDiscovery:
    """Unit tests for _external_host_discovery() — masscan + nmap -sn union."""

    def test_unions_masscan_and_nmap_ips(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('1.2.3.4\n')

        with patch('spoonmap._discover_external_masscan',
                   return_value={'1.2.3.4', '1.2.3.5'}), \
             patch('spoonmap._nmap_host_discovery', return_value={'1.2.3.6'}):
            live_ips = _external_host_discovery(str(targets), str(disc), '10000', None, 256)

        assert live_ips == {'1.2.3.4', '1.2.3.5', '1.2.3.6'}


# ── _nmap_host_discovery ───────────────────────────────────────────────────────

class TestNmapHostDiscovery:
    """Unit tests for _nmap_host_discovery() (nmap -sn ICMP echo sweep)."""

    def _make_mock_proc(self):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.pid = 77777
        return mock_proc

    def test_returns_up_hosts_from_xml(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text(
                _nmap_sn_xml(('10.0.0.1', 'up'), ('10.0.0.2', 'down')))
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _nmap_host_discovery(str(targets), str(disc), '', None)

        assert ips == {'10.0.0.1'}

    def test_source_port_and_exclusions_flags(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')
        excl = tmp_path / 'excl.txt'
        excl.write_text('10.0.0.9\n')

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(cmd)
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text(_nmap_sn_xml())
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            _nmap_host_discovery(str(targets), str(disc), '88', str(excl))

        cmd = captured_cmds[0]
        assert cmd[cmd.index('--source-port') + 1] == '88'
        assert cmd[cmd.index('--excludefile') + 1] == str(excl)

    def test_missing_output_xml_returns_empty_set(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        with patch('spoonmap.subprocess.Popen', return_value=self._make_mock_proc()), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _nmap_host_discovery(str(targets), str(disc), '', None)

        assert ips == set()

    def test_malformed_xml_logged_and_empty_set_returned(self, tmp_path, capsys):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text('<nmaprun><host>')  # unclosed tags
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _nmap_host_discovery(str(targets), str(disc), '', None)

        assert ips == set()
        assert 'Error parsing nmap discovery XML' in capsys.readouterr().out

    def test_host_without_ipv4_address_skipped(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><status state="up"/>'
            '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/></host>'
            '</nmaprun>'
        )

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text(xml)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _nmap_host_discovery(str(targets), str(disc), '', None)

        assert ips == set()

    def test_address_without_addr_attribute_skipped_others_kept(self, tmp_path):
        """A bare attrib['addr'] raised KeyError, which `except etree.ParseError`
        does not catch — so one malformed element discarded the whole sweep."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><status state="up"/><address addrtype="ipv4"/></host>'
            '<host><status state="up"/>'
            '<address addr="10.0.0.7" addrtype="ipv4"/></host>'
            '</nmaprun>'
        )

        def fake_popen(cmd, **kwargs):
            out_idx = cmd.index('-oX') + 1
            Path(cmd[out_idx]).write_text(xml)
            return self._make_mock_proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _nmap_host_discovery(str(targets), str(disc), '', None)

        assert ips == {'10.0.0.7'}

    def test_nmap_not_found_returns_empty_set(self, tmp_path, capsys):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        with patch('spoonmap.subprocess.Popen', side_effect=FileNotFoundError), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            ips = _nmap_host_discovery(str(targets), str(disc), '', None)

        assert ips == set()
        assert 'nmap not found' in capsys.readouterr().out

    def test_interrupt_inside_popen_reraises_and_restores_terminal(self, tmp_path):
        """SIGINT in the fork/exec window left proc unbound, so the handler's
        proc.kill() raised UnboundLocalError in place of the interrupt."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        with patch('spoonmap.subprocess.Popen', side_effect=KeyboardInterrupt), \
             patch('spoonmap.save_terminal_state', return_value='TERM'), \
             patch('spoonmap.restore_terminal_state') as mock_restore:
            with pytest.raises(KeyboardInterrupt):
                _nmap_host_discovery(str(targets), str(disc), '', None)

        assert mock_restore.called

    def test_keyboard_interrupt_kills_proc_and_reraises(self, tmp_path):
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        mock_proc = self._make_mock_proc()
        mock_proc.wait.side_effect = [KeyboardInterrupt, None]

        with patch('spoonmap.subprocess.Popen', return_value=mock_proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                _nmap_host_discovery(str(targets), str(disc), '', None)

        assert mock_proc.kill.called


# ── _internal_host_discovery ──────────────────────────────────────────────────

class TestInternalHostDiscovery:
    """Unit tests for _internal_host_discovery()."""

    def test_unions_masscan_and_nmap_for_small_targets(self, tmp_path):
        """For small target counts, returns union of masscan + nmap IPs."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        masscan_ips = {'10.0.0.1', '10.0.0.2'}
        nmap_ips = {'10.0.0.3'}

        with patch('spoonmap._discover_internal_masscan', return_value=masscan_ips), \
             patch('spoonmap._nmap_host_discovery', return_value=nmap_ips):
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD)

        assert live_ips == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}

    def test_skips_nmap_for_large_targets(self, tmp_path):
        """For large target counts, nmap -sn is not run."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.0/8\n')

        masscan_ips = {'10.0.0.1', '10.0.0.2'}

        with patch('spoonmap._discover_internal_masscan', return_value=masscan_ips), \
             patch('spoonmap._nmap_host_discovery') as mock_nmap:
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD + 1)

        mock_nmap.assert_not_called()
        assert live_ips == masscan_ips

    def test_nmap_starts_before_masscan_returns(self, tmp_path):
        """nmap thread is started concurrently — it begins before masscan finishes."""
        import threading as _threading

        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        event_order = []
        barrier = _threading.Barrier(2)

        def slow_masscan(*args, **kwargs):
            barrier.wait(timeout=5)  # sync with nmap thread start
            event_order.append('masscan_done')
            return {'10.0.0.1'}

        def nmap_side_effect(*args, **kwargs):
            event_order.append('nmap_started')
            barrier.wait(timeout=5)
            return {'10.0.0.2'}

        with patch('spoonmap._discover_internal_masscan', side_effect=slow_masscan), \
             patch('spoonmap._nmap_host_discovery', side_effect=nmap_side_effect):
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD)

        assert 'nmap_started' in event_order
        assert 'masscan_done' in event_order
        assert live_ips == {'10.0.0.1', '10.0.0.2'}

    def test_deduplicates_ips_across_sweeps(self, tmp_path):
        """IPs found by both masscan and nmap are deduplicated."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n10.0.0.2\n')

        shared_ip = '10.0.0.1'

        with patch('spoonmap._discover_internal_masscan',
                   return_value={shared_ip, '10.0.0.3'}), \
             patch('spoonmap._nmap_host_discovery',
                   return_value={shared_ip, '10.0.0.4'}):
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD)

        assert live_ips == {shared_ip, '10.0.0.3', '10.0.0.4'}
        assert len(live_ips) == 3

    def test_nmap_thread_exception_logged_masscan_ips_still_returned(self, tmp_path, capsys):
        """An exception in the background nmap thread is caught, warned about,
        and doesn't lose the masscan results."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        with patch('spoonmap._discover_internal_masscan', return_value={'10.0.0.1'}), \
             patch('spoonmap._nmap_host_discovery', side_effect=RuntimeError('nmap crashed')):
            live_ips = _internal_host_discovery(
                str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD)

        assert live_ips == {'10.0.0.1'}
        assert 'nmap discovery error' in capsys.readouterr().out

    def test_keyboard_interrupt_during_masscan_reraised_after_nmap_join(self, tmp_path):
        """KeyboardInterrupt while masscan runs waits for the nmap thread, then re-raises."""
        disc = tmp_path / 'discovery'
        disc.mkdir()
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')

        with patch('spoonmap._discover_internal_masscan', side_effect=KeyboardInterrupt), \
             patch('spoonmap._nmap_host_discovery', return_value={'10.0.0.2'}):
            with pytest.raises(KeyboardInterrupt):
                _internal_host_discovery(
                    str(targets), str(disc), '1000', None, HOST_DISCOVERY_NMAP_THRESHOLD)


# ── --target CLI flag ─────────────────────────────────────────────────────────

class TestParseRangeLine:
    """The shared per-line parser behind both target files and --target."""

    @pytest.mark.parametrize('line,expected', [
        ('10.0.0.5', (167772165, 167772165)),
        ('10.0.0.0/30', (167772160, 167772163)),
        ('10.0.0.1-10.0.0.3', (167772161, 167772163)),
        ('10.0.0.0 255.255.255.252', (167772160, 167772163)),
    ])
    def test_accepted_forms(self, line, expected):
        bounds, error = _parse_range_line(line)
        assert error is None
        assert bounds == expected

    def test_ipv6_reported_separately(self):
        """IPv6 parses but is not IPv4, so it gets its own error code."""
        bounds, error = _parse_range_line('2001:db8::/32')
        assert bounds is None
        assert error == 'ipv6'

    @pytest.mark.parametrize('line', [
        'nonsense',
        '10.0.0.9-10.0.0.1',       # reversed range
        '10.0.0.0 999.999.999.999',
        '10.0.0.300',
    ])
    def test_rejected_forms(self, line):
        bounds, error = _parse_range_line(line)
        assert bounds is None
        assert error == 'invalid'

    def test_file_parser_still_skips_bad_lines_silently(self, tmp_path):
        """Extracting the helper must not change _parse_target_ranges behaviour:
        a junk line is skipped without aborting the surrounding parse."""
        f = tmp_path / 'ranges.txt'
        f.write_text('10.0.0.0/30\nnonsense\n10.0.1.1\n')
        assert _parse_target_ranges(str(f)) == [
            (167772160, 167772163), (167772417, 167772417)]

    def test_file_parser_warns_on_ipv6_with_line_number(self, tmp_path, capsys):
        f = tmp_path / 'ranges.txt'
        f.write_text('10.0.0.1\n2001:db8::1\n')
        result = _parse_target_ranges(str(f))
        out = capsys.readouterr().out
        assert result == [(167772161, 167772161)]
        assert 'line 2' in out
        assert 'IPv4 only' in out


class TestParseTargetArg:
    """--target value validation."""

    def test_single_ip(self):
        assert _parse_target_arg('10.0.0.5') == ['10.0.0.5']

    def test_comma_separated_with_whitespace(self):
        assert _parse_target_arg(' 10.0.0.0/24 , 10.0.1.5 ') == [
            '10.0.0.0/24', '10.0.1.5']

    def test_range_and_netmask_forms(self):
        assert _parse_target_arg('10.0.0.1-10.0.0.9') == ['10.0.0.1-10.0.0.9']
        assert _parse_target_arg('10.0.0.0 255.255.0.0') == ['10.0.0.0 255.255.0.0']

    def test_empty_value_rejected(self):
        with pytest.raises(ValueError, match='no address'):
            _parse_target_arg('')

    def test_only_commas_rejected(self):
        with pytest.raises(ValueError, match='no address'):
            _parse_target_arg(' , , ')

    def test_ipv6_rejected_by_name(self):
        with pytest.raises(ValueError, match='not IPv4'):
            _parse_target_arg('2001:db8::1')

    def test_garbage_rejected_naming_the_token(self):
        """The message must name the offending token, not just fail."""
        with pytest.raises(ValueError, match='nope'):
            _parse_target_arg('10.0.0.1,nope')


class TestCliTargetFromArgv:
    """--target extraction from argv."""

    def test_absent_returns_none(self):
        assert _cli_target_from_argv(['spoonmap.py']) is None

    def test_value_returned(self):
        assert _cli_target_from_argv(
            ['spoonmap.py', '--target', '10.0.0.5']) == '10.0.0.5'

    def test_value_missing_at_end_rejected(self):
        with pytest.raises(ValueError, match='requires an address'):
            _cli_target_from_argv(['spoonmap.py', '--target'])

    def test_next_flag_not_consumed_as_value(self):
        """--target --resume must not treat --resume as an address."""
        with pytest.raises(ValueError, match='requires an address'):
            _cli_target_from_argv(['spoonmap.py', '--target', '--resume'])

    def test_coexists_with_other_flags(self):
        assert _cli_target_from_argv(
            ['spoonmap.py', '--resume', '--target', '10.0.0.5']) == '10.0.0.5'


class TestResolveCliTarget:
    """main()'s entry point: returns tokens or exits non-zero."""

    def test_absent_returns_none(self):
        assert _resolve_cli_target(['spoonmap.py']) is None

    def test_valid_returns_tokens(self):
        assert _resolve_cli_target(
            ['spoonmap.py', '--target', '10.0.0.0/24']) == ['10.0.0.0/24']

    def test_invalid_exits_nonzero(self, capsys):
        """A bad address must abort the run, not scan an empty target set."""
        with pytest.raises(SystemExit) as exc:
            _resolve_cli_target(['spoonmap.py', '--target', 'nope'])
        assert exc.value.code == 1
        assert 'ERROR' in capsys.readouterr().out

    def test_missing_value_exits_nonzero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            _resolve_cli_target(['spoonmap.py', '--target'])
        assert exc.value.code == 1
        assert 'requires an address' in capsys.readouterr().out


class TestWriteCliTargetFile:
    """--target writes its own scope file and never touches ranges.txt."""

    def test_writes_one_token_per_line(self, tmp_path):
        path = _write_cli_target_file(['10.0.0.5', '10.0.1.0/24'], str(tmp_path))
        assert Path(path).read_text() == '10.0.0.5\n10.0.1.0/24\n'

    def test_lands_in_output_path(self, tmp_path):
        path = _write_cli_target_file(['10.0.0.5'], str(tmp_path))
        assert path == str(tmp_path / 'cli_targets.txt')

    def test_does_not_touch_ranges_txt(self, tmp_path):
        """ranges.txt is the operator's scope input; a convenience flag must
        never overwrite it (the 2021 PR #12 approach did)."""
        ranges = tmp_path / 'ranges.txt'
        ranges.write_text('192.168.50.0/24\n')
        _write_cli_target_file(['10.0.0.5'], str(tmp_path))
        assert ranges.read_text() == '192.168.50.0/24\n'

    def test_output_is_parseable_by_the_file_parser(self, tmp_path):
        """Round-trip: what --target writes must be what the scan can read."""
        path = _write_cli_target_file(
            ['10.0.0.0/30', '10.0.1.1-10.0.1.3'], str(tmp_path))
        assert _parse_target_ranges(path) == [
            (167772160, 167772163), (167772417, 167772419)]

    def test_atomic_leaves_no_temp_file(self, tmp_path):
        _write_cli_target_file(['10.0.0.5'], str(tmp_path))
        assert [p.name for p in tmp_path.iterdir()] == ['cli_targets.txt']


# ── greppable (-oG) output ────────────────────────────────────────────────────

class TestGnmapPath:
    def test_swaps_xml_for_gnmap(self):
        assert _gnmap_path('/out/nmap_results/port80.xml') == \
            '/out/nmap_results/port80.gnmap'

    def test_udp_port_filename(self):
        assert _gnmap_path('/out/portU_161.xml') == '/out/portU_161.gnmap'


class TestBannerPassGnmapFlag:
    """Every banner pass gets its own -oG file; the script pass gets none."""

    def test_tcp_banner_pass_includes_og(self):
        cmd = _build_nmap_cmd('80', '/in.txt', '/out/port80.xml', '53',
                              target_scan='External')
        assert cmd[cmd.index('-oG') + 1] == '/out/port80.gnmap'

    def test_udp_banner_pass_includes_og(self):
        cmd = _build_nmap_cmd('U:161', '/in.txt', '/out/portU_161.xml', '53',
                              target_scan='External')
        assert cmd[cmd.index('-oG') + 1] == '/out/portU_161.gnmap'

    def test_script_pass_has_no_og(self):
        """A shared -oG across the script pass would duplicate the banner data."""
        cmd = _build_nmap_cmd('80', '/in.txt', '/out/port80.xml', '53',
                              script_scan=True, target_scan='External',
                              script_only=True)
        assert '-oG' not in cmd

    def test_one_og_file_per_port(self):
        """Distinct ports must not share an -oG target: concurrent workers
        appending to one file interleave their writes."""
        a = _build_nmap_cmd('22', '/in.txt', '/out/port22.xml', '53',
                            target_scan='External')
        b = _build_nmap_cmd('80', '/in.txt', '/out/port80.xml', '53',
                            target_scan='External')
        assert a[a.index('-oG') + 1] != b[b.index('-oG') + 1]
        assert '--append-output' not in a


class TestParseGnmapLine:
    def test_host_with_ports(self):
        ip, host_field, entries = _parse_gnmap_line(
            'Host: 10.0.0.5 (web01)\tPorts: 22/open/tcp//ssh///'
            '\tIgnored State: closed (1)')
        assert ip == '10.0.0.5'
        assert host_field == '10.0.0.5 (web01)'
        assert entries == ['22/open/tcp//ssh///']

    def test_multiple_ports_split_on_comma(self):
        _, _, entries = _parse_gnmap_line(
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///')
        assert entries == ['22/open/tcp//ssh///', '80/open/tcp//http///']

    def test_status_up_line_ignored(self):
        """A host-discovery line carries no ports and is not a scan result."""
        assert _parse_gnmap_line('Host: 10.0.0.9 ()\tStatus: Up') is None

    def test_comment_line_ignored(self):
        assert _parse_gnmap_line('# Nmap 7.99 scan initiated') is None

    def test_empty_host_field_ignored(self):
        assert _parse_gnmap_line('Host: \tPorts: 22/open/tcp//ssh///') is None

    def test_empty_ports_field_ignored(self):
        assert _parse_gnmap_line('Host: 10.0.0.5 ()\tPorts: ') is None


class TestGnmapPortSortKey:
    def test_orders_numerically_not_lexically(self):
        entries = ['443/open/tcp///', '80/open/tcp///', '8080/open/tcp///']
        assert [e.split('/')[0] for e in sorted(entries, key=_gnmap_port_sort_key)] \
            == ['80', '443', '8080']

    def test_unparseable_entry_sorts_last_without_raising(self):
        entries = ['garbage', '80/open/tcp///']
        assert sorted(entries, key=_gnmap_port_sort_key)[0] == '80/open/tcp///'


class TestAggregateGnmap:
    def test_merges_one_line_per_host_across_ports(self, tmp_path):
        """Each port is a separate nmap run, so a host open on two ports appears
        in two files; grepable output is one line per host."""
        (tmp_path / 'port22.gnmap').write_text(
            'Host: 10.0.0.5 (web01)\tPorts: 22/open/tcp//ssh///\n')
        (tmp_path / 'port80.gnmap').write_text(
            'Host: 10.0.0.5 (web01)\tPorts: 80/open/tcp//http///\n')
        lines, scanned = _aggregate_gnmap(str(tmp_path))
        assert lines == [
            'Host: 10.0.0.5 (web01)\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///']
        assert scanned == {'port22', 'port80'}

    def test_hosts_sorted_numerically(self, tmp_path):
        (tmp_path / 'port22.gnmap').write_text(
            'Host: 10.0.0.200 ()\tPorts: 22/open/tcp///\n'
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///\n')
        lines, _ = _aggregate_gnmap(str(tmp_path))
        assert lines[0].startswith('Host: 10.0.0.5')

    def test_duplicate_port_entry_not_repeated(self, tmp_path):
        (tmp_path / 'port22.gnmap').write_text(
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///\n')
        (tmp_path / 'port22b.gnmap').write_text(
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///\n')
        lines, _ = _aggregate_gnmap(str(tmp_path))
        assert lines == ['Host: 10.0.0.5 ()\tPorts: 22/open/tcp///']

    def test_hostname_form_preferred_over_bare_address(self, tmp_path):
        (tmp_path / 'port22.gnmap').write_text(
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///\n')
        (tmp_path / 'port80.gnmap').write_text(
            'Host: 10.0.0.5 (web01)\tPorts: 80/open/tcp///\n')
        lines, _ = _aggregate_gnmap(str(tmp_path))
        assert lines[0].startswith('Host: 10.0.0.5 (web01)')

    def test_non_gnmap_files_ignored(self, tmp_path):
        (tmp_path / 'port22.xml').write_text('<nmaprun></nmaprun>')
        (tmp_path / 'port22.gnmap.failed').write_text(
            'Host: 10.9.9.9 ()\tPorts: 22/open/tcp///\n')
        lines, scanned = _aggregate_gnmap(str(tmp_path))
        assert lines == []
        assert scanned == set()

    def test_missing_directory_returns_empty(self, tmp_path):
        lines, scanned = _aggregate_gnmap(str(tmp_path / 'nope'))
        assert (lines, scanned) == ([], set())

    def test_real_file_shape_comments_and_status_skipped(self, tmp_path):
        """nmap always brackets -oG output with comment lines, and a host with
        no open ports appears as 'Status: Up'."""
        (tmp_path / 'port22.gnmap').write_text(
            '# Nmap 7.99 scan initiated Thu Aug 21 11:00:00 2026 as: nmap -oG\n'
            'Host: 10.0.0.5 (web01)\tPorts: 22/open/tcp//ssh///\tIgnored State: closed (1)\n'
            'Host: 10.0.0.9 ()\tStatus: Up\n'
            '# Nmap done at Thu Aug 21 11:00:04 2026 -- 2 IP addresses\n')
        lines, _ = _aggregate_gnmap(str(tmp_path))
        assert lines == [
            'Host: 10.0.0.5 (web01)\tPorts: 22/open/tcp//ssh///']

    def test_unreadable_file_does_not_lose_other_ports(self, tmp_path, capsys):
        (tmp_path / 'port22.gnmap').write_text(
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///\n')
        (tmp_path / 'port80.gnmap').mkdir()   # a directory reads as OSError
        lines, _ = _aggregate_gnmap(str(tmp_path))
        assert lines == ['Host: 10.0.0.5 ()\tPorts: 22/open/tcp///']
        assert 'could not read' in capsys.readouterr().out


class TestWriteGnmapResult:
    def _results(self, tmp_path):
        rd = tmp_path / 'nmap_results'
        rd.mkdir()
        return rd

    def test_writes_aggregate_with_header_and_count(self, tmp_path):
        rd = self._results(tmp_path)
        (rd / 'port22.gnmap').write_text(
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///\n')
        (rd / 'port22.xml').write_text('<nmaprun></nmaprun>')
        _write_gnmap_result(str(tmp_path), str(rd))
        content = (tmp_path / 'spoonmap_output.gnmap').read_text()
        assert content.startswith('# SpooNMAP aggregated greppable output\n')
        assert 'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///' in content
        assert content.endswith('# SpooNMAP done: 1 hosts\n')

    def test_port_with_xml_but_no_gnmap_is_disclosed(self, tmp_path, capsys):
        """A scan completed before -oG existed must not silently shrink the
        artifact's coverage."""
        rd = self._results(tmp_path)
        (rd / 'port22.gnmap').write_text(
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///\n')
        (rd / 'port22.xml').write_text('<nmaprun></nmaprun>')
        (rd / 'port443.xml').write_text('<nmaprun></nmaprun>')
        _write_gnmap_result(str(tmp_path), str(rd))
        out = capsys.readouterr().out
        assert 'port443' in out
        assert '1 port(s)' in out

    def test_sql_xml_not_reported_as_a_gap(self, tmp_path, capsys):
        """_scan_extra_sql_ports writes port{N}_sql.xml with no -oG."""
        rd = self._results(tmp_path)
        (rd / 'port22.gnmap').write_text(
            'Host: 10.0.0.5 ()\tPorts: 22/open/tcp///\n')
        (rd / 'port22.xml').write_text('<nmaprun></nmaprun>')
        (rd / 'port1433_sql.xml').write_text('<nmaprun></nmaprun>')
        _write_gnmap_result(str(tmp_path), str(rd))
        assert 'no greppable output' not in capsys.readouterr().out

    def test_many_missing_ports_truncated(self, tmp_path, capsys):
        rd = self._results(tmp_path)
        for n in range(7):
            (rd / f'port{100 + n}.xml').write_text('<nmaprun></nmaprun>')
        _write_gnmap_result(str(tmp_path), str(rd))
        out = capsys.readouterr().out
        assert '7 port(s)' in out
        assert '...' in out

    def test_nothing_to_write_creates_no_file(self, tmp_path):
        rd = self._results(tmp_path)
        _write_gnmap_result(str(tmp_path), str(rd))
        assert not (tmp_path / 'spoonmap_output.gnmap').exists()

    def test_missing_result_dir_creates_no_file(self, tmp_path):
        _write_gnmap_result(str(tmp_path), str(tmp_path / 'nope'))
        assert not (tmp_path / 'spoonmap_output.gnmap').exists()

    def test_gnmap_listed_for_cleanup(self):
        """--cleanup must remove the new artifact along with the others."""
        assert 'spoonmap_output.gnmap' in spoonmap._RESULT_FILES


class TestQuarantineQuarantinesGnmap:
    """A failed port's .gnmap must not outlive its quarantined .xml."""

    def test_gnmap_sibling_renamed(self, tmp_path):
        xml = tmp_path / 'port80.xml'
        gnmap = tmp_path / 'port80.gnmap'
        xml.write_text('<nmaprun></nmaprun>')
        gnmap.write_text('Host: 10.0.0.5 ()\tPorts: 80/open/tcp///\n')
        _quarantine_failed_output(str(xml))
        assert not gnmap.exists()
        assert (tmp_path / 'port80.gnmap.failed').exists()

    def test_quarantined_gnmap_excluded_from_aggregate(self, tmp_path):
        """The end the rename exists for: a failed port contributes nothing."""
        xml = tmp_path / 'port80.xml'
        xml.write_text('<nmaprun></nmaprun>')
        (tmp_path / 'port80.gnmap').write_text(
            'Host: 10.9.9.9 ()\tPorts: 80/open/tcp///\n')
        _quarantine_failed_output(str(xml))
        lines, _ = _aggregate_gnmap(str(tmp_path))
        assert lines == []

    def test_absent_gnmap_is_not_an_error(self, tmp_path):
        xml = tmp_path / 'port80.xml'
        xml.write_text('<nmaprun></nmaprun>')
        assert _quarantine_failed_output(str(xml)) == str(xml) + '.failed'


class TestNseDirResolution:
    """Bundled NSE scripts must resolve to a real, packaged path both in a
    checkout and once installed from the wheel (see pyproject.toml's
    force-include of nse/ -> spoonmap_nse/)."""

    def _nse_paths(self, port_scripts):
        """Pull out every comma-separated token that looks like a bundled
        script path — the maps mix bare nmap script names (e.g.
        'ms-sql-ntlm-info') with absolute paths to files under _NSE_DIR, and
        only the latter are ours to ship."""
        paths = []
        for flags in port_scripts.values():
            for token in flags.split(','):
                if token.endswith('.nse'):
                    paths.append(token)
        return paths

    def test_every_bundled_nse_path_exists_on_disk(self):
        paths = self._nse_paths(INTERNAL_PORT_SCRIPTS) + \
            self._nse_paths(EXTERNAL_PORT_SCRIPTS)
        assert paths, 'expected at least one bundled .nse path to check'
        for path in paths:
            assert os.path.isfile(path), f'missing bundled NSE script: {path}'

    def test_nse_dir_prefers_checkout_directory(self):
        """A normal checkout ships nse/ alongside spoonmap.py, so that must
        win over the installed-wheel fallback."""
        assert spoonmap._NSE_DIR == f'{spoonmap._DIR}/nse'

    def test_resolver_falls_back_when_checkout_nse_dir_absent(self, tmp_path):
        """Test the resolver as a unit against a tmp_path with no nse/
        subdirectory, rather than touching the real checkout, to force the
        installed-wheel branch."""
        assert _resolve_nse_dir(str(tmp_path)) == f'{tmp_path}/spoonmap_nse'

    def test_no_call_site_reverts_to_dir_relative_nse_path(self):
        """CI's wheel-contents check (.github/workflows/ci.yml) only walks
        INTERNAL_PORT_SCRIPTS and EXTERNAL_PORT_SCRIPTS, not the other ~45 of
        the 65 _NSE_DIR call sites living in _FINDING_REPRO and
        _scan_extra_sql_ports(). A revert of any one of those back to a
        `_DIR`-relative `nse/` literal (bypassing _resolve_nse_dir(), and thus
        breaking once installed from the wheel) would be invisible to that
        check. Assert on the module's own parsed AST rather than its raw
        source text: a `_DIR}/nse/...` f-string call site parses as an
        ast.JoinedStr whose first part is a FormattedValue naming `_DIR`,
        immediately followed by a Constant string starting with '/nse/' —
        a shape only real code can produce. A comment or docstring that
        merely quotes that same text (as prose, not syntax) has no such
        JoinedStr node at all, so it can't trip this the way a plain
        substring search over inspect.getsource() could."""
        tree = ast.parse(inspect.getsource(spoonmap))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            parts = node.values
            for i, part in enumerate(parts):
                if not (isinstance(part, ast.FormattedValue)
                        and isinstance(part.value, ast.Name)
                        and part.value.id == '_DIR'):
                    continue
                following = parts[i + 1] if i + 1 < len(parts) else None
                if (isinstance(following, ast.Constant)
                        and isinstance(following.value, str)
                        and following.value.startswith('/nse/')):
                    offenders.append(f'{{_DIR}}{following.value}')
        assert not offenders, (
            'found _DIR-relative nse/ path(s); bundled scripts must be '
            'referenced via _NSE_DIR so they resolve in an installed wheel: '
            + str(offenders)
        )


class TestOperatorDirResolution:
    """Operator data (config.json, exclusions, output) must resolve against
    the CWD, never the module's own location — the opposite anchor from
    _DIR/_NSE_DIR, which stay module-relative for bundled program data."""

    def test_operator_dir_is_the_cwd(self, tmp_path, monkeypatch):
        # Compare realpaths on both sides: os.getcwd() resolves symlinks in
        # the path (e.g. macOS's /tmp -> /private/tmp), so comparing directly
        # against str(tmp_path) would depend on pytest happening to hand out
        # an already-resolved tmp_path rather than on the helper's behaviour.
        monkeypatch.chdir(tmp_path)
        assert _operator_dir() == os.path.realpath(str(tmp_path))

    def test_operator_dir_follows_cwd_changes(self, tmp_path, monkeypatch):
        # A real behavioural assertion, not a restatement of os.getcwd():
        # confirm the helper tracks a change in CWD rather than caching one
        # resolved at import time.
        first = tmp_path / 'first'
        second = tmp_path / 'second'
        first.mkdir()
        second.mkdir()
        monkeypatch.chdir(first)
        assert _operator_dir() == os.path.realpath(str(first))
        monkeypatch.chdir(second)
        assert _operator_dir() == os.path.realpath(str(second))

    def test_operator_dir_is_not_module_relative(self, tmp_path, monkeypatch):
        # Regression guard for PR #42: wherever the module is installed must
        # never be where operator data resolves, independent of install
        # mechanism.
        monkeypatch.chdir(tmp_path)
        assert _operator_dir() != spoonmap._DIR


class TestTargetEntries:
    """_target_entries() normalisation: what it notices and what it does not."""

    def test_ignores_order_blank_lines_and_comments(self, tmp_path):
        # live_hosts_combined.txt is rebuilt from a set every run, so a stamp
        # sensitive to layout would reject on every resume.
        a = tmp_path / 'a.txt'
        b = tmp_path / 'b.txt'
        a.write_text('10.0.0.1\n10.0.0.2\n')
        b.write_text('# scope\n\n  10.0.0.2  \n10.0.0.1\n\n')
        assert spoonmap._target_entries(a) == spoonmap._target_entries(b)
        assert spoonmap._target_entries(a) == {'10.0.0.1', '10.0.0.2'}

    def test_cidr_and_expanded_list_are_not_equated(self, tmp_path):
        # Documented limitation: this compares line sets, not address sets. The
        # consequence is a redundant re-scan, never a skipped one.
        cidr = tmp_path / 'cidr.txt'
        expanded = tmp_path / 'expanded.txt'
        cidr.write_text('10.0.0.0/30\n')
        expanded.write_text('10.0.0.1\n10.0.0.2\n')
        assert spoonmap._target_entries(cidr) != spoonmap._target_entries(expanded)

    def test_unreadable_target_file_is_none(self, tmp_path):
        assert spoonmap._target_entries(tmp_path / 'absent.txt') is None

    def test_directory_as_target_file_is_none(self, tmp_path):
        # IsADirectoryError is an OSError, so it must read as unreadable rather
        # than raising out of a resume gate.
        assert spoonmap._target_entries(tmp_path) is None

    def test_undecodable_byte_does_not_raise(self, tmp_path):
        # A gate must not abort the run on a target file masscan would itself
        # reject later.
        target = tmp_path / 'targets.txt'
        target.write_bytes(b'10.0.0.1\n\xff\xfe\n')
        assert '10.0.0.1' in spoonmap._target_entries(target)


class TestResumeTargetStamp:
    """The resume gate must reject a cache that did not cover this run's targets."""

    def _cached(self, tmp_path, target_text='10.0.0.1\n'):
        target = tmp_path / 'targets.txt'
        target.write_text(target_text)
        output = tmp_path / 'out.xml'
        output.write_text('<nmaprun/>')
        return target, output

    def test_identical_target_accepts_cache(self, tmp_path):
        target, output = self._cached(tmp_path)
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        assert spoonmap._resume_cache_usable(str(output), 0, 'phase', target_file=str(target), exclusions_file=None)

    def test_cache_covering_a_superset_is_accepted(self, tmp_path, capsys):
        """The load-bearing case: equality here made --resume thrash.

        The batch phase's target is rebuilt every run from a probe that is not
        resume-gated, and the iterative probe stops at the first port that finds
        hosts, so a later run can legitimately scan fewer hosts than the cache
        covered.  Re-scanning then discards a wider cached result for a narrower
        one, which is the opposite of what --resume is for.
        """
        target, output = self._cached(tmp_path, '10.0.0.1\n10.0.0.2\n10.0.0.3\n')
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        target.write_text('10.0.0.2\n')
        assert spoonmap._resume_cache_usable(str(output), 0, 'phase', target_file=str(target), exclusions_file=None)
        assert 're-running' not in capsys.readouterr().out

    def test_a_single_uncovered_target_rejects_cache(self, tmp_path, capsys):
        target, output = self._cached(tmp_path, '10.0.0.1\n')
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        target.write_text('10.0.0.1\n10.0.0.9\n')   # scope widened
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase', target_file=str(target), exclusions_file=None)
        out = capsys.readouterr().out
        assert '1 target(s) in this run were not covered' in out
        assert '10.0.0.9' in out, 'the message must name what forced the re-scan'

    def test_missing_stamp_rejects_cache(self, tmp_path, capsys):
        # Output from before stamping existed: one redundant re-scan is the safe
        # direction, a silently narrow result is not.
        target, output = self._cached(tmp_path)
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase', target_file=str(target), exclusions_file=None)
        assert 'does not record what it covered' in capsys.readouterr().out

    def test_unreadable_current_target_rejects_with_its_own_reason(self, tmp_path, capsys):
        target, output = self._cached(tmp_path)
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        target.unlink()
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase', target_file=str(target), exclusions_file=None)
        # Distinct from a coverage mismatch: the cache may well be fine.
        assert 'could not be read' in capsys.readouterr().out

    def test_reordered_target_file_still_accepts_cache(self, tmp_path):
        target, output = self._cached(tmp_path, '10.0.0.1\n10.0.0.2\n')
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        target.write_text('10.0.0.2\n10.0.0.1\n')
        assert spoonmap._resume_cache_usable(str(output), 0, 'phase', target_file=str(target), exclusions_file=None)

    def test_exclusions_none_is_a_supported_shape(self, tmp_path):
        # nmap_scan()'s two passes pass exclusions_file=None: they add no
        # --excludefile at all.  target_file has no such escape — every phase
        # scans something, so there is no caller that may omit it.
        target, output = self._cached(tmp_path)
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        assert spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                             target_file=str(target),
                                             exclusions_file=None)

    def test_unreadable_target_warns_instead_of_stamping(self, tmp_path, capsys):
        _target, output = self._cached(tmp_path)
        spoonmap._stamp_target_coverage(str(output), str(tmp_path / 'absent.txt'), None)
        assert not os.path.exists(str(output) + '.coverage')
        assert 'could not read' in capsys.readouterr().out

    def test_stamp_write_failure_warns_instead_of_raising(self, tmp_path, capsys):
        # The scan already succeeded; raising here would discard real results.
        target, output = self._cached(tmp_path)
        with patch('spoonmap._atomic_write', side_effect=OSError('ENOSPC')):
            spoonmap._stamp_target_coverage(str(output), str(target), None)
        assert 'could not record the target set' in capsys.readouterr().out

    def test_orphaned_stamp_without_its_output_is_harmless(self, tmp_path):
        target, output = self._cached(tmp_path)
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        output.unlink()
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase', target_file=str(target), exclusions_file=None)



class TestResumeTargetStampIntegration:
    """The two under-scans issue #46 describes, at the mass_scan() level."""

    def _completed_full_run(self, tmp_path, discovery_ips):
        """Run a Full scan against *discovery_ips*, leaving a stamped cache."""
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        targets = disc / 'resolved_targets.txt'
        targets.write_text('10.0.0.0/24\n')
        discovery_file = disc / 'live_hosts_discovery.txt'
        discovery_file.write_text(''.join(ip + '\n' for ip in discovery_ips))

        def fake_batch(batch, rate, output_file, target_file, *a, **kw):
            Path(output_file).write_text('<nmaprun/>')
            spoonmap._stamp_target_coverage(output_file, target_file, None)
            return {'22': {'10.0.0.1'}}

        with patch('spoonmap._run_masscan_batch', side_effect=fake_batch):
            mass_scan('Full', ['1-65535'], '88', '2000', str(targets), '',
                      discovery_file=str(discovery_file))
        return targets, discovery_file

    def test_disabling_host_discovery_forces_a_full_rescan(self, tmp_path, capsys):
        """Scenario A: the target widens to the whole range with no mtime change.

        Nothing rewrites resolved_targets.txt, so before the fingerprint the
        cached narrow sweep satisfied its gate and was reported as a completed
        full-range scan.
        """
        targets, _discovery = self._completed_full_run(tmp_path, ['10.0.0.1'])
        with patch('spoonmap._run_masscan_batch',
                   return_value={'22': {'10.0.0.1'}}) as mock_batch:
            mass_scan('Full', ['1-65535'], '88', '2000', str(targets), '',
                      resume=True, discovery_file=None)
        assert mock_batch.called, 'a widened target must re-scan, not resume'
        assert mock_batch.call_args[0][3] == str(targets)
        assert 'were not covered by the cached result' in capsys.readouterr().out

    def test_unchanged_discovery_still_resumes(self, tmp_path, capsys):
        """The load-bearing direction: an identical target set must still skip."""
        targets, discovery = self._completed_full_run(tmp_path, ['10.0.0.1'])
        with patch('spoonmap._run_masscan_batch') as mock_batch:
            mass_scan('Full', ['1-65535'], '88', '2000', str(targets), '',
                      resume=True, discovery_file=str(discovery))
        assert not mock_batch.called
        assert 'skipping completed Full port scan' in capsys.readouterr().out

    def test_a_grown_discovery_set_forces_a_full_rescan(self, tmp_path):
        """A host discovery found on the second run must not be left unscanned."""
        targets, discovery = self._completed_full_run(tmp_path, ['10.0.0.1'])
        discovery.write_text('10.0.0.1\n10.0.0.2\n')
        with patch('spoonmap._run_masscan_batch',
                   return_value={'22': {'10.0.0.1'}}) as mock_batch:
            mass_scan('Full', ['1-65535'], '88', '2000', str(targets), '',
                      resume=True, discovery_file=str(discovery))
        assert mock_batch.called

    def test_killed_masscan_leaves_no_stamp(self, tmp_path):
        """A stamp on an interrupted batch would assert coverage that never ran."""
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        targets = disc / 'resolved_targets.txt'
        targets.write_text('10.0.0.1\n')
        output_file = str(disc / 'masscan_results' / 'portFull.xml')
        with patch('spoonmap.subprocess.Popen', side_effect=KeyboardInterrupt), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                spoonmap._run_masscan_batch(['80'], '1000', output_file,
                                            str(targets), '', '')
        assert not os.path.exists(output_file + '.coverage')

    def test_failed_masscan_exit_leaves_no_stamp(self, tmp_path):
        """Same for a non-zero exit, which sys.exit()s before the stamp."""
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        targets = disc / 'resolved_targets.txt'
        targets.write_text('10.0.0.1\n')
        output_file = str(disc / 'masscan_results' / 'portFull.xml')
        proc = MagicMock()
        proc.wait.return_value = 0
        proc.returncode = 1
        proc.pid = 4242
        # Finite stderr: a bare MagicMock returns truthy bytes forever and hangs
        # the progress reader's join.
        proc.stderr = io.BytesIO(b'Error: permission denied')
        with patch('spoonmap.subprocess.Popen', return_value=proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(SystemExit):
                spoonmap._run_masscan_batch(['80'], '1000', output_file,
                                            str(targets), '', '')
        assert not os.path.exists(output_file + '.coverage')

    def test_successful_masscan_stamps_the_target_it_scanned(self, tmp_path):
        """The positive counterpart: a clean exit records its target set."""
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        targets = disc / 'resolved_targets.txt'
        targets.write_text('10.0.0.1\n')
        output_file = str(disc / 'masscan_results' / 'portFull.xml')
        proc = MagicMock()
        proc.wait.return_value = 0
        proc.returncode = 0
        proc.pid = 4243
        proc.stderr = io.BytesIO(b'')
        with patch('spoonmap.subprocess.Popen', return_value=proc), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            spoonmap._run_masscan_batch(['80'], '1000', output_file,
                                        str(targets), '', '')
        record = spoonmap._read_coverage_record(output_file)
        assert record['targets'] == spoonmap._target_entries(str(targets))
        assert record['exclusions'] == set()


class TestResumeTargetStampBatchPhase:
    """Issue #46 scenario B: the batch phase, reachable with no config change.

    live_hosts_combined.txt is rebuilt every run from a probe that is
    deliberately not resume-gated, so its content moves with packet loss. A host
    run 2's probe finds but run 1's missed must not end up in live_hosts/ and
    all_live_hosts.txt while the already-cached batches skip it.
    """

    def _run(self, tmp_path, probe_hits, resume):
        """Drive mass_scan()'s batch path with a controllable probe result."""
        spoonmap.output_path = str(tmp_path)
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True, exist_ok=True)
        targets = disc / 'resolved_targets.txt'
        if not targets.exists():
            # Written once: rewriting it would bump the mtime baseline and reject
            # every cache for that reason instead of the coverage check under test.
            targets.write_text('10.0.0.0/24\n')
        batch_calls = []

        def fake_batch(batch, rate, output_file, target_file, *a, **kw):
            Path(output_file).write_text('<nmaprun/>')
            spoonmap._stamp_target_coverage(output_file, target_file, None)
            if 'probe_fast' in output_file:
                return {'80': set(probe_hits)}
            if 'probe_slow' in output_file:
                return {}
            batch_calls.append(list(batch))
            return {}

        with patch('spoonmap._run_masscan_batch', side_effect=fake_batch):
            mass_scan('All', ['80', '443'], '53', '10000', str(targets), '',
                      batch_size=10, resume=resume)
        return batch_calls, targets

    def test_a_probe_that_finds_a_new_host_rescans_cached_batches(self, tmp_path, capsys):
        first, _ = self._run(tmp_path, {'10.0.0.7'}, resume=False)
        assert first == [['443']], 'setup: port 443 must reach a main batch'
        capsys.readouterr()

        second, _ = self._run(tmp_path, {'10.0.0.7', '10.0.0.9'}, resume=True)
        out = capsys.readouterr().out
        assert second == [['443']], (
            'the cached batch must be re-scanned now that 10.0.0.9 is a target'
        )
        assert 'were not covered by the cached result' in out
        assert '10.0.0.9' in out

    def test_an_unchanged_probe_still_skips_cached_batches(self, tmp_path, capsys):
        first, _ = self._run(tmp_path, {'10.0.0.7'}, resume=False)
        assert first == [['443']]
        capsys.readouterr()

        second, _ = self._run(tmp_path, {'10.0.0.7'}, resume=True)
        assert second == [], 'an unchanged target set must still resume'
        assert 'skipping completed batch' in capsys.readouterr().out

    def test_a_probe_that_finds_fewer_hosts_still_skips_cached_batches(self, tmp_path, capsys):
        """Exact equality here made --resume thrash on ordinary probe variance.

        The cache covered a superset of what this run would scan, so there is
        nothing left to do — re-scanning would discard a wider completed result
        for a narrower one.
        """
        first, _ = self._run(tmp_path, {'10.0.0.7', '10.0.0.9'}, resume=False)
        assert first == [['443']]
        capsys.readouterr()

        second, _ = self._run(tmp_path, {'10.0.0.7'}, resume=True)
        assert second == [], 'a narrower target set must not force a re-scan'
        assert 'skipping completed batch' in capsys.readouterr().out


class TestResumeTargetStampNmapDiscovery:
    """The two nmap discovery phases: stamp on success, reject on a wider target."""

    def _proc(self, returncode=0):
        proc = MagicMock()
        proc.wait.return_value = 0
        proc.returncode = returncode
        proc.pid = 999
        proc.stdout = io.StringIO('')
        proc.stderr = io.StringIO('')
        return proc

    def _udp_xml(self, ip='10.0.0.5'):
        return (
            '<?xml version="1.0"?><nmaprun><host>'
            f'<address addr="{ip}" addrtype="ipv4"/>'
            '<ports><port protocol="udp" portid="53">'
            '<state state="open"/></port></ports>'
            '</host></nmaprun>'
        )

    def test_udp_discovery_stamps_on_success_then_resumes(self, tmp_path):
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        (tmp_path / 'discovery' / 'live_hosts').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.5\n')
        xml = tmp_path / 'discovery' / 'masscan_results' / 'portU_53.xml'

        def fake_popen(cmd, **kwargs):
            Path(cmd[cmd.index('-oX') + 1]).write_text(self._udp_xml())
            return self._proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            spoonmap._nmap_udp_discovery('U:53', str(target), str(tmp_path), '', None)
        assert spoonmap._read_coverage_record(str(xml))['targets'] == {'10.0.0.5'}

        # Same target → resume; widened target → re-scan.
        with patch('spoonmap.subprocess.Popen') as mock_popen:
            spoonmap._nmap_udp_discovery('U:53', str(target), str(tmp_path), '',
                                         None, resume=True)
        assert not mock_popen.called

        # Widen the target but hold its mtime *behind* the cached XML, so the
        # mtime baseline still accepts the cache and the coverage check is the
        # only thing that can reject it.
        target.write_text('10.0.0.5\n10.0.0.6\n')
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            spoonmap._nmap_udp_discovery('U:53', str(target), str(tmp_path), '',
                                         None, resume=True)
        assert mock_popen.called, 'a target added since the cache must re-scan'

    def test_udp_discovery_does_not_stamp_after_a_failed_nmap(self, tmp_path):
        """A non-zero exit can still leave parseable partial XML.

        This function does not treat that as fatal, so without the returncode
        guard the stamp would claim full target coverage for a partial result.
        """
        (tmp_path / 'discovery' / 'masscan_results').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.5\n')
        xml = tmp_path / 'discovery' / 'masscan_results' / 'portU_53.xml'

        def fake_popen(cmd, **kwargs):
            Path(cmd[cmd.index('-oX') + 1]).write_text(self._udp_xml())
            return self._proc(returncode=1)

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            spoonmap._nmap_udp_discovery('U:53', str(target), str(tmp_path), '', None)
        assert xml.exists(), 'the partial result stays readable on disk'
        assert not Path(str(xml) + '.coverage').exists()

    def test_port_discovery_stamps_on_success_then_resumes(self, tmp_path):
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        (disc / 'live_hosts').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        xml = disc / 'masscan_results' / 'portDirect.xml'

        def fake_popen(cmd, **kwargs):
            Path(cmd[cmd.index('-oX') + 1]).write_text(
                '<?xml version="1.0"?><nmaprun><host>'
                '<address addr="10.0.0.1" addrtype="ipv4"/>'
                '<ports><port protocol="tcp" portid="80">'
                '<state state="open"/></port></ports>'
                '</host></nmaprun>'
            )
            return self._proc()

        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            spoonmap._nmap_port_discovery(['80'], str(target), '', None)
        assert spoonmap._read_coverage_record(str(xml))['targets'] == {'10.0.0.1'}

        with patch('spoonmap.subprocess.Popen') as mock_popen, \
             patch('spoonmap.restore_terminal_state'):
            spoonmap._nmap_port_discovery(['80'], str(target), '', None, resume=True)
        assert not mock_popen.called

        # Widen the target but hold its mtime behind the cached XML, so only the
        # coverage check can reject the cache (see the UDP counterpart).
        target.write_text('10.0.0.1\n10.0.0.2\n')
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))
        with patch('spoonmap.subprocess.Popen', side_effect=fake_popen) as mock_popen, \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            spoonmap._nmap_port_discovery(['80'], str(target), '', None, resume=True)
        assert mock_popen.called, 'a target added since the cache must re-scan'


class TestBannerAndNseTargetCoverage:
    """Issue #47: the per-port host list grows every run, so the banner and NSE
    resume gates must check what the cached XML actually covered."""

    def _setup(self, tmp_path, hosts='10.0.0.1\n'):
        spoonmap.output_path = str(tmp_path)
        os.makedirs(f'{tmp_path}/discovery/live_hosts', exist_ok=True)
        os.makedirs(f'{tmp_path}/nmap_results', exist_ok=True)
        os.makedirs(f'{tmp_path}/nse_results', exist_ok=True)
        live = Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt'
        live.write_text(hosts)
        return live

    def test_a_grown_host_list_rescans_the_banner_pass(self, tmp_path, capsys):
        """The scenario #46 left open: the probe re-runs every resume and unions
        a newly-found host into live_hosts/port80.txt, but the cached XML from
        the previous run still parses, so the host was never banner-scanned."""
        live = self._setup(tmp_path)
        cached = Path(tmp_path) / 'nmap_results' / 'port80.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, live)

        live.write_text('10.0.0.1\n10.0.0.9\n')   # probe found another host

        with patch('spoonmap.nmap_worker', side_effect=_fake_worker_drain) as mock_worker:
            nmap_scan('88', max_threads=2, script_scan=False)

        out = capsys.readouterr().out
        assert mock_worker.called, 'the new host must be banner-scanned'
        assert 'were not covered by the cached result' in out
        assert '10.0.0.9' in out
        assert 'already been scanned' not in out

    def test_an_unchanged_host_list_still_skips_the_port(self, tmp_path, capsys):
        live = self._setup(tmp_path)
        cached = Path(tmp_path) / 'nmap_results' / 'port80.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, live)

        with patch('spoonmap.nmap_worker') as mock_worker:
            nmap_scan('88', max_threads=2, script_scan=False)

        assert not mock_worker.called
        assert 'already been scanned' in capsys.readouterr().out

    def test_a_shrunk_host_list_still_skips_the_port(self, tmp_path):
        """Subset semantics: the cache covered more than this run would scan."""
        live = self._setup(tmp_path, '10.0.0.1\n10.0.0.9\n')
        cached = Path(tmp_path) / 'nmap_results' / 'port80.xml'
        cached.write_text('<nmaprun/>')
        _write_target_stamp(cached, live)

        live.write_text('10.0.0.1\n')

        with patch('spoonmap.nmap_worker') as mock_worker:
            nmap_scan('88', max_threads=2, script_scan=False)
        assert not mock_worker.called

    def test_nse_coverage_is_recorded_independently_of_the_banner_pass(self, tmp_path, capsys):
        """A complete banner pass says nothing about the NSE pass's coverage."""
        live = self._setup(tmp_path)
        banner = Path(tmp_path) / 'nmap_results' / 'port80.xml'
        banner.write_text('<nmaprun/>')
        nse = Path(tmp_path) / 'nse_results' / 'port80.xml'
        nse.write_text('<nmaprun/>')
        _write_target_stamp(nse, live)
        # Banner pass covered a host list from before 10.0.0.9 appeared; NSE
        # covered the current one.
        live.write_text('10.0.0.1\n10.0.0.9\n')
        _write_target_stamp(banner, live)
        live.write_text('10.0.0.1\n10.0.0.9\n')

        with patch('spoonmap.nmap_worker', side_effect=_fake_worker_drain) as mock_worker, \
             patch('spoonmap._get_scripts_for_port', return_value='ftp-anon'):
            nmap_scan('88', max_threads=2, script_scan=True)

        out = capsys.readouterr().out
        assert mock_worker.called, 'the NSE pass has not covered 10.0.0.9'
        assert 're-running port 80 NSE scan' in out


class TestNmapWorkerTargetCoverage:
    """nmap_worker() must record coverage per pass, and only on success."""

    def _run(self, tmp_path, returncode=0, script_scan=False, scripts='',
             ip_to_hostname=None, interrupt=False):
        spoonmap.output_path = str(tmp_path)
        for d in ('nmap_results', 'nse_results', 'discovery/live_hosts'):
            os.makedirs(f'{tmp_path}/{d}', exist_ok=True)
        live = Path(tmp_path) / 'discovery' / 'live_hosts' / 'port80.txt'
        live.write_text('10.0.0.1\n10.0.0.2\n')

        work_queue = Queue()
        work_queue.put('port80.txt')
        work_queue.put(None)
        interrupt_event = threading.Event()

        def popen_side_effect(*a, **k):
            proc = MagicMock()
            proc.poll.return_value = 0
            proc.wait.return_value = 0
            proc.returncode = returncode
            proc.stderr = io.StringIO('boom' if returncode else '')
            if interrupt:
                interrupt_event.set()
            return proc

        with patch('spoonmap._build_nmap_cmd', return_value=['nmap', 'fake']), \
             patch('spoonmap._get_scripts_for_port', return_value=scripts), \
             patch('spoonmap.create_hostname_target_file'), \
             patch('spoonmap.subprocess.Popen', side_effect=popen_side_effect):
            nmap_worker(work_queue, [0], 1, '88', threading.Lock(), interrupt_event,
                        ip_to_hostname, script_scan=script_scan)
        return live

    def test_successful_banner_pass_records_its_coverage(self, tmp_path):
        self._run(tmp_path)
        record = spoonmap._read_coverage_record(f'{tmp_path}/nmap_results/port80.xml')
        assert record['targets'] == {'10.0.0.1', '10.0.0.2'}

    def test_failed_banner_pass_records_nothing(self, tmp_path):
        # The failure path quarantines the XML; a coverage record left beside it
        # would be applied to whatever lands there next.
        self._run(tmp_path, returncode=1)
        assert not Path(f'{tmp_path}/nmap_results/port80.xml.coverage').exists()

    def test_successful_nse_pass_records_its_own_coverage(self, tmp_path):
        self._run(tmp_path, script_scan=True, scripts='ftp-anon')
        assert Path(f'{tmp_path}/nse_results/port80.xml.coverage').exists()
        assert Path(f'{tmp_path}/nmap_results/port80.xml.coverage').exists()

    def test_failed_nse_pass_records_nothing_for_that_pass(self, tmp_path):
        self._run(tmp_path, returncode=1, script_scan=True, scripts='ftp-anon')
        assert not Path(f'{tmp_path}/nse_results/port80.xml.coverage').exists()

    def test_hostname_variant_does_not_change_what_is_recorded(self, tmp_path):
        """The record keys on the IP list even when nmap got the hostname file,
        because that is what nmap_scan()'s gate compares against."""
        self._run(tmp_path, ip_to_hostname={'10.0.0.1': 'host1.internal'})
        record = spoonmap._read_coverage_record(f'{tmp_path}/nmap_results/port80.xml')
        assert record['targets'] == {'10.0.0.1', '10.0.0.2'}


class TestStaleCoverageRecordIsDiscarded:
    """A record that cannot be written truthfully must be removed, not left."""

    def test_unreadable_target_removes_an_earlier_record(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        output = tmp_path / 'out.xml'
        output.write_text('<nmaprun/>')
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        target.unlink()
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        assert not Path(str(output) + '.coverage').exists()

    def test_discarding_a_missing_record_is_not_an_error(self, tmp_path):
        spoonmap._discard_coverage_record(str(tmp_path / 'never-existed.xml'))


class TestExclusionsCoverage:
    """Issue #48: coverage is `targets - exclusions`, so narrowing the exclusions
    file widens the real scan with nothing else on disk changing."""

    def _cached(self, tmp_path, excl_text='192.168.1.1\n'):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        excl = tmp_path / 'exclusions.txt'
        excl.write_text(excl_text)
        output = tmp_path / 'out.xml'
        output.write_text('<nmaprun/>')
        spoonmap._stamp_target_coverage(str(output), str(target), str(excl))
        return target, excl, output

    def test_unchanged_exclusions_accept_the_cache(self, tmp_path):
        target, excl, output = self._cached(tmp_path)
        assert spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                             target_file=str(target), exclusions_file=str(excl))

    def test_narrowing_exclusions_rejects_the_cache(self, tmp_path, capsys):
        """The headline case: a host cleared for testing is removed from
        exclusions.txt, so it is now in scope and was never scanned."""
        target, excl, output = self._cached(tmp_path, '192.168.1.1\n10.0.0.9\n')
        excl.write_text('192.168.1.1\n')           # 10.0.0.9 cleared for testing
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target), exclusions_file=str(excl))
        out = capsys.readouterr().out
        assert '1 entry excluded when the cache was written is now in scope' in out
        assert '10.0.0.9' in out

    def test_emptying_the_exclusions_file_rejects_the_cache(self, tmp_path):
        target, excl, output = self._cached(tmp_path)
        excl.write_text('')
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target), exclusions_file=str(excl))

    def test_dropping_the_exclusions_file_entirely_rejects_the_cache(self, tmp_path):
        target, _excl, output = self._cached(tmp_path)
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target), exclusions_file=None)

    def test_widening_exclusions_still_accepts_the_cache(self, tmp_path, capsys):
        """Excluding more means a strictly smaller scan set, which the cache
        already covers — the opposite direction from the targets check."""
        target, excl, output = self._cached(tmp_path)
        excl.write_text('192.168.1.1\n192.168.1.2\n')
        assert spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                             target_file=str(target), exclusions_file=str(excl))
        assert 're-running' not in capsys.readouterr().out

    def test_adding_exclusions_where_there_were_none_still_accepts(self, tmp_path):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        output = tmp_path / 'out.xml'
        output.write_text('<nmaprun/>')
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        excl = tmp_path / 'exclusions.txt'
        excl.write_text('10.0.0.9\n')
        assert spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                            target_file=str(target), exclusions_file=str(excl))

    def test_unreadable_exclusions_file_rejects_the_cache(self, tmp_path, capsys):
        target, excl, output = self._cached(tmp_path)
        excl.unlink()
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target), exclusions_file=str(excl))
        out = capsys.readouterr().out
        assert 'exclusions file' in out
        assert 'could not be read' in out

    def test_a_missing_record_rejects_the_cache(self, tmp_path, capsys):
        """An output from before coverage tracking must not read as
        exclusion-free, which would over-accept every such cache."""
        target, excl, output = self._cached(tmp_path)
        Path(str(output) + '.coverage').unlink()
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target), exclusions_file=str(excl))
        assert 'does not record what it covered' in capsys.readouterr().out

    def test_a_malformed_record_rejects_the_cache(self, tmp_path, capsys):
        """Truncated or hand-edited JSON must read as "cannot say", not as
        "nothing excluded" — that is the state the empty-file encoding used to
        make ambiguous."""
        target, excl, output = self._cached(tmp_path)
        Path(str(output) + '.coverage').write_text('{"targets": [')
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target), exclusions_file=str(excl))
        assert 'does not record what it covered' in capsys.readouterr().out

    def test_an_empty_exclusion_set_is_recorded_explicitly(self, tmp_path):
        """"Nothing was excluded" is a recorded fact, not an absent one."""
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        output = tmp_path / 'out.xml'
        output.write_text('<nmaprun/>')
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        assert spoonmap._read_coverage_record(str(output)) == {
            'targets': {'10.0.0.0/24'}, 'exclusions': set()}
        assert spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                            target_file=str(target), exclusions_file=None)

    def test_unreadable_exclusions_file_records_nothing(self, tmp_path, capsys):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        output = tmp_path / 'out.xml'
        output.write_text('<nmaprun/>')
        spoonmap._stamp_target_coverage(str(output), str(target),
                                        str(tmp_path / 'absent-excl.txt'))
        assert not Path(str(output) + '.coverage').exists()
        assert 'could not read absent-excl.txt' in capsys.readouterr().out


class TestHostDiscoveryExclusionsCoverage:
    """_host_discovery()'s mtime baseline covers its targets but not its
    exclusions: its real target is the exclusion-subtracted filtered_target."""

    def _completed_run(self, tmp_path, excl_text):
        out = tmp_path / 'out'
        disc = out / 'discovery'
        disc.mkdir(parents=True)
        target = disc / 'resolved_targets.txt'
        target.write_text('10.0.0.0/24\n')
        excl = tmp_path / 'exclusions.txt'
        excl.write_text(excl_text)
        with patch('spoonmap._internal_host_discovery', return_value={'10.0.0.1'}), \
             patch('spoonmap._build_discovery_target_file',
                   return_value=(str(target), 256)):
            result = _host_discovery(str(target), str(out), '1000', str(excl),
                                     scan_type='Internal')
        assert result is not None
        # Hold the cache newer than the targets file so only the coverage check
        # can reject it.
        os.utime(str(target), (1000, 1000))
        os.utime(result, (2000, 2000))
        return target, excl, result

    def test_narrowed_exclusions_force_rediscovery(self, tmp_path, capsys):
        target, excl, _cache = self._completed_run(tmp_path, '10.0.0.9\n10.0.0.10\n')
        excl.write_text('10.0.0.9\n')
        with patch('spoonmap._internal_host_discovery',
                   return_value={'10.0.0.1'}) as m, \
             patch('spoonmap._build_discovery_target_file',
                   return_value=(str(target), 256)):
            _host_discovery(str(target), str(tmp_path / 'out'), '1000', str(excl),
                            scan_type='Internal', resume=True)
        assert m.called, '10.0.0.10 is newly in scope and was never discovered'
        assert 'now in scope' in capsys.readouterr().out

    def test_unchanged_exclusions_still_skip_discovery(self, tmp_path, capsys):
        target, excl, _cache = self._completed_run(tmp_path, '10.0.0.9\n')
        with patch('spoonmap._internal_host_discovery') as m, \
             patch('spoonmap._build_discovery_target_file',
                   return_value=(str(target), 256)):
            _host_discovery(str(target), str(tmp_path / 'out'), '1000', str(excl),
                            scan_type='Internal', resume=True)
        assert not m.called
        assert 'skipping host discovery' in capsys.readouterr().out


class TestExclusionsCoveragePerPhase:
    """Each phase must actually pass its exclusions file to its gate and its record.

    The gate-level tests above prove the comparison works; these prove it is
    wired in. Both directions are needed to pin the wiring: dropping exclusions
    at the *gate* makes it reject whenever any exclusion exists (caught by the
    "unchanged still resumes" cases), while dropping them at the *record* makes it
    accept a narrowed exclusions file (caught by the "narrowed re-scans" cases).
    These use the real _run_masscan_batch()/nmap paths with only subprocess.Popen
    faked, so the record the second pass reads is the one production wrote.
    """

    def _masscan_popen(self, seen_batches=None):
        def fake_popen(cmd, **kwargs):
            out_path = cmd[cmd.index('-oX') + 1]
            if seen_batches is not None and ('/batch_' in out_path or 'portFull' in out_path):
                seen_batches.append(out_path)
            Path(out_path).write_text('')   # found nothing; placeholder is stamped
            proc = MagicMock()
            proc.wait.return_value = 0
            proc.returncode = 0
            proc.pid = 12345
            proc.stderr = io.BytesIO(b'')
            return proc
        return fake_popen

    def _setup(self, tmp_path, excl_text):
        spoonmap.output_path = str(tmp_path)
        targets = tmp_path / 'discovery' / 'resolved_targets.txt'
        targets.parent.mkdir(parents=True)
        targets.write_text('10.0.0.0/24\n')
        os.utime(str(targets), (1000, 1000))
        excl = tmp_path / 'exclusions.txt'
        excl.write_text(excl_text)
        return targets, excl

    def _run_full(self, tmp_path, targets, excl, resume, seen):
        with patch('spoonmap.subprocess.Popen', side_effect=self._masscan_popen(seen)), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mass_scan('Full', ['1-65535'], '88', '2000', str(targets), str(excl),
                      resume=resume)

    def test_full_sweep_narrowed_exclusions_rescan(self, tmp_path, capsys):
        targets, excl = self._setup(tmp_path, '10.0.0.9\n10.0.0.10\n')
        self._run_full(tmp_path, targets, excl, False, None)
        capsys.readouterr()
        excl.write_text('10.0.0.9\n')
        seen = []
        self._run_full(tmp_path, targets, excl, True, seen)
        assert seen, '10.0.0.10 is newly in scope, so the sweep must re-run'
        assert 'now in scope' in capsys.readouterr().out

    def test_full_sweep_unchanged_exclusions_resume(self, tmp_path, capsys):
        targets, excl = self._setup(tmp_path, '10.0.0.9\n')
        self._run_full(tmp_path, targets, excl, False, None)
        capsys.readouterr()
        seen = []
        self._run_full(tmp_path, targets, excl, True, seen)
        assert seen == [], 'unchanged exclusions must still resume'
        assert 'skipping completed Full port scan' in capsys.readouterr().out

    def _run_batches(self, tmp_path, targets, excl, resume, seen):
        with patch('spoonmap.subprocess.Popen', side_effect=self._masscan_popen(seen)), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            mass_scan('All', ['80', '443'], '53', '10000', str(targets), str(excl),
                      batch_size=10, resume=resume)

    def test_port_batches_narrowed_exclusions_rescan(self, tmp_path, capsys):
        targets, excl = self._setup(tmp_path, '10.0.0.9\n10.0.0.10\n')
        first = []
        self._run_batches(tmp_path, targets, excl, False, first)
        assert first, 'setup: a main batch must have run'
        capsys.readouterr()
        excl.write_text('10.0.0.9\n')
        seen = []
        self._run_batches(tmp_path, targets, excl, True, seen)
        assert seen, 'the cached batch must be re-scanned'
        assert 'now in scope' in capsys.readouterr().out

    def test_port_batches_unchanged_exclusions_resume(self, tmp_path, capsys):
        targets, excl = self._setup(tmp_path, '10.0.0.9\n')
        first = []
        self._run_batches(tmp_path, targets, excl, False, first)
        assert first
        capsys.readouterr()
        seen = []
        self._run_batches(tmp_path, targets, excl, True, seen)
        assert seen == [], 'unchanged exclusions must still resume'
        assert 'skipping completed batch' in capsys.readouterr().out

    def _nmap_proc(self):
        proc = MagicMock()
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        proc.returncode = 0
        proc.stdout = io.StringIO('')
        proc.stderr = io.StringIO('')
        return proc

    def _nmap_dirs(self, tmp_path):
        disc = tmp_path / 'discovery'
        (disc / 'masscan_results').mkdir(parents=True)
        (disc / 'live_hosts').mkdir(parents=True)
        spoonmap.output_path = str(tmp_path)
        return disc

    def test_nmap_port_discovery_both_directions(self, tmp_path, capsys):
        disc = self._nmap_dirs(tmp_path)
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        excl = tmp_path / 'exclusions.txt'
        excl.write_text('10.0.0.9\n10.0.0.10\n')
        xml = disc / 'masscan_results' / 'portDirect.xml'

        def fake_popen(cmd, **kwargs):
            Path(cmd[cmd.index('-oX') + 1]).write_text('<nmaprun/>')
            return self._nmap_proc()

        def run(resume):
            with patch('spoonmap.subprocess.Popen', side_effect=fake_popen) as mp, \
                 patch('spoonmap.save_terminal_state', return_value=None), \
                 patch('spoonmap.restore_terminal_state'):
                _nmap_port_discovery(['80'], str(target), '', str(excl), resume=resume)
            return mp

        run(False)
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))
        capsys.readouterr()
        assert not run(True).called, 'unchanged exclusions must still resume'

        excl.write_text('10.0.0.9\n')
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))
        capsys.readouterr()
        assert run(True).called, 'a newly in-scope host must force a re-scan'
        assert 'now in scope' in capsys.readouterr().out

    def test_nmap_udp_discovery_both_directions(self, tmp_path, capsys):
        disc = self._nmap_dirs(tmp_path)
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.5\n')
        excl = tmp_path / 'exclusions.txt'
        excl.write_text('10.0.0.9\n10.0.0.10\n')
        xml = disc / 'masscan_results' / 'portU_53.xml'

        def fake_popen(cmd, **kwargs):
            Path(cmd[cmd.index('-oX') + 1]).write_text(
                '<?xml version="1.0"?><nmaprun><host>'
                '<address addr="10.0.0.5" addrtype="ipv4"/>'
                '<ports><port protocol="udp" portid="53">'
                '<state state="open"/></port></ports></host></nmaprun>'
            )
            return self._nmap_proc()

        def run(resume):
            with patch('spoonmap.subprocess.Popen', side_effect=fake_popen) as mp, \
                 patch('spoonmap.save_terminal_state', return_value=None), \
                 patch('spoonmap.restore_terminal_state'):
                _nmap_udp_discovery('U:53', str(target), str(tmp_path), '',
                                    str(excl), resume=resume)
            return mp

        run(False)
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))
        capsys.readouterr()
        assert not run(True).called, 'unchanged exclusions must still resume'

        excl.write_text('10.0.0.9\n')
        os.utime(str(target), (1000, 1000))
        os.utime(str(xml), (2000, 2000))
        capsys.readouterr()
        assert run(True).called, 'a newly in-scope host must force a re-scan'
        assert 'now in scope' in capsys.readouterr().out


class TestCoverageRecordIsSingleAndAtomic:
    """One record, one atomic write.

    As two sidecars written in sequence, a KeyboardInterrupt between them left a
    fresh target list beside a stale exclusion list, and the gate accepted that
    pair as an exclusion-free scan.
    """

    def _stamped(self, tmp_path, excl_text=None):
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.0/24\n')
        excl = None
        if excl_text is not None:
            excl = tmp_path / 'exclusions.txt'
            excl.write_text(excl_text)
        output = tmp_path / 'out.xml'
        output.write_text('<nmaprun/>')
        return target, excl, output

    def test_both_halves_live_in_one_file(self, tmp_path):
        target, excl, output = self._stamped(tmp_path, '10.0.0.9\n')
        spoonmap._stamp_target_coverage(str(output), str(target), str(excl))
        assert spoonmap._read_coverage_record(str(output)) == {
            'targets': {'10.0.0.0/24'}, 'exclusions': {'10.0.0.9'}}
        # No second sidecar to fall out of step with the first.
        assert sorted(p.name for p in tmp_path.iterdir()) == [
            'exclusions.txt', 'out.xml', 'out.xml.coverage', 'targets.txt']

    def test_interrupt_during_the_write_discards_the_record(self, tmp_path):
        """The demonstrated over-accept: run 1 exclusion-free, run 2 interrupted
        mid-write, run 3 accepting run 1's record as though run 2 had happened."""
        target, _e, output = self._stamped(tmp_path)
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        assert spoonmap._read_coverage_record(str(output))['exclusions'] == set()

        excl = tmp_path / 'exclusions.txt'
        excl.write_text('10.0.0.9\n')
        with patch('spoonmap._atomic_write', side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                spoonmap._stamp_target_coverage(str(output), str(target), str(excl))

        assert spoonmap._read_coverage_record(str(output)) is None
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target),
                                                 exclusions_file=str(excl))

    def test_a_wider_surviving_record_cannot_validate_a_narrower_output(self, tmp_path):
        """The hazard the discard exists for.

        A record kept from a wide run would accept a later narrow output, since
        the narrow target is a subset of it. Asserting on a *narrower* leftover
        record proves nothing: the targets check rejects that regardless.
        """
        target, _e, output = self._stamped(tmp_path)
        target.write_text('10.0.0.1\n10.0.0.2\n10.0.0.3\n')
        spoonmap._stamp_target_coverage(str(output), str(target), None)

        # A later, narrower run rewrites the output but cannot record it.
        target.write_text('10.0.0.1\n')
        with patch('spoonmap._atomic_write', side_effect=OSError('ENOSPC')):
            spoonmap._stamp_target_coverage(str(output), str(target), None)

        assert spoonmap._read_coverage_record(str(output)) is None, (
            'the wider record must not survive to validate this output'
        )
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target),
                                                 exclusions_file=None)

    def test_masscan_clears_the_record_before_it_scans(self, tmp_path):
        """A run killed outright never reaches the stamp, so the record has to be
        dropped up front — otherwise the previous run's record describes output
        that no longer exists."""
        targets = tmp_path / 'targets.txt'
        targets.write_text('10.0.0.1\n')
        output_xml = tmp_path / 'out.xml'
        output_xml.write_text('<nmaprun/>')
        spoonmap._stamp_target_coverage(str(output_xml), str(targets), None)
        assert Path(str(output_xml) + '.coverage').exists()

        # SIGKILL stand-in: the process dies inside Popen, so no stamp runs.
        with patch('spoonmap.subprocess.Popen', side_effect=KeyboardInterrupt), \
             patch('spoonmap.save_terminal_state', return_value=None), \
             patch('spoonmap.restore_terminal_state'):
            with pytest.raises(KeyboardInterrupt):
                spoonmap._run_masscan_batch(['445'], '1000', str(output_xml),
                                            str(targets), None, None)
        assert not Path(str(output_xml) + '.coverage').exists()

    def test_exclusion_respelling_errs_toward_rescanning(self, tmp_path):
        """Line-level, not address-level: an equivalent respelling re-scans.

        Safe direction by construction — it can cost a redundant scan but never
        skip one.
        """
        target, excl, output = self._stamped(tmp_path, '10.0.0.9\n')
        spoonmap._stamp_target_coverage(str(output), str(target), str(excl))
        excl.write_text('10.0.0.9/32\n')      # same address, different line
        assert not spoonmap._resume_cache_usable(str(output), 0, 'phase',
                                                 target_file=str(target),
                                                 exclusions_file=str(excl))

    def test_record_is_invisible_to_result_aggregation(self, tmp_path):
        result_dir = tmp_path / 'masscan_results'
        result_dir.mkdir()
        xml = result_dir / 'portFull.xml'
        xml.write_text(
            '<?xml version="1.0"?><nmaprun><host>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        excl = tmp_path / 'exclusions.txt'
        excl.write_text('10.0.0.9\n')
        spoonmap._stamp_target_coverage(str(xml), str(target), str(excl))
        assert (result_dir / 'portFull.xml.coverage').exists()
        hosts_json, xml_hosts = spoonmap._aggregate_result_dir(str(result_dir) + '/', {})
        assert [h['ip'] for h in hosts_json] == ['10.0.0.1']
        assert set(xml_hosts) == {'10.0.0.1'}

    def test_cleanup_removes_the_record(self, tmp_path):
        disc = tmp_path / 'discovery' / 'masscan_results'
        disc.mkdir(parents=True)
        target = tmp_path / 'targets.txt'
        target.write_text('10.0.0.1\n')
        output = disc / 'portFull.xml'
        output.write_text('<nmaprun/>')
        spoonmap._stamp_target_coverage(str(output), str(target), None)
        assert (disc / 'portFull.xml.coverage').exists()
        spoonmap._delete_previous_results(str(tmp_path))
        assert not (tmp_path / 'discovery').exists()
