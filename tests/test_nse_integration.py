"""Integration tests for custom NSE scripts.

Each test:
1. Starts a plain-TCP stub server that mimics the target protocol response
2. Runs nmap with the custom NSE against 127.0.0.1 on the real port
3. Asserts the script output (positive) or absence of output (negative)

Requires nmap to be installed and tests to run as root (for nmap raw socket access).
Skip the module if nmap is not found or if the required port is already in use.

Run exclusively:
    uv run pytest tests/test_nse_integration.py -v
"""

import os
import shutil
import socket
import socketserver
import subprocess
import threading
import time

import pytest

# ── helpers ───────────────────────────────────────────────────────────────────

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NSE_DIR = os.path.join(_ROOT, 'nse')

pytestmark = pytest.mark.skipif(
    shutil.which('nmap') is None,
    reason='nmap not installed',
)


def _port_is_free(port: int) -> bool:
    """Return True if nobody is listening on 127.0.0.1:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('127.0.0.1', port))
            return True
        except OSError:
            return False


class _ReuseAddrServer(socketserver.TCPServer):
    allow_reuse_address = True


class _StubServer:
    """Context manager: plain-TCP server that sends a fixed response to any connection.

    The server runs in a daemon thread so it does not block the test.  It
    handles connections sequentially, which is sufficient because nmap makes
    at most two connections per script invocation (SSL attempt + TCP fallback).
    """

    def __init__(self, port: int, response: bytes):
        self._port = port
        self._response = response
        self._server: _ReuseAddrServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> '_StubServer':
        response = self._response

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.recv(4096)       # drain probe (may be TLS or HTTP)
                    self.request.sendall(response)
                except Exception:
                    pass

        self._server = _ReuseAddrServer(('127.0.0.1', self._port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        time.sleep(0.05)  # give the server a moment to bind
        return self

    def __exit__(self, *_):
        if self._server:
            self._server.shutdown()
            self._server.server_close()


def _run_nmap(port: int, script_path: str) -> str:
    """Run nmap with a single NSE script against 127.0.0.1; return combined output."""
    cmd = [
        'nmap', '-sT', '-p', str(port),
        '--script', script_path,
        '--script-timeout', '10s',
        '-T4',
        '127.0.0.1',
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout + result.stderr


def _udp_port_is_free(port: int) -> bool:
    """Return True if nobody is bound to 127.0.0.1:port/udp."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('127.0.0.1', port))
            return True
        except OSError:
            return False


class _UdpStubServer:
    """Context manager: UDP server that sends a fixed response to any datagram received.

    Runs in a daemon thread so it does not block the test.
    """

    def __init__(self, port: int, response: bytes):
        self._port = port
        self._response = response
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def __enter__(self) -> '_UdpStubServer':
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', self._port))
        self._sock.settimeout(0.2)

        def _serve():
            while not self._stop.is_set():
                try:
                    _, addr = self._sock.recvfrom(4096)
                except (socket.timeout, OSError):
                    continue
                try:
                    self._sock.sendto(self._response, addr)
                except OSError:
                    pass

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()
        time.sleep(0.05)  # give the server a moment to bind
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        if self._sock:
            self._sock.close()


def _run_nmap_udp(port: int, script_path: str) -> str:
    """Run nmap UDP scan with a single NSE script against 127.0.0.1; return combined output."""
    cmd = [
        'nmap', '-sU', '-p', str(port),
        '--script', script_path,
        '--script-timeout', '10s',
        '-T4',
        '127.0.0.1',
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout + result.stderr


# ── nodejs-inspector ──────────────────────────────────────────────────────────

_NODEJS_PORT   = 9229
_NODEJS_SCRIPT = os.path.join(_NSE_DIR, 'nodejs-inspector.nse')

_NODEJS_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"Browser": "node.js/v18.17.0", "V8-Version": "10.7.193.23"}'
)
_NODEJS_INVALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: text/html\r\n\r\n'
    b'<html>Not a Node.js service</html>'
)


@pytest.mark.skipif(not _port_is_free(_NODEJS_PORT),
                    reason=f'port {_NODEJS_PORT} already in use')
class TestNodejsInspectorNse:

    def test_detects_nodejs_inspector(self):
        """Stub returns valid /json/version → script reports version string."""
        with _StubServer(_NODEJS_PORT, _NODEJS_VALID):
            output = _run_nmap(_NODEJS_PORT, _NODEJS_SCRIPT)
        assert 'nodejs-inspector' in output
        assert 'Node.js Inspector accessible' in output
        assert 'node.js/v18.17.0' in output

    def test_no_output_for_non_nodejs_service(self):
        """Stub returns HTML → script produces no output (fingerprint mismatch)."""
        with _StubServer(_NODEJS_PORT, _NODEJS_INVALID):
            output = _run_nmap(_NODEJS_PORT, _NODEJS_SCRIPT)
        assert 'Node.js Inspector accessible' not in output


# ── delve-debugger ────────────────────────────────────────────────────────────

_DELVE_PORT   = 2345
_DELVE_SCRIPT = os.path.join(_NSE_DIR, 'delve-debugger.nse')

_DELVE_VALID = (
    b'{"seq":1,"type":"response","command":"initialize",'
    b'"success":true,"body":{"supportsConfigurationDoneRequest":true}}\n'
)
_DELVE_INVALID = b'HELLO stranger\n'


@pytest.mark.skipif(not _port_is_free(_DELVE_PORT),
                    reason=f'port {_DELVE_PORT} already in use')
class TestDelveDebuggerNse:

    def test_detects_delve_debugger(self):
        """Stub returns DAP response → script reports Delve responding."""
        with _StubServer(_DELVE_PORT, _DELVE_VALID):
            output = _run_nmap(_DELVE_PORT, _DELVE_SCRIPT)
        assert 'delve-debugger' in output
        assert 'Delve debugger responding' in output

    def test_no_output_for_non_delve_service(self):
        """Stub returns non-DAP data → script produces no output."""
        with _StubServer(_DELVE_PORT, _DELVE_INVALID):
            output = _run_nmap(_DELVE_PORT, _DELVE_SCRIPT)
        assert 'Delve debugger responding' not in output


# ── kubelet-anon-check ────────────────────────────────────────────────────────

_KUBELET_PORT   = 10250
_KUBELET_SCRIPT = os.path.join(_NSE_DIR, 'kubelet-anon-check.nse')

_KUBELET_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"items":[]}'
)
_KUBELET_UNAUTH = (
    b'HTTP/1.0 401 Unauthorized\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"message":"Unauthorized"}'
)


@pytest.mark.skipif(not _port_is_free(_KUBELET_PORT),
                    reason=f'port {_KUBELET_PORT} already in use')
class TestKubeletAnonCheckNse:

    def test_detects_anonymous_access(self):
        """Stub returns HTTP 200 → script reports anonymous access enabled.

        The script tries TLS first; the stub is plain TCP so TLS handshake
        fails, the script creates a new socket and falls back to plain TCP,
        which succeeds.  The stub handles both connections sequentially.
        """
        with _StubServer(_KUBELET_PORT, _KUBELET_VALID):
            output = _run_nmap(_KUBELET_PORT, _KUBELET_SCRIPT)
        assert 'kubelet-anon-check' in output
        assert 'Anonymous access enabled' in output

    def test_no_output_when_auth_required(self):
        """Stub returns HTTP 401 → script produces no output."""
        with _StubServer(_KUBELET_PORT, _KUBELET_UNAUTH):
            output = _run_nmap(_KUBELET_PORT, _KUBELET_SCRIPT)
        assert 'Anonymous access enabled' not in output


# ── cups-browsed-rce ──────────────────────────────────────────────────────────

_CUPS_PORT   = 631
_CUPS_SCRIPT = os.path.join(_NSE_DIR, 'cups-browsed-rce.nse')

# Vulnerable: CUPS 2.0.1 (in the <= 2.0.1 range)
_CUPS_VULN = (
    b'HTTP/1.0 200 OK\r\n'
    b'Server: CUPS/2.0.1 IPP/2.1\r\n'
    b'Content-Type: text/html\r\n\r\n'
    b'<html></html>'
)
# Patched: CUPS 2.1.0 (first version outside the vulnerable range)
_CUPS_PATCHED = (
    b'HTTP/1.0 200 OK\r\n'
    b'Server: CUPS/2.1.0 IPP/2.1\r\n'
    b'Content-Type: text/html\r\n\r\n'
    b'<html></html>'
)
# Non-CUPS service (no Server header containing CUPS)
_CUPS_UNRELATED = (
    b'HTTP/1.0 200 OK\r\n'
    b'Server: Apache/2.4.51\r\n'
    b'Content-Type: text/html\r\n\r\n'
    b'<html></html>'
)


def _cups_daemon_reachable() -> bool:
    """Return True if a real CUPS daemon is listening on 127.0.0.1:631."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect(('127.0.0.1', _CUPS_PORT))
            return True
        except OSError:
            return False


@pytest.mark.skipif(not _cups_daemon_reachable(),
                    reason='no real CUPS daemon on 127.0.0.1:631')
class TestCupsBrowsedRceNseLive:
    """Run the script against the real local cupsd (port 631 is occupied).

    This exercises the full nmap → NSE → HTTP → version-parse → verdict path
    against a genuine CUPS installation. The daemon version may vary; these
    tests assert shape and presence, not a specific verdict.
    """

    def test_script_fires_and_reports_version(self):
        """Script runs against real cupsd and reports a cups_version field."""
        output = _run_nmap(_CUPS_PORT, _CUPS_SCRIPT)
        assert 'cups-browsed-rce' in output
        assert 'cups_version' in output

    def test_verdict_present(self):
        """Script always emits a verdict field when CUPS is detected."""
        output = _run_nmap(_CUPS_PORT, _CUPS_SCRIPT)
        assert 'verdict' in output

    def test_modern_cups_not_flagged_vulnerable(self):
        """CUPS 2.4+ (installed here) must not be flagged as LIKELY VULNERABLE."""
        output = _run_nmap(_CUPS_PORT, _CUPS_SCRIPT)
        # Only assert LIKELY VULNERABLE is absent; NOT VULNERABLE text may vary
        # depending on whether nmap also finds UDP 631 open.
        assert 'LIKELY VULNERABLE' not in output


@pytest.mark.skipif(not _port_is_free(_CUPS_PORT),
                    reason=f'port {_CUPS_PORT} already in use — stub tests require a free port')
class TestCupsBrowsedRceNseStub:
    """Use a TCP stub server to exercise specific version strings and edge cases."""

    def test_flags_vulnerable_version(self):
        """Stub returns CUPS 2.0.1 banner → script reports LIKELY VULNERABLE."""
        with _StubServer(_CUPS_PORT, _CUPS_VULN):
            output = _run_nmap(_CUPS_PORT, _CUPS_SCRIPT)
        assert 'cups-browsed-rce' in output
        assert 'LIKELY VULNERABLE' in output
        assert '2.0.1' in output

    def test_not_vulnerable_for_patched_version(self):
        """Stub returns CUPS 2.1.0 banner → script reports NOT VULNERABLE."""
        with _StubServer(_CUPS_PORT, _CUPS_PATCHED):
            output = _run_nmap(_CUPS_PORT, _CUPS_SCRIPT)
        assert 'LIKELY VULNERABLE' not in output
        assert 'NOT VULNERABLE' in output

    def test_no_output_for_non_cups_service(self):
        """Stub returns a non-CUPS banner → script produces no output."""
        with _StubServer(_CUPS_PORT, _CUPS_UNRELATED):
            output = _run_nmap(_CUPS_PORT, _CUPS_SCRIPT)
        assert 'cups-browsed-rce' not in output


# ── ollama-detect ─────────────────────────────────────────────────────────────

_OLLAMA_PORT   = 11434
_OLLAMA_SCRIPT = os.path.join(_NSE_DIR, 'ollama-detect.nse')

_OLLAMA_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"models":[{"name":"llama2","size":3825819519},{"name":"mistral","size":4109854208}]}'
)
_OLLAMA_INVALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: text/html\r\n\r\n'
    b'<html><body>Welcome</body></html>'
)


@pytest.mark.skipif(not _port_is_free(_OLLAMA_PORT),
                    reason=f'port {_OLLAMA_PORT} already in use — stub tests require a free port')
class TestOllamaDetectNse:
    def test_detects_ollama_api(self):
        """Stub returns valid /api/tags body → script reports unauthenticated access."""
        with _StubServer(_OLLAMA_PORT, _OLLAMA_VALID):
            output = _run_nmap(_OLLAMA_PORT, _OLLAMA_SCRIPT)
        assert 'Ollama API accessible' in output

    def test_no_output_for_non_ollama_service(self):
        """Stub returns plain HTML → script produces no output."""
        with _StubServer(_OLLAMA_PORT, _OLLAMA_INVALID):
            output = _run_nmap(_OLLAMA_PORT, _OLLAMA_SCRIPT)
        assert 'ollama-detect' not in output


# ── openai-api-detect ─────────────────────────────────────────────────────────

_OPENAI_PORT   = 1234
_OPENAI_SCRIPT = os.path.join(_NSE_DIR, 'openai-api-detect.nse')

_OPENAI_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"object":"list","data":[{"id":"Mistral-7B","object":"model"}]}'
)
_OPENAI_INVALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"status":"ok"}'
)


@pytest.mark.skipif(not _port_is_free(_OPENAI_PORT),
                    reason=f'port {_OPENAI_PORT} already in use — stub tests require a free port')
class TestOpenaiApiDetectNse:
    def test_detects_openai_compatible_api(self):
        """Stub returns valid /v1/models body → script reports unauthenticated access."""
        with _StubServer(_OPENAI_PORT, _OPENAI_VALID):
            output = _run_nmap(_OPENAI_PORT, _OPENAI_SCRIPT)
        assert 'OpenAI-compatible LLM API accessible' in output

    def test_no_output_for_generic_json_service(self):
        """Stub returns generic JSON without the three-string fingerprint → no output."""
        with _StubServer(_OPENAI_PORT, _OPENAI_INVALID):
            output = _run_nmap(_OPENAI_PORT, _OPENAI_SCRIPT)
        assert 'openai-api-detect' not in output


# ── gradio-detect ─────────────────────────────────────────────────────────────

_GRADIO_PORT   = 7860
_GRADIO_SCRIPT = os.path.join(_NSE_DIR, 'gradio-detect.nse')

_GRADIO_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"version":"3.50.2","gradio_version":"3.50.2"}'
)
_GRADIO_INVALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"version":"1.0","app":"flask"}'
)


@pytest.mark.skipif(not _port_is_free(_GRADIO_PORT),
                    reason=f'port {_GRADIO_PORT} already in use — stub tests require a free port')
class TestGradioDetectNse:
    def test_detects_gradio_ui(self):
        """Stub returns valid /info body with version+gradio → script reports access."""
        with _StubServer(_GRADIO_PORT, _GRADIO_VALID):
            output = _run_nmap(_GRADIO_PORT, _GRADIO_SCRIPT)
        assert 'Gradio web UI accessible' in output

    def test_no_output_for_non_gradio_service(self):
        """Stub returns JSON with version but no 'gradio' key → no output."""
        with _StubServer(_GRADIO_PORT, _GRADIO_INVALID):
            output = _run_nmap(_GRADIO_PORT, _GRADIO_SCRIPT)
        assert 'gradio-detect' not in output


# ── koboldcpp-detect ──────────────────────────────────────────────────────────

_KOBOLD_PORT   = 5001
_KOBOLD_SCRIPT = os.path.join(_NSE_DIR, 'koboldcpp-detect.nse')

_KOBOLD_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"result":"llama-2-7b-chat.Q4_K_M.gguf"}'
)
_KOBOLD_INVALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: text/html\r\n\r\n'
    b'<html><body>Service</body></html>'
)


@pytest.mark.skipif(not _port_is_free(_KOBOLD_PORT),
                    reason=f'port {_KOBOLD_PORT} already in use — stub tests require a free port')
class TestKoboldcppDetectNse:
    def test_detects_koboldcpp_api(self):
        """Stub returns valid /api/v1/model body → script reports unauthenticated access."""
        with _StubServer(_KOBOLD_PORT, _KOBOLD_VALID):
            output = _run_nmap(_KOBOLD_PORT, _KOBOLD_SCRIPT)
        assert 'KoboldCpp API accessible' in output

    def test_no_output_for_non_kobold_service(self):
        """Stub returns plain HTML → script produces no output."""
        with _StubServer(_KOBOLD_PORT, _KOBOLD_INVALID):
            output = _run_nmap(_KOBOLD_PORT, _KOBOLD_SCRIPT)
        assert 'koboldcpp-detect' not in output


# ── wsus-detect ───────────────────────────────────────────────────────────────

_WSUS_PORT   = 8530
_WSUS_SCRIPT = os.path.join(_NSE_DIR, 'wsus-detect.nse')

# WSUS ASMX help page listing WSUS-specific SOAP methods.
_WSUS_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: text/html; charset=utf-8\r\n\r\n'
    b'<html><head><title>ClientWebService</title></head><body>'
    b'<p>The following operations are supported: SyncUpdates, GetConfig, '
    b'GetCookie, GetExtendedUpdateInfo, RegisterComputer.</p>'
    b'<p>Windows Server Update Services</p></body></html>'
)
_WSUS_INVALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: text/html\r\n\r\n'
    b'<html><body>Just a web server</body></html>'
)


@pytest.mark.skipif(not _port_is_free(_WSUS_PORT),
                    reason=f'port {_WSUS_PORT} already in use — stub tests require a free port')
class TestWsusDetectNse:
    def test_detects_wsus(self):
        """Stub returns a WSUS ASMX help page → script reports WSUS detected."""
        with _StubServer(_WSUS_PORT, _WSUS_VALID):
            output = _run_nmap(_WSUS_PORT, _WSUS_SCRIPT)
        assert 'wsus-detect' in output
        assert 'Microsoft WSUS detected' in output

    def test_no_output_for_non_wsus_service(self):
        """Stub returns generic HTML (no WSUS markers) → no detection."""
        with _StubServer(_WSUS_PORT, _WSUS_INVALID):
            output = _run_nmap(_WSUS_PORT, _WSUS_SCRIPT)
        assert 'Microsoft WSUS detected' not in output


# ── openvpn-detect ────────────────────────────────────────────────────────────

_OPENVPN_PORT   = 1194
_OPENVPN_SCRIPT = os.path.join(_NSE_DIR, 'openvpn-detect.nse')

# P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8, key_id 0 -> first byte 0x40):
# 1-byte opcode + 8-byte session id + 1-byte ack-array length (0) + 4-byte packet id.
_OPENVPN_SERVER_HARD_RESET_V2 = b'\x40' + b'\x22' * 8 + b'\x00' + b'\x00\x00\x00\x00'
# Older P_CONTROL_HARD_RESET_SERVER_V1 (opcode 2 -> first byte 0x10).
_OPENVPN_SERVER_HARD_RESET_V1 = b'\x10' + b'\x22' * 8 + b'\x00' + b'\x00\x00\x00\x00'
# Not a hard-reset opcode -> must not be confirmed as OpenVPN.
_OPENVPN_UNRELATED = b'\x00' * 14


def _tcp_framed(payload: bytes) -> bytes:
    """Prefix a payload with OpenVPN-over-TCP's 2-byte big-endian length header."""
    length = len(payload)
    return bytes([(length >> 8) & 0xFF, length & 0xFF]) + payload


@pytest.mark.skipif(not _udp_port_is_free(_OPENVPN_PORT),
                    reason=f'udp port {_OPENVPN_PORT} already in use — stub tests require a free port')
class TestOpenvpnDetectNseUdp:
    def test_detects_openvpn_server_v2(self):
        """Stub replies with a P_CONTROL_HARD_RESET_SERVER_V2 -> script confirms OpenVPN over udp."""
        with _UdpStubServer(_OPENVPN_PORT, _OPENVPN_SERVER_HARD_RESET_V2):
            output = _run_nmap_udp(_OPENVPN_PORT, _OPENVPN_SCRIPT)
        assert 'openvpn-detect' in output
        assert 'OpenVPN server confirmed' in output
        assert 'udp' in output

    def test_no_output_for_non_openvpn_udp_service(self):
        """Stub replies with a non-hard-reset opcode -> script produces no output."""
        with _UdpStubServer(_OPENVPN_PORT, _OPENVPN_UNRELATED):
            output = _run_nmap_udp(_OPENVPN_PORT, _OPENVPN_SCRIPT)
        assert 'OpenVPN server confirmed' not in output


@pytest.mark.skipif(not _port_is_free(_OPENVPN_PORT),
                    reason=f'port {_OPENVPN_PORT} already in use — stub tests require a free port')
class TestOpenvpnDetectNseTcp:
    def test_detects_openvpn_server_v1(self):
        """Stub replies with a length-prefixed P_CONTROL_HARD_RESET_SERVER_V1 -> script confirms OpenVPN over tcp."""
        with _StubServer(_OPENVPN_PORT, _tcp_framed(_OPENVPN_SERVER_HARD_RESET_V1)):
            output = _run_nmap(_OPENVPN_PORT, _OPENVPN_SCRIPT)
        assert 'openvpn-detect' in output
        assert 'OpenVPN server confirmed' in output
        assert 'tcp' in output

    def test_no_output_for_non_openvpn_tcp_service(self):
        """Stub replies with a non-hard-reset opcode -> script produces no output."""
        with _StubServer(_OPENVPN_PORT, _tcp_framed(_OPENVPN_UNRELATED)):
            output = _run_nmap(_OPENVPN_PORT, _OPENVPN_SCRIPT)
        assert 'OpenVPN server confirmed' not in output
