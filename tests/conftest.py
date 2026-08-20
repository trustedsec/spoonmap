"""Shared pytest configuration for the SpooNMAP test suite.

Its only job is to make the NSE integration tests deterministic.
``tests/test_nse_integration.py`` binds real local ports and shells out to real
nmap, and it used to gate each class with

    @pytest.mark.skipif(not _port_is_free(PORT), reason=...)

which is evaluated at **import** time — once, during collection, before a single
test has run.  Anything that grabbed the port between collection and the test
(another process starting, an earlier test's socket, a service coming up) turned
an environment problem into a failure: the stub server could not bind, or nmap
found a foreign service on the port and the script's output did not match.  One
run during this project produced six such failures, all clean on an immediate
re-run.  A non-deterministic exit gate is corrosive when the gate is the only
quality signal the project has.

The check now happens in ``pytest_runtest_setup``, i.e. immediately before each
test runs, and a class declares what it needs with a plain attribute:

    class TestFooNse:
        required_tcp_port = 9229

A hook rather than an autouse fixture, so no fixture is introduced into a suite
that deliberately has none, and so the check costs nothing for the ~880 unit
tests that declare no port.

This narrows *when* a test runs; it never changes *what* a test asserts.  A
genuinely broken NSE script still fails, because a script assertion is only ever
skipped when the port could not be claimed at all — in which case the script was
never exercised.
"""

import socket

import pytest

_KINDS = (
    ('required_tcp_port', 'tcp', socket.SOCK_STREAM),
    ('required_udp_port', 'udp', socket.SOCK_DGRAM),
)


def port_is_bindable(port, sock_type=socket.SOCK_STREAM):
    """Return True if 127.0.0.1:*port* can be bound right now.

    Binds and immediately closes rather than connecting: a connect() probe
    cannot distinguish "free" from "listening but not accepting", and on the
    stub servers' own ports it would consume one of the handler slots.
    """
    with socket.socket(socket.AF_INET, sock_type) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(('127.0.0.1', port))
        except OSError:
            return False
    return True


def pytest_runtest_setup(item):
    """Skip a port-dependent test when its port is occupied at run time."""
    cls = getattr(item, 'cls', None)
    if cls is None:
        return
    for attr, label, sock_type in _KINDS:
        port = getattr(cls, attr, None)
        if port is None:
            continue
        if not port_is_bindable(port, sock_type):
            # pytest.skip(), not a skip marker: the condition is only knowable
            # at run time, which is the entire point.
            pytest.skip(f'{label} port {port} on 127.0.0.1 is in use — the stub '
                        'server cannot claim it, so this is an environment '
                        'conflict, not an NSE regression')
