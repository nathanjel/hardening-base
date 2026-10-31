"""hb-probe: port lists, and a scan of this machine's loopback."""
import contextlib
import io
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool  # noqa: E402

probe = load_tool("probe")


class ProbeTest(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(probe.parse_ports("22,80-82, 443"), [22, 80, 81, 82, 443])
        for bad in ("0", "70000", "90-80"):
            with self.assertRaises(Exception):
                probe.parse_ports(bad)

    def test_scan_finds_a_listener_and_flags_the_unexpected(self):
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen()
            port = srv.getsockname()[1]
            closed = port + 1 if port < 65535 else port - 1
            self.assertEqual(probe.tcp_state("127.0.0.1", port, 1), "open")
            self.assertEqual(probe.tcp_state("127.0.0.1", closed, 1), "closed")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = probe.main(["hb-probe", "scan", "127.0.0.1", "--ports", f"{port},{closed}",
                                 "--expect", str(closed), "--timeout", "0.3"])
        self.assertEqual(rc, 1)
        self.assertIn(f"NOT EXPECTED open: {port}", out.getvalue())
        self.assertIn(f"expected but closed: {closed}", out.getvalue())


if __name__ == "__main__":
    unittest.main()
