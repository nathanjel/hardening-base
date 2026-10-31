"""hbkit.wg: checking [wg], the wg-quick file, and what a PC pastes."""
import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import tools  # noqa: E402,F401  (puts lib/ on the path)
from hbkit import wg  # noqa: E402


def key(n):
    return base64.b64encode(bytes([n]) * 32).decode()


def cfg(**over):
    c = {"interface": "wg0", "address": "10.77.0.1/24", "port": 51820,
         "endpoint": "vpn.example.com", "peers": [f"desk 10.77.0.2 {key(1)}", f"laptop 10.77.0.3 {key(2)}"]}
    c.update(over)
    return c


class ParseTest(unittest.TestCase):
    def test_good_config(self):
        iface, peers = wg.parse(cfg())
        self.assertEqual(str(iface), "10.77.0.1/24")
        self.assertEqual([(p.name, str(p.ip), p.allowed) for p in peers],
                         [("desk", "10.77.0.2", "10.77.0.2/32"), ("laptop", "10.77.0.3", "10.77.0.3/32")])

    def test_every_problem_is_named(self):
        bad = cfg(peers=[
            f"Desk 10.77.0.2 {key(1)}",          # capital letter
            f"far 10.78.0.2 {key(2)}",           # outside the network
            "short 10.77.0.4 abc",               # not a key
            f"twin 10.77.0.2 {key(3)}",          # address used twice
            f"server 10.77.0.1 {key(4)}",        # the server's own address
            "two fields",
        ])
        with self.assertRaises(ValueError) as ctx:
            wg.parse(bad)
        msg = str(ctx.exception)
        for part in ("'Desk'", "far: 10.78.0.2", "short: the public key", "twin: address used twice",
                     "server: address used twice", "'two fields'"):
            self.assertIn(part, msg)

    def test_address_needs_a_prefix(self):
        with self.assertRaises(ValueError):
            wg.parse(cfg(address="10.77.0.1"))
        with self.assertRaises(ValueError):
            wg.parse(cfg(address="10.77.0.1/31", peers=[]))

    def test_key_check(self):
        self.assertTrue(wg.valid_key(key(9)))
        self.assertFalse(wg.valid_key(key(9)[:-2]))
        self.assertFalse(wg.valid_key("!" * 44))


class RenderTest(unittest.TestCase):
    def test_render_and_read_back(self):
        text = wg.render(cfg(), key(7))
        self.assertIn(f"PrivateKey = {key(7)}", text)
        self.assertIn("ListenPort = 51820", text)
        settings, peers = wg.read_conf(text)
        self.assertEqual(settings["Address"], "10.77.0.1/24")
        self.assertEqual(peers, {"desk": ("10.77.0.2/32", key(1)), "laptop": ("10.77.0.3/32", key(2))})

    def test_diff_names_changes_without_keys(self):
        old = wg.render(cfg(), key(7))
        new = wg.render(cfg(port=51821, peers=[f"desk 10.77.0.9 {key(1)}", f"tab 10.77.0.4 {key(5)}"]), key(8))
        lines = wg.diff(old, new)
        self.assertEqual(lines, ["ListenPort 51820 → 51821", "server key changed", "~ peer desk",
                                 "- peer laptop", "+ peer tab 10.77.0.4/32"])
        self.assertNotIn(key(8), " ".join(lines))
        self.assertEqual(wg.diff(None, new), ["new file"])
        self.assertEqual(wg.diff(old, old), [])

    def test_peer_text(self):
        text = wg.peer_text(cfg(), "laptop", key(7))
        self.assertIn("Address = 10.77.0.3/32", text)
        self.assertIn(f"PublicKey = {key(7)}", text)
        self.assertIn("AllowedIPs = 10.77.0.1/32", text)
        self.assertIn("Endpoint = vpn.example.com:51820", text)
        self.assertNotIn(key(2), text)   # the PC's own key is already in its app
        self.assertIn("Endpoint = [2001:db8::1]:51820",
                      wg.peer_text(cfg(endpoint="2001:db8::1"), "desk", key(7)))
        with self.assertRaises(KeyError):
            wg.peer_text(cfg(), "nobody", key(7))


if __name__ == "__main__":
    unittest.main()
