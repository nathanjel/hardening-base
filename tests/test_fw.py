"""hb-fw: zones from config and from firewalld's files, and the apply/confirm/revert cycle."""
import contextlib
import io
import os
import stat
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

fw = load_tool("fw")

PUBLIC_XML = """<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>Public</short>
  <description>For use in public areas.</description>
  <service name="ssh"/>
  <service name="mdns"/>
  <service name="http"/>
  <rule family="ipv4">
    <source address="192.0.2.0/27"/>
    <port port="5060" protocol="udp"/>
    <accept/>
  </rule>
  <rule family="ipv4">
    <source address="198.51.100.16/28"/>
    <port port="10000-10200" protocol="udp"/>
    <accept/>
  </rule>
  <forward/>
</zone>
"""

TRUSTED_XML = """<?xml version="1.0" encoding="utf-8"?>
<zone target="ACCEPT">
  <short>Trusted</short>
  <interface name="vxlan.calico"/>
  <source address="10.1.0.0/16"/>
  <forward/>
</zone>
"""


class ValuesTest(unittest.TestCase):
    def test_normalising(self):
        self.assertEqual(fw.norm_port("8088/tcp"), "8088/tcp")
        self.assertEqual(fw.norm_port("10000-10000/udp"), "10000/udp")
        self.assertEqual(fw.norm_net("192.0.2.7"), "192.0.2.7/32")
        self.assertEqual(fw.norm_rule("5060/udp  from 192.0.2.0/27"), "5060/udp from 192.0.2.0/27")
        for bad in ("80", "0/tcp", "90-80/tcp", "80/icmp"):
            with self.assertRaises(ValueError):
                fw.norm_port(bad)
        with self.assertRaises(ValueError):
            fw.norm_net("192.0.2.1/24")   # host bits set: probably a typo

    def test_config_errors_are_all_named(self):
        with self.assertRaises(ValueError) as ctx:
            fw.zone_from_config("public", {"service": ["ssh"], "target": "OPEN", "ports": ["x"],
                                           "rules": ["5060/udp to 192.0.2.0/27"], "forward": "yes"})
        msg = str(ctx.exception)
        for part in ("fw.zones.public.service is not", "target must be", "ports: 'x'", "rules:", "forward must be"):
            self.assertIn(part, msg)


class FilesTest(unittest.TestCase):
    def test_parse_render_roundtrip(self):
        z, short, desc = fw.zone_from_xml(PUBLIC_XML)
        self.assertEqual(z.services, {"ssh", "mdns", "http"})
        self.assertEqual(z.rules, {"5060/udp from 192.0.2.0/27", "10000-10200/udp from 198.51.100.16/28"})
        self.assertTrue(z.forward)
        again, short2, desc2 = fw.zone_from_xml(fw.render("public", z, short, desc))
        self.assertEqual((again, short2, desc2), (z, short, desc))
        t, _, _ = fw.zone_from_xml(TRUSTED_XML)
        self.assertEqual((t.target, t.interfaces), ("ACCEPT", {"vxlan.calico"}))

    def test_unmanaged_content_is_refused(self):
        for extra in ("<masquerade/>", '<forward-port port="80" protocol="tcp" to-port="8080"/>',
                      '<rule family="ipv4"><source address="192.0.2.1"/><service name="ssh"/><accept/></rule>',
                      '<rule family="ipv4"><source address="192.0.2.1"/><port port="22" protocol="tcp"/>'
                      '<log prefix="x"/><accept/></rule>',
                      '<rule family="ipv6"><source address="192.0.2.1"/><port port="22" protocol="tcp"/><accept/></rule>',
                      '<source ipset="blocklist"/>'):
            with self.assertRaises(fw.Unmanaged, msg=extra):
                fw.zone_from_xml(PUBLIC_XML.replace("<forward/>", extra))

    def test_changes(self):
        old, _, _ = fw.zone_from_xml(PUBLIC_XML)
        new = fw.zone_from_config("public", {
            "services": ["ssh", "http", "wireguard"], "forward": True,
            "rules": ["5060/udp from 192.0.2.0/27", "10000-10200/udp from 198.51.100.16/28"]})
        self.assertEqual(fw.changes(old, new), ["- service mdns", "+ service wireguard"])
        self.assertEqual(fw.changes(None, fw.zone_from_config("wg", {"interfaces": ["wg0"]})),
                         ["+ interface wg0"])

    def test_export_reads_back_as_the_same_zone(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "public.xml"), "w") as f:
            f.write(PUBLIC_XML)
        self.addCleanup(setattr, fw, "ETC", fw.ETC)
        fw.ETC, fw.LIB = d, d
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            fw.do_export(["public"])
        data = tomllib.loads(out.getvalue())
        z, _, _ = fw.zone_from_xml(PUBLIC_XML)
        self.assertEqual(fw.zone_from_config("public", data["fw"]["zones"]["public"]), z)


FAKE = """#!/bin/sh
echo "$(basename "$0") $*" >> "{log}"
case "$*" in
  --get-services) echo "ssh http https mdns wireguard samba" ;;
  --get-active-zones) printf 'public (default)\\n  interfaces: eth0\\n' ;;
  --check-config) [ -e "{fail}" ] && exit 1 ;;
esac
exit 0
"""


class ApplyTest(unittest.TestCase):
    """apply → revert → apply → confirm, with firewall-cmd, systemd-run and systemctl faked."""

    def setUp(self):
        temp_state(self)
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        root = tempfile.mkdtemp()
        self.etc, self.lib, binDir = (os.path.join(root, n) for n in ("etc", "lib", "bin"))
        for d in (self.etc, self.lib, binDir):
            os.makedirs(d)
        self.log, self.fail = os.path.join(root, "calls.log"), os.path.join(root, "fail")
        for cmd in ("firewall-cmd", "systemd-run", "systemctl"):
            p = os.path.join(binDir, cmd)
            with open(p, "w") as f:
                f.write(FAKE.format(log=self.log, fail=self.fail))
            os.chmod(p, stat.S_IRWXU)
        self.addCleanup(os.environ.__setitem__, "PATH", os.environ["PATH"])
        os.environ["PATH"] = binDir + os.pathsep + os.environ["PATH"]
        with open(os.path.join(self.etc, "public.xml"), "w") as f:
            f.write(PUBLIC_XML)
        old = (fw.ETC, fw.LIB, fw.notify, fw.busy)
        self.addCleanup(lambda: setattr(fw, "ETC", old[0]) or setattr(fw, "LIB", old[1])
                        or setattr(fw, "notify", old[2]) or setattr(fw, "busy", old[3]))
        self.notes = []
        fw.ETC, fw.LIB = self.etc, self.lib
        fw.notify = lambda *a: self.notes.append(a)
        fw.busy = lambda: []
        self.cfg = {"fw": {"revert_minutes": 5, "zones": {
            "public": {"services": ["ssh", "http", "wireguard"], "forward": True,
                       "rules": ["5060/udp from 192.0.2.0/27", "10000-10200/udp from 198.51.100.16/28"]},
            "wg": {"interfaces": ["wg0"], "services": ["ssh"], "ports": ["16443/tcp"]}}}}

    def calls(self):
        with open(self.log) as f:
            return f.read()

    def read(self, name):
        with open(os.path.join(self.etc, name)) as f:
            return f.read()

    def test_cycle(self):
        self.assertEqual(fw.do_plan(self.cfg), 1)
        self.assertEqual(fw.do_apply(self.cfg, yes=True), 0)
        self.assertIn("systemd-run --unit=hb-fw-revert --on-active=5min", self.calls())
        self.assertIn("firewall-cmd --reload", self.calls())
        self.assertIn('<service name="wireguard"/>', self.read("public.xml"))
        self.assertIn('<interface name="wg0"/>', self.read("wg.xml"))
        self.assertEqual(fw.verdict(self.cfg)[0], 1)              # waiting for confirmation
        self.assertEqual(fw.do_apply(self.cfg, yes=True), 0)      # nothing more to change
        # the timer fires: the old public zone comes back and the new wg zone goes
        self.assertEqual(fw.do_revert(by_timer=True), 0)
        self.assertEqual(self.read("public.xml"), PUBLIC_XML)
        self.assertFalse(os.path.exists(os.path.join(self.etc, "wg.xml")))
        self.assertEqual(self.notes[-1][:2], ("warn", "fw.revert"))
        # again, and this time confirmed
        self.assertEqual(fw.do_apply(self.cfg, yes=True), 0)
        self.assertEqual(fw.do_confirm(), 0)
        self.assertIn("systemctl stop hb-fw-revert.timer", self.calls())
        self.assertEqual(fw.verdict(self.cfg), (0, "ok: zones public, wg match hb.toml"))
        self.assertEqual(fw.do_revert(by_timer=True), 0)          # too late: nothing to revert
        self.assertIn('<service name="wireguard"/>', self.read("public.xml"))

    def test_rejected_config_is_put_back_at_once(self):
        open(self.fail, "w").close()
        self.assertEqual(fw.do_apply(self.cfg, yes=True), 2)
        self.assertEqual(self.read("public.xml"), PUBLIC_XML)
        self.assertFalse(os.path.exists(os.path.join(self.etc, "wg.xml")))
        self.assertFalse(os.path.exists(fw.pending_path()))

    def test_unmanaged_zone_file_blocks_apply(self):
        with open(os.path.join(self.etc, "public.xml"), "w") as f:
            f.write(PUBLIC_XML.replace("<forward/>", "<masquerade/>"))
        self.assertEqual(fw.do_apply(self.cfg, yes=True), 2)
        self.assertFalse(os.path.exists(self.log) and "systemd-run" in self.calls())
        self.assertEqual(fw.verdict(self.cfg)[0], 2)

    def test_busy_box_needs_a_human(self):
        fw.busy = lambda: ["1 call in progress"]
        self.assertEqual(fw.do_apply(self.cfg, yes=True), 1)
        self.assertEqual(self.read("public.xml"), PUBLIC_XML)


if __name__ == "__main__":
    unittest.main()
