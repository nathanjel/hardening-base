"""hb-inventory: the state dump is written whole, pieces fail alone, and the check reads it."""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

inventory = load_tool("inventory")
CFG = {"inventory": {"drift_ignore": []}}


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class InventoryTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.addCleanup(setattr, inventory, "pieces", inventory.pieces)

    def use(self, pieces):
        inventory.pieces = lambda: pieces

    def test_users_txt(self):
        d = tempfile.mkdtemp()
        write(os.path.join(d, "passwd"), "root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"
                                        "nobody:x:65534:65534::/:/sbin/nologin\nrescue:x:4700:4700::/home/rescue:/bin/bash\n")
        write(os.path.join(d, "group"), "wheel:x:10:alice\ndocker:x:978:alice,rescue\nalice:x:1001:\n")
        self.assertEqual(inventory.users_txt(os.path.join(d, "passwd"), os.path.join(d, "group")),
                         "alice 1001 1001 /home/alice /bin/bash docker,wheel\n"
                         "rescue 4700 4700 /home/rescue /bin/bash docker\n")

    def test_written_whole_and_failures_noted(self):
        self.use([("packages.txt", lambda: "git\nrestic\n"),
                  ("firewalld.txt", lambda: (_ for _ in ()).throw(RuntimeError("firewall-cmd: exit 252"))),
                  ("k8s/objects.json", lambda: json.dumps({"items": [{"kind": "Secret"}, {"kind": "Service"}]}))])
        root = inventory.state_root()
        write(os.path.join(root, "stale.txt"), "from an older dump\n")
        self.assertEqual(inventory.do_run(CFG), 1)
        self.assertEqual(sorted(os.listdir(root)), ["inventory.json", "k8s", "packages.txt"])
        self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(root, "packages.txt")).st_mode & 0o777, 0o600)
        meta = json.load(open(os.path.join(root, "inventory.json")))
        self.assertEqual(meta["counts"], {"packages": 2, "k8s_objects": 2})
        self.assertEqual(meta["errors"], ["firewalld.txt: firewall-cmd: exit 252"])
        self.assertFalse(os.path.exists(root + ".new") or os.path.exists(root + ".old"))
        rc, line = inventory.verdict()
        self.assertEqual(rc, 1)
        self.assertIn("couldn't read firewalld.txt", line)

    def test_verdict(self):
        self.assertEqual(inventory.verdict()[0], 0)
        self.use([("packages.txt", lambda: "git\n")])
        self.assertEqual(inventory.do_run(CFG), 0)
        self.assertEqual(inventory.verdict(), (0, "ok: state dump 0 h ago: 1 packages, 0 k8s objects"))
        rc, line = inventory.verdict(now=time.time() + 60 * 3600)
        self.assertEqual(rc, 1)
        self.assertIn("60 h old", line)


SS = """\
udp UNCONN 0 0 0.0.0.0:45829 0.0.0.0:* users:(("rpc.statd",pid=9,fd=8))
udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=7,fd=12))
udp UNCONN 0 0 127.0.0.1:41000 0.0.0.0:* users:(("helper",pid=5,fd=1))
tcp LISTEN 0 4096 127.0.0.1:35473 0.0.0.0:* users:(("agy",pid=2,fd=12))
tcp LISTEN 0 100 0.0.0.0:40500 0.0.0.0:* users:(("denoiser",pid=3,fd=6))
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3),("sshd",pid=4,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))
tcp LISTEN 0 511 *:443 *:* users:(("nginx",pid=8,fd=6),("traefik",pid=6,fd=6))
"""

FIREWALLD = """\
public (default, active)
  target: default
  interfaces: eno1
  services: ssh
  ports: 80/tcp 443/tcp
  rich rules: \n\trule family="ipv4" source address="10.0.0.0/8" drop
\trule family="ipv6" drop

wg (active)
  target: DROP
  ports: 445/tcp
  rich rules: 
"""


def obj(kind, name, ns=None, **extra):
    o = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "uid": "u1", "resourceVersion": "1"}}
    if ns:
        o["metadata"]["namespace"] = ns
    for k, v in extra.items():
        if k == "meta":
            o["metadata"].update(v)
        else:
            o[k] = v
    return o


def dump(root, files):
    for name, text in files.items():
        write(os.path.join(root, name), text if isinstance(text, str) else json.dumps({"items": text}))


class PiecesTest(unittest.TestCase):
    def test_listening(self):
        self.assertEqual(inventory.listening_lines(SS), [
            "tcp *:443 nginx,traefik",
            "tcp 0.0.0.0:22 sshd",
            "tcp 0.0.0.0:40500 denoiser",                 # a TCP listener keeps its port
            "tcp [::]:22 sshd",
            "udp 0.0.0.0:51820 ?",                        # so does a kernel socket (WireGuard)
            "udp 0.0.0.0:ephemeral rpc.statd",            # a program's UDP socket doesn't
            "udp 127.0.0.53%lo:53 systemd-resolve"])      # loopback throwaway ports left out

    def test_sudoers_keeps_includes(self):
        d = tempfile.mkdtemp()
        write(os.path.join(d, "sudoers"), "# comment\nDefaults env_reset\n\nroot ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n")
        write(os.path.join(d, "sudoers.d", "x"), "%wheel ALL=(ALL) ALL\n")
        self.assertEqual(inventory.sudoers_txt(os.path.join(d, "sudoers"), os.path.join(d, "sudoers.d")),
                         f"{d}/sudoers: Defaults env_reset\n{d}/sudoers: root ALL=(ALL) ALL\n"
                         f"{d}/sudoers: #includedir /etc/sudoers.d\n{d}/sudoers.d/x: %wheel ALL=(ALL) ALL\n")

    def test_groups(self):
        d = tempfile.mkdtemp()
        write(os.path.join(d, "group"), "wheel:x:10:bob,alice\nempty:x:20:\ndocker:x:978:alice\n")
        self.assertEqual(inventory.groups_txt(os.path.join(d, "group")), "docker 978 alice\nwheel 10 alice,bob\n")

    def test_firewalld(self):
        d = inventory.p_firewalld(FIREWALLD)
        self.assertEqual(d["public ports"], "80/tcp 443/tcp")
        self.assertEqual(d["public rich rules"],
                         'rule family="ipv4" source address="10.0.0.0/8" drop | rule family="ipv6" drop')
        self.assertEqual(d["wg target"], "DROP")
        self.assertEqual(d["wg rich rules"], "")


class DriftTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.a, self.b = tempfile.mkdtemp(), tempfile.mkdtemp()
        dep = obj("Deployment", "web", "shop", spec={"replicas": 1}, status={"ready": 1},
                  meta={"annotations": {"deployment.kubernetes.io/revision": "3"}})
        dump(self.a, {
            "system.txt": "2026-11-01T04:00:00+0100\nLinux box 7.2.13 #1 x86_64\nPRETTY_NAME=\"Fedora 44\"\n",
            "packages.txt": "git\nrestic\n",
            "units-enabled.txt": "sshd.service enabled disabled\n",
            "snaps.txt": "Name Version Rev Tracking Publisher Notes\nmicrok8s v1.35.6 9072 1.35/stable canonical** classic,held\n",
            "groups.txt": "wheel 10 alice\n",
            "k8s/objects.json": [dep, obj("Secret", "tls", "shop", data={"k": "old"})],
        })
        dep2 = json.loads(json.dumps(dep))
        dep2["status"] = {"ready": 0}
        dep2["metadata"].update(resourceVersion="99", annotations={"deployment.kubernetes.io/revision": "4"})
        dump(self.b, {
            "system.txt": "2026-11-02T04:00:00+0100\nLinux box 7.2.14 #1 x86_64\nPRETTY_NAME=\"Fedora 44\"\n",
            "packages.txt": "git\nnmap\n",
            "units-enabled.txt": "sshd.service enabled disabled\nevil.service enabled disabled\n",
            "snaps.txt": "Name Version Rev Tracking Publisher Notes\nmicrok8s v1.35.7 9100 1.35/stable canonical** classic\n",
            "groups.txt": "wheel 10 alice,mallory\n",
            "listening.txt": "tcp 0.0.0.0:4444 nc\n",              # new piece: not compared
            "k8s/objects.json": [
                dep2,                                                     # only noise changed
                obj("Secret", "tls", "shop", data={"k": "new"}),          # renewed: changed, no values
                obj("Job", "backup-1", "shop", meta={"ownerReferences": [{"kind": "CronJob"}]}),
                obj("EndpointSlice", "web-x", "shop",
                    meta={"labels": {"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"}}),
                obj("EndpointSlice", "host", "shop", meta={"labels": {"endpointslice.kubernetes.io/managed-by": "me"}}),
            ],
        })

    def test_drift_lines(self):
        self.assertEqual(inventory.drift(self.a, self.b), [
            "system changed: kernel: 7.2.13 → 7.2.14",
            "package added: nmap",
            "package removed: restic",
            "snap changed: microk8s: v1.35.6 1.35/stable classic,held → v1.35.7 1.35/stable classic",
            "group changed: wheel: 10 alice → 10 alice,mallory",
            "unit enabled: evil.service",
            "k8s added: shop/EndpointSlice/host",
            "k8s changed: shop/Secret/tls",
        ])
        self.assertEqual(inventory.drift(self.a, self.b, ignore=["^k8s changed: .*/Secret/", "^package"]), [
            "system changed: kernel: 7.2.13 → 7.2.14",
            "snap changed: microk8s: v1.35.6 1.35/stable classic,held → v1.35.7 1.35/stable classic",
            "group changed: wheel: 10 alice → 10 alice,mallory",
            "unit enabled: evil.service",
            "k8s added: shop/EndpointSlice/host",
        ])

    def test_run_logs_drift_against_the_dump_before(self):
        self.addCleanup(setattr, inventory, "pieces", inventory.pieces)
        out = io.StringIO()
        inventory.pieces = lambda: [("packages.txt", lambda: "git\n")]
        with contextlib.redirect_stdout(out):
            inventory.do_run(CFG)                                 # the first dump: nothing to compare
        self.assertEqual(inventory.read_drift(), [])
        inventory.pieces = lambda: [("packages.txt", lambda: "git\nnmap\n")]
        with contextlib.redirect_stdout(out):
            inventory.do_run(CFG)
        e = inventory.read_drift()
        self.assertEqual([x["changes"] for x in e], [["package added: nmap"]])
        self.assertIn("1 change since the dump of", out.getvalue())
        with contextlib.redirect_stdout(out):
            inventory.do_run(CFG)                                 # no change: nothing logged
        self.assertEqual(len(inventory.read_drift()), 1)
        inventory.log_drift(["later"], 0, now=int(time.time()) + 91 * 86400)
        self.assertEqual([x["changes"] for x in inventory.read_drift()], [["later"]])   # 90 days kept


if __name__ == "__main__":
    unittest.main()
