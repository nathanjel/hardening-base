"""hb-inventory: the state dump is written whole, pieces fail alone, and the check reads it."""
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

inventory = load_tool("inventory")


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
        self.assertEqual(inventory.do_run(), 1)
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
        self.assertEqual(inventory.do_run(), 0)
        self.assertEqual(inventory.verdict(), (0, "ok: state dump 0 h ago: 1 packages, 0 k8s objects"))
        rc, line = inventory.verdict(now=time.time() + 60 * 3600)
        self.assertEqual(rc, 1)
        self.assertIn("60 h old", line)


if __name__ == "__main__":
    unittest.main()
