"""hb-breakglass: passphrases, the kit key and page, a whole kit run (commands faked), the verdicts."""
import contextlib
import io
import json
import os
import pwd
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

bg = load_tool("breakglass")
ME = pwd.getpwuid(os.getuid()).pw_name


def cfg(**over):
    c = {"breakglass": {"user": "rescue", "uid": 4700, "host": "server.example", "note": "", "test_days": 180},
         "backup": {"repo": "/mnt/backup/restic", "password_file": "/dev/null"}, "probe": {"host": ""}}
    c["breakglass"].update(over)
    return c


class PiecesTest(unittest.TestCase):
    def test_passphrase(self):
        wl = bg.words()
        self.assertEqual(len(wl), 7772)
        p = bg.passphrase(wl).split("-")
        self.assertEqual(len(p), 6)
        self.assertTrue(all(w in wl for w in p))

    def test_ssh_key_needs_the_passphrase(self):
        d = tempfile.mkdtemp()
        pub = bg.make_ssh_key(os.path.join(d, "k"), "correct-horse-battery", "rescue kit")
        self.assertTrue(pub.startswith("ssh-ed25519 ") and pub.endswith("rescue kit"))
        ok = subprocess.run(["ssh-keygen", "-y", "-P", "correct-horse-battery", "-f", os.path.join(d, "k")],
                            capture_output=True)
        bad = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", os.path.join(d, "k")], capture_output=True)
        self.assertEqual((ok.returncode, bad.returncode != 0), (0, True))

    def kit(self, **over):
        k = {"host": "server.example", "user": "rescue", "made": "2026-11-01", "note": "OVH login: <in the safe>",
             "fingerprint": "SHA256:abc", "repo": "/mnt/backup/restic", "restic_password": "r-e-s-t-i-c",
             "phrase": "p-h-r-a-s-e", "password": "p-a-s-s", "codes": [f"AAAA{i}-BBBBB" for i in range(10)]}
        k.update(over)
        return k

    def test_page_has_everything(self):
        k = self.kit()
        for text in (bg.kit_txt(k), bg.kit_html(k)):
            for want in ("p-h-r-a-s-e", "p-a-s-s", "r-e-s-t-i-c", "AAAA0-BBBBB", "AAAA9-BBBBB", "SHA256:abc",
                         "ssh -o IdentitiesOnly=yes -i $env:USERPROFILE\\rescue.key rescue@server.example", "restic -r /mnt/backup/restic"):
                self.assertIn(want, text)
        self.assertIn("&lt;in the safe&gt;", bg.kit_html(k))
        no_repo = bg.kit_txt(self.kit(repo="", restic_password=""))
        self.assertNotIn("BACKUP PASSWORD", no_repo)
        self.assertNotIn("restic", no_repo)

    def test_sessions_text(self):
        answers = {("show-user",): "4 7\n",
                   ("show-session", "4"): "Service=sshd\nRemoteHost=203.0.113.7\nTTY=pts/1\n",
                   ("show-session", "7"): "Service=systemd-user\nRemoteHost=\nTTY=\n"}
        old = bg.util.run
        self.addCleanup(setattr, bg.util, "run", old)
        bg.util.run = lambda *cmd, **kw: (0, answers[(cmd[1],) if cmd[1] == "show-user" else cmd[1:3]], "")
        self.assertEqual(bg.sessions_text(4700), "sshd from 203.0.113.7")

    def test_uid_of_another_user_is_refused(self):
        rc, line = bg.chk_account(cfg(user="hb-no-such-user", uid=os.getuid()))
        self.assertEqual(rc, 2)
        self.assertIn(ME, line)


class KitTest(unittest.TestCase):
    """A whole kit run: system commands answered by a fake run(), files in temp dirs."""

    def setUp(self):
        temp_state(self)
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.keydir = tempfile.mkdtemp()
        self.out = os.path.join(tempfile.mkdtemp(), "kit")
        self.calls, self.notes = [], []
        saved = {n: getattr(bg, n) for n in ("KEYDIR", "ITEMS")}
        self.addCleanup(lambda: [setattr(bg, n, v) for n, v in saved.items()])
        for name, val in (("run", self.fake_run), ("ask", lambda q: True),
                          ("notify", lambda *a: self.notes.append(a)), ("sudo_user", lambda: None)):
            self.addCleanup(setattr, bg.util, name, getattr(bg.util, name))
            setattr(bg.util, name, val)
        bg.KEYDIR = self.keydir
        bg.ITEMS = (("account", lambda c: (0, "ok"), None),)
        self.keys = []

    def fake_run(self, *cmd, **kw):
        self.calls.append(cmd)
        if cmd[:2] == ("sshd", "-T"):
            return 0, f"authorizedkeysfile {self.keydir}/%u\n", ""
        if cmd[:3] == ("restic", "key", "add"):
            self.keys.append({"id": f"id{len(self.keys)}", "hostName": "hb-kit", "created": str(time.time())})
            return 0, "", ""
        if cmd[:3] == ("restic", "key", "list"):
            return 0, json.dumps([{"id": "main", "hostName": "agent", "created": "1"}] + self.keys), ""
        if cmd[0].endswith("/hb") and cmd[1:3] == ("totp", "codes"):
            return 0, "\n".join(f"CODE{i}-XXXXX" for i in range(10)), ""
        if cmd[0] == "ssh-keygen":
            return 0, "256 SHA256:hostkey root@x (ED25519)", ""
        return 0, "", ""

    def test_kit_then_rotate(self):
        c = cfg()
        self.assertEqual(bg.do_kit(c, self.out), 0)
        self.assertEqual(sorted(os.listdir(self.out)), ["kit.html", "kit.txt", "rescue.key", "rescue.key.pub"])
        with open(os.path.join(self.out, "kit.txt")) as f:
            page = f.read()
        self.assertIn("CODE9-XXXXX", page)
        self.assertIn("SHA256:hostkey", page)
        with open(os.path.join(self.keydir, "rescue")) as f, open(os.path.join(self.out, "rescue.key.pub")) as g:
            self.assertIn(g.read().strip(), f.read())
        chpasswd = [cmd for cmd in self.calls if cmd[0] == "chpasswd"]
        self.assertEqual(len(chpasswd), 1)                               # password via stdin, not argv
        self.assertEqual(bg.load_state()["restic_key"], "id0")
        self.assertEqual(bg.kit_verdict(c)[0], 1)                         # files still on the server
        # rotate: the old backup key goes
        self.assertEqual(bg.do_kit(c, self.out + "2"), 0)
        self.assertIn(("restic", "key", "remove", "id0"), self.calls)
        self.assertEqual(bg.load_state()["restic_key"], "id1")

    def test_kit_states(self):
        c = cfg()
        self.assertEqual(bg.kit_verdict(c)[0], 1)                         # no kit
        bg.save_state({"kit_made": "2026-11-01", "kit_made_ts": time.time() - 60, "kit_dir": "/nonexistent"})
        self.assertIn("not used yet", bg.kit_verdict(c)[1])
        bg.save_state({**bg.load_state(), "last_login": time.time()})
        self.assertEqual(bg.kit_verdict(c)[0], 0)
        bg.save_state({**bg.load_state(), "last_login": time.time() - 200 * 86400,
                       "kit_made_ts": time.time() - 300 * 86400})
        self.assertIn("test it again", bg.kit_verdict(c)[1])

    def test_kit_refused_before_hb_ssh(self):
        bg.KEYDIR = "/elsewhere"
        self.assertEqual(bg.do_kit(cfg(), self.out), 2)
        self.assertFalse(os.path.exists(self.out))


if __name__ == "__main__":
    unittest.main()
