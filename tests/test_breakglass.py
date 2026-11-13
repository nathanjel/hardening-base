"""hb-breakglass: passphrases, the kit key and page, a whole kit run (commands faked), the verdicts."""
import contextlib
import io
import json
import os
import stat
import pwd
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

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

    def test_ssh_key_from_a_terminal(self):
        # found on a box: run from a terminal, ssh-keygen asked the person for the passphrase
        # (readpassphrase opens /dev/tty first), and the page printed one the key didn't have
        d = tempfile.mkdtemp()
        key, child = os.path.join(d, "k"), os.path.join(d, "child.py")
        with open(child, "w") as f:
            f.write("import os, sys, importlib.machinery, importlib.util\n"
                    "os.setsid()\n"
                    "fd = os.open(sys.argv[1], os.O_RDWR)   # a session leader's first terminal is its own\n"
                    "for n in (0, 1, 2):\n    os.dup2(fd, n)\n"
                    "loader = importlib.machinery.SourceFileLoader('bg', sys.argv[2])\n"
                    "bg = importlib.util.module_from_spec(importlib.util.spec_from_loader('bg', loader))\n"
                    "loader.exec_module(bg)\n"
                    "bg.make_ssh_key(sys.argv[3], 'correct-horse-battery', 'c')\n")
        master, slave = os.openpty()
        p = subprocess.Popen([sys.executable, "-IB", child, os.ttyname(slave), bg.__file__, key],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(slave)
        out, answered, deadline = b"", 0, time.time() + 60
        try:
            while p.poll() is None and time.time() < deadline:
                r, _, _ = select.select([master], [], [], 0.2)
                if r:
                    try:
                        out += os.read(master, 4096)
                    except OSError:
                        break
                for _ in range(out.lower().count(b"passphrase") - answered):    # as the person did: Enter
                    os.write(master, b"\n")
                    answered += 1
            rc = p.wait(timeout=10)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            os.close(master)
        self.assertNotIn(b"passphrase", out.lower())
        self.assertEqual(rc, 0, out)
        ok = subprocess.run(["ssh-keygen", "-y", "-P", "correct-horse-battery", "-f", key], capture_output=True)
        self.assertEqual(ok.returncode, 0)

    def test_ssh_key_asks_no_helper_program(self):
        # with DISPLAY (sudo keeps it on Amazon Linux) ssh-keygen would ask SSH_ASKPASS instead
        d = tempfile.mkdtemp()
        helper = os.path.join(d, "askpass")
        with open(helper, "w") as f:
            f.write("#!/bin/sh\necho wrong-answer\n")
        os.chmod(helper, 0o755)
        with mock.patch.dict(os.environ, {"DISPLAY": ":0", "SSH_ASKPASS": helper, "SSH_ASKPASS_REQUIRE": "force"}):
            bg.make_ssh_key(os.path.join(d, "k"), "correct-horse-battery", "c")
        ok = subprocess.run(["ssh-keygen", "-y", "-P", "correct-horse-battery", "-f", os.path.join(d, "k")],
                            capture_output=True)
        self.assertEqual(ok.returncode, 0)

    def test_a_key_without_the_kits_passphrase_makes_no_kit(self):
        d = tempfile.mkdtemp()
        fake = os.path.join(d, "ssh-keygen")
        with open(fake, "w") as f:      # makes keys with no passphrase, whatever it is given
            f.write(f'#!/bin/sh\ncase " $* " in *" -t "*) exec {shutil.which("ssh-keygen")} -N "" "$@" ;; esac\n'
                    f'exec {shutil.which("ssh-keygen")} "$@"\n')
        os.chmod(fake, 0o755)
        with mock.patch.object(bg, "KEYGEN", fake):
            with self.assertRaisesRegex(RuntimeError, "didn't lock the key with the kit's passphrase"):
                bg.make_ssh_key(os.path.join(d, "k"), "correct-horse-battery", "c")

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

    def rotations(self):
        return [c for c in self.calls if c[0] == "chpasswd" or c[:3] == ("restic", "key", "add")
                or (c[0].endswith("/hb") and c[1:3] == ("totp", "codes"))]

    def test_a_destination_that_cant_take_the_kit_changes_nothing(self):
        old_key = "# the kit made 2026-11-01\nssh-ed25519 AAAAold rescue kit\n"
        with open(os.path.join(self.keydir, "rescue"), "w") as f:
            f.write(old_key)
        bg.save_state({"kit_made": "2026-11-01", "restic_key": "old"})
        before = bg.load_state()
        d = tempfile.mkdtemp()
        os.mkdir(os.path.join(d, "real"))
        os.symlink(os.path.join(d, "real"), os.path.join(d, "link"))
        with open(os.path.join(d, "file"), "w"):
            pass
        for to in (f"{d}/link/kit", f"{d}/no/such/kit", f"{d}/file/kit"):
            self.assertEqual(bg.do_kit(cfg(), to), 2, to)
            self.assertEqual(self.rotations(), [], to)                  # no key, password, codes or backup key
            with open(os.path.join(self.keydir, "rescue")) as f:
                self.assertEqual(f.read(), old_key, to)
            self.assertEqual(bg.load_state(), before, to)
        self.assertEqual(os.listdir(os.path.join(d, "real")), [])
        self.assertFalse([x for x in os.listdir(bg.util.state_dir("breakglass")) if x.startswith("kit-")])

    def test_a_failed_delivery_keeps_the_new_kit(self):
        real = bg.kit_put
        self.addCleanup(setattr, bg, "kit_put", real)

        def full(dfd, name, *a, **kw):
            if name == "kit.html":
                raise OSError(28, "No space left on device")
            real(dfd, name, *a, **kw)
        bg.kit_put = full
        self.assertEqual(bg.do_kit(cfg(), self.out), 2)
        self.assertFalse(os.path.exists(self.out))                       # nothing half-written left there
        staged = bg.load_state()["kit_dir"]
        self.assertTrue(staged.startswith(bg.util.state_dir("breakglass")), staged)
        self.assertEqual(sorted(os.listdir(staged)),
                         ["kit.html", "kit.txt", "rescue.key", "rescue.key.pub", "secrets.json"])
        self.assertEqual(stat.S_IMODE(os.stat(staged).st_mode), 0o700)
        self.assertIn(f"kit files still on the server: {staged}", bg.kit_verdict(cfg())[1])
        self.assertNotIn("rotation", bg.load_state())                     # the kit is whole, just not delivered
        self.assertEqual(self.notes[-1][:2], ("warn", "breakglass.kit"))

    def failing_write(self, suffix):
        """util.write_atomic, refusing paths that end in suffix with a full disk."""
        real = bg.util.write_atomic
        self.addCleanup(setattr, bg.util, "write_atomic", real)

        def write(path, *a, **kw):
            if path.endswith(suffix):
                raise OSError(28, "No space left on device")
            return real(path, *a, **kw)
        bg.util.write_atomic = write
        return lambda: setattr(bg.util, "write_atomic", real)

    def test_a_failed_write_while_staging_keeps_what_was_made(self):
        undo = self.failing_write("/kit.html")
        self.assertEqual(bg.do_kit(cfg(), self.out), 2)
        self.assertTrue(self.rotations())                                 # the credentials did change
        rot = bg.load_state()["rotation"]
        staged = rot["staging"]
        self.assertTrue(set(os.listdir(staged)) >= {"rescue.key", "rescue.key.pub", "secrets.json", "kit.txt"})
        with open(os.path.join(staged, "secrets.json")) as f:
            secrets = json.load(f)
        self.assertEqual(len(secrets["codes"]), 10)
        self.assertTrue(secrets["password"] and secrets["phrase"] and secrets["restic_password"])
        rc, line = bg.kit_verdict(cfg())
        self.assertEqual(rc, 2)                                           # never "ok" after a half rotation
        self.assertIn(f"didn't finish; what was made is in {staged}", line)
        self.assertEqual(self.notes[-1][:2], ("fail", "breakglass.kit"))
        self.assertFalse(os.path.exists(self.out))
        # the next run makes a whole kit, clears the record and the earlier try's secrets
        undo()
        self.assertEqual(bg.do_kit(cfg(), self.out + "2"), 0)
        self.assertNotIn("rotation", bg.load_state())
        self.assertFalse(os.path.exists(staged))
        self.assertNotEqual(bg.kit_verdict(cfg())[0], 2)

    def test_two_unfinished_runs_are_both_named(self):
        undo = self.failing_write("/kit.html")
        self.assertEqual(bg.do_kit(cfg(), self.out), 2)
        first = bg.load_state()["rotation"]["staging"]
        self.assertEqual(bg.do_kit(cfg(), self.out + "2"), 2)
        rc, line = bg.kit_verdict(cfg())
        self.assertIn(first, line)
        undo()
        self.assertEqual(bg.do_kit(cfg(), self.out + "3"), 0)
        self.assertFalse(os.path.exists(first))

    def test_nothing_changes_if_the_secrets_cant_be_written_down(self):
        bg.save_state({"kit_made": "2026-11-01", "restic_key": "old"})
        before = bg.load_state()
        self.failing_write("/secrets.json")
        self.assertEqual(bg.do_kit(cfg(), self.out), 2)
        self.assertEqual(self.rotations(), [])
        self.assertEqual(bg.load_state(), before)
        self.assertFalse([x for x in os.listdir(bg.util.state_dir("breakglass")) if x.startswith("kit-")])
        self.assertFalse(os.path.exists(self.out))

    def test_kit_refused_before_hb_ssh(self):
        bg.KEYDIR = "/elsewhere"
        self.assertEqual(bg.do_kit(cfg(), self.out), 2)
        self.assertFalse(os.path.exists(self.out))


if __name__ == "__main__":
    unittest.main()
