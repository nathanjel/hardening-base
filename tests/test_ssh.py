"""hb-ssh: key lines, the PAM edit, sshd's view of the drop-in, apply → revert → confirm."""
import contextlib
import ctypes
import ctypes.util
import getpass
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

ssh = load_tool("ssh")
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
ME = getpass.getuser()

FEDORA_PAM = """#%PAM-1.0
auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
account    include      password-auth
session    include      postlogin
"""

FAKE = """#!/bin/sh
echo "$(basename "$0") $*" >> {log}
[ "$(basename "$0")" = sshd ] && [ -e {fail} ] && {{ echo "bad config"; exit 1; }}
exit 0
"""


def make_key(d, name):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", os.path.join(d, name)],
                   check=True)
    with open(os.path.join(d, name + ".pub")) as f:
        return f.read().strip()


class KeysTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.pub = make_key(self.d, "desk")

    def test_parse(self):
        keys, errors = ssh.parse_keys([f"{ME} {self.pub}"])
        self.assertEqual(errors, [])
        self.assertEqual(keys[ME][0][0], "ssh-ed25519")
        self.assertEqual(keys[ME][0][2], "desk")

    def test_errors_are_all_named(self):
        typ, blob, _ = self.pub.split()
        _, errors = ssh.parse_keys([
            f"{ME} ssh-rsa {blob} lies about its type",
            f"no-such-user-hb {self.pub}",
            f"{ME} {typ} bm90IGEga2V5",
            f"{ME}",
            f"{ME} {self.pub}", f"{ME} {self.pub}",
        ])
        self.assertEqual(len(errors), 5, errors)
        self.assertTrue(any("twice" in e for e in errors))

    def test_home_keys_skip_options(self):
        _, blob, _ = self.pub.split()
        home = tempfile.mkdtemp()
        os.makedirs(os.path.join(home, ".ssh"))
        with open(os.path.join(home, ".ssh", "authorized_keys"), "w") as f:
            f.write(f'# comment\nfrom="10.0.0.0/8",no-pty {self.pub}\n')
        old = ssh.pwd.getpwnam
        self.addCleanup(setattr, ssh.pwd, "getpwnam", old)
        ssh.pwd.getpwnam = lambda u: type("P", (), {"pw_dir": home})()
        self.assertEqual([k[1] for k in ssh.home_keys("x")], [blob])


class PamTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, ssh, "totp_path", ssh.totp_path)
        ssh.totp_path = lambda: "/opt/hb/tools/hb-totp"

    def test_swap_and_back(self):
        on, err = ssh.pam_want(FEDORA_PAM, codes=True)
        self.assertIsNone(err)
        auth = [l for l in on.splitlines() if l.startswith("auth")]
        self.assertRegex(auth[0], r"^auth\s+requisite\s+pam_exec\.so quiet expose_authtok /opt/hb/tools/hb-totp verify$")
        self.assertRegex(auth[1], r"^auth\s+required\s+pam_permit\.so$")     # after the code, never before
        self.assertNotIn("password-auth", "\n".join(auth))
        self.assertIn("account    include      password-auth", on)
        self.assertEqual(ssh.pam_want(on, codes=True)[0], on)
        self.assertEqual(ssh.pam_want(on, codes=False)[0], FEDORA_PAM)
        self.assertEqual(ssh.pam_want(FEDORA_PAM, codes=False)[0], FEDORA_PAM)

    def test_older_versions_are_replaced(self):
        exe = "pam_exec.so quiet expose_authtok /opt/hb/tools/hb-totp verify"
        for old in (f"auth       required     {exe}",
                    f"{ssh.PAM_NOTE}older note\nauth       [success=ok default=die] {exe}\nauth       required     pam_permit.so"):
            text = FEDORA_PAM.replace(ssh.PAM_STOCK, old)
            self.assertEqual(ssh.pam_want(text, True)[0], ssh.pam_want(FEDORA_PAM, True)[0])
            self.assertEqual(ssh.pam_want(text, False)[0], FEDORA_PAM)

    def test_changed_code_line_is_refused(self):
        # e.g. type=, which would make pam_exec answer "ignore" and let pam_permit decide: hb check fails
        on = ssh.pam_want(FEDORA_PAM, True)[0]
        self.assertIsNone(ssh.pam_want(on.replace("pam_exec.so quiet", "pam_exec.so type=account quiet"), True)[0])

    def test_unexpected_layout_is_refused(self):
        self.assertIsNone(ssh.pam_want(FEDORA_PAM.replace("substack", "include"), True)[0])
        self.assertIsNone(ssh.pam_want(FEDORA_PAM + "auth substack password-auth\n", True)[0])


LIBPAM = ctypes.util.find_library("pam")


@unittest.skipUnless(LIBPAM and hasattr(ctypes.CDLL(LIBPAM), "pam_start_confdir"), "no libpam >= 1.4")
class PamStackTest(unittest.TestCase):
    """The auth stack hb writes, run by the real libpam. For keyboard-interactive, sshd calls
    pam_authenticate in a forked child and pam_setcred in the parent, and drops the session when setcred
    fails; both that and the one-handle order are checked. The verifier is faked by true/false."""

    def setUp(self):
        self.addCleanup(setattr, ssh, "totp_path", ssh.totp_path)

    def run_stack(self, verifier, forked):
        ssh.totp_path = lambda: verifier
        d = tempfile.mkdtemp()
        for name in ("postlogin", "password-auth"):
            open(os.path.join(d, name), "w").close()
        with open(os.path.join(d, "hbtest"), "w") as f:
            f.write(ssh.pam_want(FEDORA_PAM, True)[0])
        lib = ctypes.CDLL(LIBPAM)

        class Msg(ctypes.Structure):
            _fields_ = [("style", ctypes.c_int), ("msg", ctypes.c_char_p)]

        class Resp(ctypes.Structure):
            _fields_ = [("resp", ctypes.c_void_p), ("retcode", ctypes.c_int)]

        conv_t = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(Msg)),
                                  ctypes.POINTER(ctypes.POINTER(Resp)), ctypes.c_void_p)

        class Conv(ctypes.Structure):
            _fields_ = [("conv", conv_t), ("appdata", ctypes.c_void_p)]

        libc = ctypes.CDLL(None)
        libc.calloc.restype = libc.strdup.restype = ctypes.c_void_p

        def answer(n, _msgs, resp, _data):     # libpam frees what we hand back, so it comes from malloc
            arr = ctypes.cast(libc.calloc(n, ctypes.sizeof(Resp)), ctypes.POINTER(Resp))
            for i in range(n):
                arr[i].resp = libc.strdup(b"123456")
            resp[0] = arr
            return 0

        conv, handle = Conv(conv_t(answer), None), ctypes.c_void_p()
        self.assertEqual(lib.pam_start_confdir(b"hbtest", ME.encode(), ctypes.byref(conv), d.encode(),
                                               ctypes.byref(handle)), 0)
        if forked:
            pid = os.fork()
            if pid == 0:
                os._exit(lib.pam_authenticate(handle, 0))
            auth = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
        else:
            auth = lib.pam_authenticate(handle, 0)
        cred = lib.pam_setcred(handle, 0x2) if auth == 0 else None       # PAM_ESTABLISH_CRED
        lib.pam_end(handle, auth)
        return auth, cred

    def test_code_accepted_and_session_allowed(self):
        self.assertEqual(self.run_stack("/bin/true", forked=True), (0, 0))      # as sshd does it
        self.assertEqual(self.run_stack("/bin/true", forked=False), (0, 0))

    def test_code_refused(self):
        self.assertNotEqual(self.run_stack("/bin/false", forked=True)[0], 0)
        self.assertNotEqual(self.run_stack("/bin/false", forked=False)[0], 0)


@unittest.skipUnless(os.path.exists(SSHD), "no sshd")
class SshdTest(unittest.TestCase):
    """What sshd itself makes of the drop-in, per client address."""

    def effective(self, dropin, addr):
        d = tempfile.mkdtemp()
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{d}/hostkey"], check=True)
        os.makedirs(f"{d}/conf.d")
        with open(f"{d}/conf.d/10-hb-ssh.conf", "w") as f:
            f.write(dropin)
        with open(f"{d}/conf.d/50-redhat.conf", "w") as f:
            f.write("X11Forwarding yes\nGSSAPIAuthentication yes\nUsePAM yes\n")
        with open(f"{d}/main", "w") as f:
            f.write(f"Include {d}/conf.d/*.conf\nAuthorizedKeysFile .ssh/authorized_keys\n"
                    "Subsystem sftp /usr/libexec/openssh/sftp-server\n")
        out = subprocess.run([SSHD, "-T", "-f", f"{d}/main", "-h", f"{d}/hostkey", "-C",
                              f"user={ME},host=x,addr={addr},laddr=192.0.2.1,lport=22"],
                             capture_output=True, text=True, check=True).stdout
        return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)

    def test_codes_except_from_wireguard(self):
        dropin = ssh.render_dropin(True, ["10.77.0.0/24"])
        net = self.effective(dropin, "203.0.113.9")
        wg = self.effective(dropin, "10.77.0.2")
        self.assertEqual(net["authenticationmethods"], "publickey,keyboard-interactive:pam")
        self.assertEqual(wg["authenticationmethods"], "publickey")
        for eff in (net, wg):
            self.assertEqual(eff["authorizedkeysfile"], "/etc/ssh/authorized_keys/%u")
            self.assertEqual(eff["allowgroups"], "hb-ssh")
            self.assertEqual(eff["x11forwarding"], "no")
            self.assertEqual(eff["gssapiauthentication"], "no")
            self.assertEqual(eff["kbdinteractiveauthentication"], "yes")
            self.assertEqual(eff["maxauthtries"], "3")
            self.assertIn("sftp", eff["subsystem"])

    def test_key_only(self):
        eff = self.effective(ssh.render_dropin(False, ["10.77.0.0/24"]), "203.0.113.9")
        self.assertEqual(eff["authenticationmethods"], "publickey")
        self.assertEqual(eff["kbdinteractiveauthentication"], "no")


class ApplyTest(unittest.TestCase):
    """apply → revert → apply → confirm, with systemd, sshd and the group tools faked."""

    def setUp(self):
        temp_state(self)
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        root = tempfile.mkdtemp()
        bin_dir = os.path.join(root, "bin")
        os.makedirs(bin_dir)
        os.makedirs(os.path.join(root, "sshd_config.d"))
        self.log, self.fail = os.path.join(root, "calls.log"), os.path.join(root, "fail")
        for cmd in ("systemd-run", "systemctl", "sshd", "groupadd", "gpasswd"):
            p = os.path.join(bin_dir, cmd)
            with open(p, "w") as f:
                f.write(FAKE.format(log=self.log, fail=self.fail))
            os.chmod(p, stat.S_IRWXU)
        self.addCleanup(os.environ.__setitem__, "PATH", os.environ["PATH"])
        os.environ["PATH"] = bin_dir + os.pathsep + os.environ["PATH"]
        self.addCleanup(os.environ.pop, "SUDO_USER", None)
        os.environ["SUDO_USER"] = ME
        self.pam = os.path.join(root, "pam-sshd")
        with open(self.pam, "w") as f:
            f.write(FEDORA_PAM)
        saved = {n: getattr(ssh, n) for n in ("KEYDIR", "DROPIN", "PAM", "totp_missing", "not_root_owned",
                                               "group_members")}
        self.addCleanup(lambda: [setattr(ssh, n, v) for n, v in saved.items()])
        self.addCleanup(setattr, ssh.util, "notify", ssh.util.notify)
        self.notes = []
        ssh.util.notify = lambda *a: self.notes.append(a)
        ssh.group_members = lambda: None                                 # no hb-ssh group yet
        ssh.KEYDIR, ssh.DROPIN, ssh.PAM = (os.path.join(root, "authorized_keys"),
                                           os.path.join(root, "sshd_config.d", "10-hb-ssh.conf"), self.pam)
        self.missing = ""
        ssh.totp_missing = lambda users: self.missing
        ssh.not_root_owned = lambda path: []
        self.pub = make_key(root, "desk")
        self.cfg = {"ssh": {"keys": [f"{ME} {self.pub}"], "codes": True, "key_only_from": ["10.77.0.0/24"],
                            "revert_minutes": 5},
                    "breakglass": {"user": ""}}

    def calls(self):
        with open(self.log) as f:
            return f.read()

    def read(self, path):
        with open(path) as f:
            return f.read()

    def test_cycle(self):
        self.assertEqual(ssh.do_plan(self.cfg), 1)
        self.assertEqual(ssh.do_apply(self.cfg, yes=True), 0)
        calls = self.calls()
        self.assertIn("groupadd -r hb-ssh", calls)
        self.assertIn(f"gpasswd -M {ME} hb-ssh", calls)
        self.assertIn("systemd-run --unit=hb-ssh-revert --on-active=5min", calls)
        self.assertIn("sshd -t", calls)
        self.assertIn("systemctl reload sshd", calls)
        keyfile = os.path.join(ssh.KEYDIR, ME)
        self.assertEqual(os.stat(keyfile).st_mode & 0o777, 0o644)
        self.assertEqual(os.stat(ssh.KEYDIR).st_mode & 0o777, 0o755)
        self.assertIn(self.pub.split()[1], self.read(keyfile))
        self.assertIn("hb-totp verify", self.read(self.pam))
        self.assertEqual(ssh.verdict(self.cfg)[0], 1)                   # waiting for confirmation
        # the timer fires: everything is as before
        self.assertEqual(ssh.do_revert(by_timer=True), 0)
        self.assertEqual(self.read(self.pam), FEDORA_PAM)
        self.assertFalse(os.path.exists(keyfile))
        self.assertFalse(os.path.exists(ssh.DROPIN))
        self.assertEqual(self.notes[-1][:2], ("warn", "ssh.revert"))
        # again, confirmed this time
        self.assertEqual(ssh.do_apply(self.cfg, yes=True), 0)
        self.assertEqual(ssh.do_confirm(), 0)
        self.assertIn("systemctl stop hb-ssh-revert.timer", self.calls())
        self.assertEqual(ssh.do_revert(by_timer=True), 0)                # too late: nothing to revert
        self.assertIn("hb-totp verify", self.read(self.pam))

    def test_rejected_config_is_put_back_at_once(self):
        open(self.fail, "w").close()
        self.assertEqual(ssh.do_apply(self.cfg, yes=True), 2)
        self.assertEqual(self.read(self.pam), FEDORA_PAM)
        self.assertFalse(os.path.exists(ssh.DROPIN))
        self.assertIsNone(ssh.GUARD.pending())

    def test_refuses_to_lock_you_out(self):
        os.environ["SUDO_USER"] = "someone-else"
        self.assertEqual(ssh.do_apply(self.cfg, yes=True), 2)
        os.environ["SUDO_USER"] = ME
        self.missing = ME
        self.assertEqual(ssh.do_apply(self.cfg, yes=True), 2)
        ssh.not_root_owned = lambda path: ["/home/x"]
        self.missing = ""
        self.assertEqual(ssh.do_apply(self.cfg, yes=True), 2)
        self.assertFalse(os.path.exists(self.log))                       # nothing ran at all

    def test_stray_key_file_goes(self):
        os.makedirs(ssh.KEYDIR)
        with open(os.path.join(ssh.KEYDIR, "olduser"), "w") as f:
            f.write(self.pub + "\n")
        self.assertEqual(ssh.do_apply(self.cfg, yes=True), 0)
        self.assertFalse(os.path.exists(os.path.join(ssh.KEYDIR, "olduser")))


if __name__ == "__main__":
    unittest.main()
