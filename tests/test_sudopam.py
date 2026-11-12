"""hbkit.sudopam: the two lines that make sudo ask one group's members for their code (hb totp), and
that stack run by the real libpam."""
import ctypes
import ctypes.util
import grp
import os
import pwd
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import tools  # noqa: E402,F401  (puts lib/ on the path)
from hbkit import sudopam  # noqa: E402

# /etc/pam.d/sudo as Fedora and Amazon Linux 2023 ship it
STOCK = """#%PAM-1.0
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    optional     pam_keyinit.so revoke
session    required     pam_limits.so
session    include      system-auth
"""
VERIFIER = "/opt/hb/tools/hb-totp"
LIBPAM = ctypes.util.find_library("pam")
ME = pwd.getpwuid(os.getuid()).pw_name


class SudoPamTest(unittest.TestCase):
    def test_lines_go_just_before_the_password_step(self):
        new, why = sudopam.want(STOCK, "hb-admins", VERIFIER)
        self.assertIsNone(why)
        lines = new.splitlines()
        i = lines.index("auth       include      system-auth")
        self.assertEqual(lines[i - 2:i], [
            "auth       [success=ignore auth_err=1 ignore=1 default=die] pam_succeed_if.so quiet user ingroup hb-admins",
            f"auth       [success=done default=die] pam_exec.so quiet expose_authtok {VERIFIER} verify"])
        self.assertTrue(lines[i - 3].startswith("# hb-harden: members of hb-admins"))
        self.assertEqual(lines[0], "#%PAM-1.0")
        self.assertEqual(new.replace("\n".join(lines[i - 3:i]) + "\n", ""), STOCK)     # nothing else changed
        self.assertEqual(sudopam.want(new, "hb-admins", VERIFIER), (new, None))      # in place: no change

    def test_another_group_or_path_replaces_hbs_lines(self):
        new = sudopam.want(STOCK, "hb-admins", VERIFIER)[0]
        other = sudopam.want(new, "ops", "/usr/local/hb/tools/hb-totp")[0]
        self.assertNotIn("hb-admins", other)
        self.assertEqual(other.count("pam_succeed_if"), 1)
        self.assertIn("ingroup ops", other)
        self.assertIn("/usr/local/hb/tools/hb-totp verify", other)

    def test_refused(self):
        for text in (STOCK.replace("auth       include      system-auth\n", ""),
                     STOCK + "auth include system-auth\n",
                     "@include common-auth\n"):
            self.assertIn("exactly one 'auth include system-auth'", sudopam.want(text, "hb-admins", VERIFIER)[1])
        edited = sudopam.want(STOCK, "hb-admins", VERIFIER)[0].replace("default=die]", "default=bad]")
        self.assertIn("edited by hand", sudopam.want(edited, "hb-admins", VERIFIER)[1])
        # Codex round 1: an auth line ahead of hb's could decide first (a password, a jump)
        for early in ("auth       sufficient   pam_unix.so", "-auth      optional     pam_whatever.so",
                      "auth       [success=2 default=ignore] pam_localuser.so",
                      "AUTH       sufficient   pam_unix.so",                  # Codex round 2: PAM reads types in any case
                      "-AUTH      optional     pam_whatever.so",
                      "@include common-auth",
                      "[auth]     sufficient   pam_unix.so",                  # Codex round 4: PAM drops the brackets
                      "[-AUTH]    optional     pam_whatever.so",
                      "[auth]sufficient pam_unix.so",                         # Codex round 5: the token ends at ]
                      "[-AUTH]sufficient pam_unix.so"):
            text = STOCK.replace("#%PAM-1.0\n", "#%PAM-1.0\n" + early + "\n")
            self.assertIn("an auth line comes before", sudopam.want(text, "hb-admins", VERIFIER)[1] or "", early)
        self.assertIsNone(sudopam.want(STOCK.replace("#%PAM-1.0\n", "#%PAM-1.0\n# a comment\n"), "hb-admins", VERIFIER)[1])
        self.assertIn("isn't a group name", sudopam.want(STOCK, "Bad Group", VERIFIER)[1])
        self.assertIn("full path", sudopam.want(STOCK, "hb-admins", "hb-totp")[1])

    def test_sudo_i_reaches_the_gate_only_through_sudo(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for text, rc in (("auth include sudo\naccount include sudo\n", 0), ("AUTH substack sudo\n", 0),
                         ("auth include system-auth\n", 2), ("[auth] sufficient pam_permit.so\nauth include sudo\n", 2),
                         ("auth sufficient pam_unix.so\nauth include sudo\n", 2), ("account include sudo\n", 2),
                         ("[auth]sufficient pam_permit.so\nauth include sudo\n", 2)):
            with self.subTest(text):
                with open(f"{d}/sudo-i", "w") as f:
                    f.write(text)
                self.assertEqual(sudopam.check_login(f"{d}/sudo-i")[0], rc)
        self.assertEqual(sudopam.check_login(f"{d}/none")[0], 2)

    def test_check_and_write_keep_the_file(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = f"{d}/sudo"
        with open(path, "w") as f:
            f.write(STOCK)
        os.chmod(path, 0o644)
        self.assertEqual(sudopam.check(path, "hb-admins", VERIFIER)[0], 1)
        sudopam.write(path, "hb-admins", VERIFIER)
        self.assertEqual(sudopam.check(path, "hb-admins", VERIFIER),
                         (0, f"{path}: hb-admins's members answer with their code"))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
        self.assertEqual(sudopam.check(f"{d}/none", "hb-admins", VERIFIER)[0], 2)


@unittest.skipUnless(LIBPAM and hasattr(ctypes.CDLL(LIBPAM), "pam_start_confdir"), "no libpam >= 1.4")
class SudoPamStackTest(unittest.TestCase):
    """The stack hb writes, run by the real libpam as sudo runs it: pam_authenticate, then
    pam_setcred. The password step behind it is a stand-in (system-auth here) that lets anyone
    through or nobody, and the code checker a script that takes 123456 or refuses."""

    def run_stack(self, group, system_auth, code_ok, text=None):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        verifier = f"{d}/bin/hb-totp"
        os.makedirs(f"{d}/bin")
        check = '[ "$code" = 123456 ]' if code_ok else "exit 1"
        with open(verifier, "w") as f:
            f.write("#!/bin/sh\nread code\n" + check + "\n")
        os.chmod(verifier, 0o755)
        with open(f"{d}/system-auth", "w") as f:
            f.write(system_auth)
        with open(f"{d}/hbtest", "w") as f:
            f.write((text or sudopam.want(STOCK, group, verifier)[0]).replace("VERIFIER", verifier))
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
        auth = lib.pam_authenticate(handle, 0)
        cred = lib.pam_setcred(handle, 0x2) if auth == 0 else None       # PAM_ESTABLISH_CRED
        lib.pam_end(handle, auth)
        return auth, cred

    MINE = grp.getgrgid(os.getgid()).gr_name       # a group the test's user is in: stands for hb-admins
    NOT_MINE = "hbtestnosuchgroup"
    ANYONE = "auth sufficient pam_permit.so\nauth required pam_deny.so\n"
    NOBODY = "auth required pam_deny.so\n"
    # system-auth's auth lines as Fedora and AL2023 ship them: what sudo's pam_setcred runs
    STOCK_AUTH = "auth required pam_env.so\nauth sufficient pam_unix.so try_first_pass nullok\nauth required pam_deny.so\n"

    def test_a_member_gets_in_with_the_code(self):
        self.assertEqual(self.run_stack(self.MINE, self.STOCK_AUTH, code_ok=True), (0, 0))

    def test_setcred_is_the_stock_stacks_for_everyone(self):
        # pam_setcred skips the code line (pam_succeed_if answers "ignore" there), so it is
        # system-auth's, as without hb's lines: a stack whose setcred fails fails for members too
        self.assertEqual(self.run_stack(self.MINE, self.NOBODY, code_ok=True)[0], 0)
        self.assertNotEqual(self.run_stack(self.MINE, self.NOBODY, code_ok=True)[1], 0)

    def test_a_wrong_code_fails_even_where_the_password_step_would_pass(self):
        self.assertNotEqual(self.run_stack(self.MINE, self.ANYONE, code_ok=False)[0], 0)

    def test_an_unexpected_answer_from_the_group_test_fails(self):
        # Codex round 1: only "not a member" may skip the code; a service error must not open the password
        broken = sudopam.want(STOCK, self.MINE, "/x/hb-totp")[0].replace("/x/hb-totp", "VERIFIER").replace(
            f"user ingroup {self.MINE}", f"user frobnicate {self.MINE}")
        self.assertNotEqual(self.run_stack(self.MINE, self.ANYONE, code_ok=False, text=broken)[0], 0)

    def test_everyone_else_goes_on_to_the_password_step(self):
        self.assertEqual(self.run_stack(self.NOT_MINE, self.ANYONE, code_ok=False), (0, 0))
        self.assertNotEqual(self.run_stack(self.NOT_MINE, self.NOBODY, code_ok=True)[0], 0)


if __name__ == "__main__":
    unittest.main()
