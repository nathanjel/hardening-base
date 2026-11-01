"""hb-totp: RFC 6238 vectors, the PAM verdict, replay and recovery codes."""
import base64
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool  # noqa: E402

totp = load_tool("totp")
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


class TotpTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        old = (totp.DIR, totp.announce)
        self.addCleanup(lambda: setattr(totp, "DIR", old[0]) or setattr(totp, "announce", old[1]))
        totp.DIR = d
        self.notes = []
        totp.announce = lambda user, left: self.notes.append((user, left))
        self.now = 1111111111
        totp.save("alice", {"secret": RFC_SECRET, "codes": [], "last_step": 0})

    def pam(self, code, user="alice", now=None, kind="auth"):
        env = {"PAM_TYPE": kind, "PAM_USER": user}
        return totp.verify(env, code.encode() + b"\0", now=self.now if now is None else now)

    def test_rfc6238_vectors(self):
        key = b"12345678901234567890"
        for t, want in ((59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                        (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")):
            self.assertEqual(totp.hotp(key, t // 30, digits=8), want)
            self.assertEqual(totp.hotp(key, t // 30), want[-6:])

    def test_code_once_within_drift(self):
        self.assertEqual(self.pam("050471"), 0)
        self.assertEqual(self.pam("050471"), 1)                     # replay
        later = totp.hotp(b"12345678901234567890", self.now // 30 + 1)
        self.assertEqual(self.pam(later), 0)                        # one step ahead: drift
        far = totp.hotp(b"12345678901234567890", self.now // 30 + 3)
        self.assertEqual(self.pam(far), 1)                          # too far

    def test_refusals(self):
        self.assertEqual(self.pam("050471", kind="account"), 1)
        self.assertEqual(self.pam("050471", user="../alice"), 1)
        self.assertEqual(self.pam("050471", user="nobody"), 1)       # no file
        self.assertEqual(self.pam(""), 1)
        self.assertEqual(self.pam("05047"), 1)
        self.assertEqual(self.pam("0504711"), 1)
        with open(totp.user_path("broken"), "w") as f:
            f.write("{not json")
        with self.assertRaises(ValueError):
            totp.verify({"PAM_TYPE": "auth", "PAM_USER": "broken"}, b"050471")
        # safe_verify, PAM's entry point, turns any error into a refusal
        self.addCleanup(setattr, sys, "stdin", sys.stdin)
        sys.stdin = io.TextIOWrapper(io.BytesIO(b"050471\0"))
        self.addCleanup(os.environ.pop, "PAM_USER", None)
        self.addCleanup(os.environ.pop, "PAM_TYPE", None)
        os.environ.update(PAM_TYPE="auth", PAM_USER="broken")
        self.assertEqual(totp.safe_verify(), 1)

    def test_recovery_codes_work_once(self):
        codes, hashes = totp.new_codes()
        totp.save("rescue", {"codes": hashes, "last_step": 0})
        typed = codes[3].lower().replace("-", " ")                  # case and spacing don't matter
        self.assertEqual(self.pam(typed, user="rescue"), 0)
        self.assertEqual(self.pam(codes[3], user="rescue"), 1)
        self.assertEqual(len(totp.load("rescue")["codes"]), 9)
        self.assertEqual(self.notes, [("rescue", 9)])
        self.assertEqual(self.pam("050471", user="rescue"), 1)       # no secret: digits refused
        self.assertEqual(self.pam("ZZZZZ-ZZZZZ", user="rescue"), 1)

    def test_codes_are_stored_hashed(self):
        codes, hashes = totp.new_codes()
        self.assertEqual(len(set(codes)), 10)
        for c, h in zip(codes, hashes):
            self.assertNotIn(totp.norm_code(c), h)
            self.assertTrue(totp.code_matches(totp.norm_code(c), h))
        self.assertEqual(totp.norm_code("abcde-fghjk"), "ABCDEFGHJK")
        self.assertEqual(totp.norm_code("O1IL0-00000"), "01110" + "00000")
        self.assertIsNone(totp.norm_code("ABCDE-FGHJ"))
        self.assertIsNone(totp.norm_code("ABCDE-FGHJU"))

    def test_files_are_root_only(self):
        self.assertEqual(os.stat(totp.user_path("alice")).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(totp.DIR).st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
