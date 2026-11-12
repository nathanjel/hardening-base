"""hb-totp: RFC 6238 vectors, the PAM verdict, replay and recovery codes."""
import base64
import io
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool  # noqa: E402

totp = load_tool("totp")
KEY = b"12345678901234567890"
# one wrong answer from a process of its own, counting each answer the check evaluates in a file
PARALLEL_TRY = """import sys
sys.path.insert(0, sys.argv[1])
from tools import load_tool
totp = load_tool("totp")
totp.DIR, tried = sys.argv[2], sys.argv[3]
real = totp.answer
def counted(data, text, now):
    with open(tried, "a") as f:
        f.write("x")
    return real(data, text, now)
totp.answer, totp.locked = counted, lambda user: None
totp.verify({"PAM_TYPE": "auth", "PAM_USER": "alice"}, b"000000")
"""
RFC_SECRET = base64.b32encode(KEY).decode()


class TotpTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        old = (totp.DIR, totp.announce, totp.locked)
        self.addCleanup(lambda: setattr(totp, "DIR", old[0]) or setattr(totp, "announce", old[1])
                        or setattr(totp, "locked", old[2]))
        totp.DIR = d
        self.notes, self.locks = [], []
        totp.announce = lambda user, left: self.notes.append((user, left))
        totp.locked = self.locks.append
        self.now = 1111111111
        totp.save("alice", {"secret": RFC_SECRET, "codes": [], "last_step": 0})

    def pam(self, code, user="alice", now=None, kind="auth"):
        env = {"PAM_TYPE": kind, "PAM_USER": user}
        return totp.verify(env, code.encode() + b"\0", now=self.now if now is None else now)

    def test_admins_count_as_needing_codes(self):
        # hb harden's admins answer sudo with their code, so a missing enrolment is worth a warning
        self.addCleanup(setattr, totp, "clock_synced", totp.clock_synced)
        totp.clock_synced = lambda: True
        cfg = {"ssh": {"keys": [], "codes": False}, "harden": {"admins": ["bob"]}}
        self.assertIn("bob not enrolled", totp.verdict(cfg)[1])
        cfg["harden"]["admins"] = ["alice"]
        self.assertNotIn("not enrolled", totp.verdict(cfg)[1])

    def test_wrong_codes_lock_the_account_for_a_while(self):
        # Codex round 1: sudo has no attempt limit of its own, so the check keeps one per account
        for i in range(totp.FAIL_LIMIT):
            self.assertEqual(self.pam("000000", now=self.now + i), 1)
        self.assertEqual(self.locks, ["alice"])
        self.assertEqual(self.pam("050471", now=self.now + 10), 1)          # the right code too, while locked
        self.assertEqual(self.pam("000000", now=self.now + 11), 1)
        self.assertEqual(self.locks, ["alice"])                              # one SMS, not one per try
        self.assertEqual(len(totp.load("alice")["fails"]), totp.FAIL_LIMIT)  # tries while locked don't count
        t = self.now + totp.FAIL_WINDOW                                      # the oldest is now that old
        self.assertEqual(self.pam(totp.hotp(KEY, t // 30), now=t), 0)
        self.assertEqual(totp.load("alice")["fails"], [])

    def test_parallel_attempts_share_one_budget(self):
        # Codex round 3: the time was read before the lock, so attempts holding it out of order
        # dropped each other's failures; now at most FAIL_LIMIT answers are ever checked. Separate
        # processes, as sshd and sudo are (not forks of this one, which may hold other threads' locks).
        tried = os.path.join(totp.DIR, "tried")
        procs = [subprocess.Popen([sys.executable, "-I", "-B", "-c", PARALLEL_TRY, os.path.dirname(__file__), totp.DIR, tried],
                                  stdin=subprocess.DEVNULL) for _ in range(24)]
        for p in procs:
            self.assertEqual(p.wait(timeout=120), 0)
        with open(tried) as f:
            self.assertEqual(len(f.read()), totp.FAIL_LIMIT)

    def test_the_clock_is_read_under_the_lock(self):
        # Codex round 3: read before the lock, attempts could be judged out of order
        order, real_lock, real_time = [], totp.lock, totp.time

        class Clock:
            @staticmethod
            def time():
                order.append("clock")
                return real_time.time()

        class Held:
            def __enter__(self):
                self.inner = real_lock()
                self.inner.__enter__()
                order.append("lock")

            def __exit__(self, *exc):
                return self.inner.__exit__(*exc)
        self.addCleanup(setattr, totp, "lock", real_lock)
        self.addCleanup(setattr, totp, "time", real_time)
        totp.lock, totp.time = Held, Clock
        totp.verify({"PAM_TYPE": "auth", "PAM_USER": "alice"}, b"000000")
        self.assertEqual(order[:2], ["lock", "clock"])

    def test_a_clock_gone_back_keeps_the_count(self):
        # a failure stamped in the future counts as now, rather than as expired
        for i in range(totp.FAIL_LIMIT):
            self.assertEqual(self.pam("000000", now=self.now + 3600 + i), 1)
        self.assertEqual(self.pam("050471"), 1)                              # an hour earlier: still locked
        t = self.now + totp.FAIL_WINDOW
        self.assertEqual(self.pam(totp.hotp(KEY, t // 30), now=t), 0)       # it ends a window after that

    def test_a_right_code_clears_the_count(self):
        for i in range(totp.FAIL_LIMIT - 1):
            self.assertEqual(self.pam("000000", now=self.now + i), 1)
        self.assertEqual(self.pam("050471"), 0)
        self.assertEqual(totp.load("alice")["fails"], [])
        for i in range(totp.FAIL_LIMIT - 1):
            self.assertEqual(self.pam("000000", now=self.now + 30 + i), 1)
        self.assertEqual(self.pam(totp.hotp(KEY, (self.now + 60) // 30), now=self.now + 60), 0)
        self.assertEqual(self.locks, [])

    def test_wrong_recovery_codes_count_too(self):
        codes, hashes = totp.new_codes()
        totp.save("rescue", {"codes": hashes, "last_step": 0})
        for i in range(totp.FAIL_LIMIT):
            self.assertEqual(self.pam("AAAAA-AAAAA", user="rescue", now=self.now + i), 1)
        self.assertEqual(self.pam(codes[0], user="rescue", now=self.now + 10), 1)
        self.assertEqual(len(totp.load("rescue")["codes"]), totp.N_CODES)    # none used up while locked
        self.assertEqual(self.locks, ["rescue"])

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
