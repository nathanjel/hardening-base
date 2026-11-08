"""hbkit.pyversion: on a Python older than 3.11 a tool re-runs itself on the newest /usr/bin/python3.N."""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

sys.path.insert(0, os.path.join(REPO, "lib"))
from hbkit import pyversion  # noqa: E402


class NewestTest(unittest.TestCase):
    def test_picks_the_newest_runnable_python_from_3_11(self):
        with tempfile.TemporaryDirectory() as d:
            for name, mode in (("python3.9", 0o755), ("python3.11", 0o755), ("python3.13", 0o755),
                               ("python3.14", 0o644),                          # not executable
                               ("python3.13-config", 0o755), ("python3.20t", 0o755)):
                path = os.path.join(d, name)
                open(path, "w").close()
                os.chmod(path, mode)
            self.assertEqual(pyversion.newest(os.path.join(d, "python3.*")), os.path.join(d, "python3.13"))

    def test_none_when_only_old_ones(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("python3.6", "python3.9"):
                path = os.path.join(d, name)
                open(path, "w").close()
                os.chmod(path, 0o755)
            self.assertIsNone(pyversion.newest(os.path.join(d, "python3.*")))


@unittest.skipUnless(pyversion.newest(), "no /usr/bin/python3.N >= 3.11 here")
class ReRunTest(unittest.TestCase):
    def test_an_old_interpreter_hands_over_with_the_same_flags_and_arguments(self):
        with tempfile.TemporaryDirectory() as d:
            script = os.path.join(d, "tool")
            with open(script, "w") as f:
                f.write(textwrap.dedent(f"""\
                    import os, sys
                    if not os.environ.get("HB_TEST_RERUN"):
                        os.environ["HB_TEST_RERUN"] = "1"
                        sys.version_info = (3, 9, 25, "final", 0)     # what AL2023's /usr/bin/python3 says
                    sys.path.insert(0, {os.path.join(REPO, "lib")!r})
                    import hbkit.pyversion
                    print(sys.executable, sys.flags.isolated, sys.flags.dont_write_bytecode, sys.argv[1:])
                    """))
            r = subprocess.run([sys.executable, "-I", "-B", script, "a b", "--c"], capture_output=True, text=True,
                               timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            exe, isolated, nobytecode, args = r.stdout.split(" ", 3)
            self.assertEqual(exe, pyversion.newest())
            self.assertEqual((isolated, nobytecode, args.strip()), ("1", "1", "['a b', '--c']"))


if __name__ == "__main__":
    unittest.main()
