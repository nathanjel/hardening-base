"""hbkit.start: a tool re-runs itself on Python 3.11+ when it has to, and ends quietly when its output pipe closes."""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

sys.path.insert(0, os.path.join(REPO, "lib"))
from hbkit import start  # noqa: E402


class NewestTest(unittest.TestCase):
    def test_picks_the_newest_runnable_python_from_3_11(self):
        with tempfile.TemporaryDirectory() as d:
            for name, mode in (("python3.9", 0o755), ("python3.11", 0o755), ("python3.13", 0o755),
                               ("python3.14", 0o644),                          # not executable
                               ("python3.13-config", 0o755), ("python3.20t", 0o755)):
                path = os.path.join(d, name)
                open(path, "w").close()
                os.chmod(path, mode)
            self.assertEqual(start.newest(os.path.join(d, "python3.*")), os.path.join(d, "python3.13"))

    def test_none_when_only_old_ones(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("python3.6", "python3.9"):
                path = os.path.join(d, name)
                open(path, "w").close()
                os.chmod(path, 0o755)
            self.assertIsNone(start.newest(os.path.join(d, "python3.*")))


@unittest.skipUnless(start.newest(), "no /usr/bin/python3.N >= 3.11 here")
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
                    import hbkit.start
                    print(sys.executable, sys.flags.isolated, sys.flags.dont_write_bytecode, sys.argv[1:])
                    """))
            r = subprocess.run([sys.executable, "-I", "-B", script, "a b", "--c"], capture_output=True, text=True,
                               timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            exe, isolated, nobytecode, args = r.stdout.split(" ", 3)
            self.assertEqual(exe, start.newest())
            self.assertEqual((isolated, nobytecode, args.strip()), ("1", "1", "['a b', '--c']"))


class ClosedPipeTest(unittest.TestCase):
    def tool(self, body):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        self.dir = d
        path = os.path.join(d, "tool")
        with open(path, "w") as f:
            f.write(f"import sys\nsys.path.insert(0, {os.path.join(REPO, 'lib')!r})\nimport hbkit.start\n" + body)
        return path

    def run_closing(self, body, lines=1):
        """Start the tool, read LINES lines, close the reading end, then let the tool go on (EOF on stdin)."""
        p = subprocess.Popen([sys.executable, "-I", "-B", self.tool(body)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(lines):
            p.stdout.readline()
        p.stdout.close()
        p.stdin.close()
        err = p.stderr.read().decode()
        p.stderr.close()
        p.wait(timeout=30)
        return p.returncode, err

    def test_a_reader_that_goes_away_ends_the_tool_quietly(self):
        # hb health status | head -3, which prints and flushes line by line
        rc, err = self.run_closing("sys.stdin.read()\nfor i in range(100000):\n    print('line', i, flush=True)\n", 0)
        self.assertEqual((rc, err), (141, ""))

    def test_output_still_buffered_at_exit_ends_quietly_too(self):
        # the last flush happens while Python shuts down: without help, "Exception ignored" and exit 120
        rc, err = self.run_closing("print('x' * 100)\nsys.stdin.read()\n", 0)
        self.assertEqual((rc, err), (141, ""))

    def test_the_tool_unwinds_on_the_way_out(self):
        body = ("sys.stdin.read()\ntry:\n    while True:\n        print('x', flush=True)\n"
                "finally:\n    open(sys.argv[0] + '.cleaned', 'w').close()\n")
        rc, err = self.run_closing(body, 0)
        self.assertEqual((rc, err), (141, ""))
        self.assertTrue(os.path.exists(os.path.join(self.dir, "tool.cleaned")))

    def test_another_broken_pipe_after_the_reader_left_still_shows(self):
        # stdout is closed, but this error has nothing to do with it: its traceback and exit 1 stay
        body = "print('one', flush=True)\nprint('pending')\nsys.stdin.read()\nraise BrokenPipeError('the API hung up')\n"
        rc, err = self.run_closing(body, 1)
        self.assertEqual(rc, 1)
        self.assertIn("BrokenPipeError: the API hung up", err)
        self.assertNotIn("Exception ignored", err)

    def test_another_broken_pipe_still_shows(self):
        script = self.tool("raise BrokenPipeError('the API hung up')\n")
        p = subprocess.run([sys.executable, "-I", "-B", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 1)
        self.assertIn("BrokenPipeError: the API hung up", p.stderr)


if __name__ == "__main__":
    unittest.main()
