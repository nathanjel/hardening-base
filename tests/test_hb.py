"""The hb dispatcher's `check`: one line per tool, then a count that names the tools with nothing to check."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402


class CheckSummaryTest(unittest.TestCase):
    def test_counts_and_not_managed(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.makedirs(f"{d}/tools")
        shutil.copy(os.path.join(REPO, "hb"), f"{d}/hb")
        for name, line, rc in (("alpha", "ok: not managed", 0), ("beta", "warn: smartmontools not installed", 1),
                               ("gamma", "ok: fine", 0), ("delta", "ok: microk8s not installed", 0),
                               ("epsilon", "ok: upgrade: 0 packages; backup not configured", 0),   # the digest
                               ("omega", "fail: broken", 2)):
            with open(f"{d}/tools/hb-{name}", "w") as f:
                f.write(f"#!/bin/sh\necho 'detail first'\necho '{line}'\nexit {rc}\n")
            os.chmod(f"{d}/tools/hb-{name}", 0o755)
        r = subprocess.run([f"{d}/hb", "check"], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)
        lines = r.stdout.splitlines()
        self.assertEqual(lines[0], "alpha      ok: not managed")       # the verdict is a check's last line
        self.assertEqual(lines[-1], "4 ok, 1 warn, 1 fail; not managed here: alpha, delta")

    def test_a_check_that_crashed_is_a_failure_not_a_warning(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.makedirs(f"{d}/tools")
        shutil.copy(os.path.join(REPO, "hb"), f"{d}/hb")
        for name, line, rc in (("alpha", "warn: something", 1), ("beta", "pending: a group change", 1),
                               ("gamma", "ModuleNotFoundError: No module named 'tomllib'", 1),
                               ("delta", "line 9: x: unbound variable", 1)):
            with open(f"{d}/tools/hb-{name}", "w") as f:
                f.write(f"#!/bin/sh\necho \"{line}\"\nexit {rc}\n")
            os.chmod(f"{d}/tools/hb-{name}", 0o755)
        r = subprocess.run([f"{d}/hb", "check"], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)
        lines = r.stdout.splitlines()
        self.assertIn("gamma      fail: the check broke: ModuleNotFoundError: No module named 'tomllib'", lines)
        self.assertIn("delta      fail: the check broke: line 9: x: unbound variable", lines)
        self.assertEqual(lines[-1], "0 ok, 2 warn, 2 fail")


if __name__ == "__main__":
    unittest.main()
