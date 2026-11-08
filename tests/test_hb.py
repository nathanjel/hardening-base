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
        for name, line, rc in (("alpha", "ok: not managed", 0), ("beta", "warn: something", 1),
                               ("gamma", "ok: fine", 0), ("delta", "ok: microk8s not installed", 0),
                               ("omega", "fail: broken", 2)):
            with open(f"{d}/tools/hb-{name}", "w") as f:
                f.write(f"#!/bin/sh\necho 'detail first'\necho '{line}'\nexit {rc}\n")
            os.chmod(f"{d}/tools/hb-{name}", 0o755)
        r = subprocess.run([f"{d}/hb", "check"], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)
        lines = r.stdout.splitlines()
        self.assertEqual(lines[0], "alpha      ok: not managed")       # the verdict is a check's last line
        self.assertEqual(lines[-1], "3 ok, 1 warn, 1 fail; not managed here: alpha, delta")


if __name__ == "__main__":
    unittest.main()
