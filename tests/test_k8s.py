"""hb-k8s's restart item, as (namespace) root with systemctl faked; the other items not managed."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

# systemctl show answers what systemd would have loaded: snapd's defaults, or hb's drop-in once it's there
FAKE_SYSTEMCTL = """#!/bin/sh
echo "$*" >> {log}
if [ "$1" = show ]; then
  if [ -f "{units}/$2.d/10-hb-keep-restarting.conf" ]; then
    printf 'RestartUSec=10s\\nStartLimitIntervalUSec=0\\n'
  else
    printf 'RestartUSec=100ms\\nStartLimitIntervalUSec=10s\\n'
  fi
fi
exit 0
"""


def can_fake_root():
    return shutil.which("unshare") is not None and subprocess.run(
        ["unshare", "-r", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
@unittest.skipUnless(os.path.exists("/snap/bin/microk8s"), "hb-k8s exits early without microk8s")
class KeepRestartingTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.units, self.bin, self.log = f"{d}/units", f"{d}/bin", f"{d}/systemctl.log"
        os.makedirs(self.units)
        os.makedirs(self.bin)
        with open(f"{self.bin}/systemctl", "w") as f:
            f.write(FAKE_SYSTEMCTL.format(log=self.log, units=self.units))
        os.chmod(f"{self.bin}/systemctl", 0o755)
        self.toml = f"{d}/hb.toml"
        self.config('["kubelite", "k8s-dqlite"]')

    def config(self, daemons):
        with open(self.toml, "w") as f:
            f.write(f"[k8s]\nkeep_restarting = {daemons}\n")

    def tool(self, *args):
        env = {**os.environ, "HB_CONFIG": self.toml, "HB_SYSTEMD_DIR": self.units, "HB_STATE": f"{self.d}/state",
               "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-k8s"), *args], env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              start_new_session=True)

    def dropin(self, daemon):
        return f"{self.units}/snap.microk8s.daemon-{daemon}.service.d/10-hb-keep-restarting.conf"

    def test_pending_then_applied(self):
        r = self.tool("status")
        line = next(l for l in r.stdout.splitlines() if " restart " in f" {l} ")
        self.assertIn("kubelite: no drop-in; k8s-dqlite: no drop-in", line)
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for daemon in ("kubelite", "k8s-dqlite"):
            with open(self.dropin(daemon)) as f:
                text = f.read()
            self.assertIn("[Unit]\nStartLimitIntervalSec=0\n[Service]\nRestartSec=10s\n", text)
            self.assertEqual(os.stat(self.dropin(daemon)).st_mode & 0o777, 0o644)
            self.assertEqual(os.stat(os.path.dirname(self.dropin(daemon))).st_mode & 0o777, 0o755)
        with open(self.log) as f:
            self.assertIn("daemon-reload", f.read())
        r = self.tool("status")
        self.assertIn("kubelite k8s-dqlite: retry every 10 s, no limit", r.stdout)
        self.assertEqual(self.tool("check").returncode, 0)

    def test_an_edited_dropin_is_pending_again(self):
        self.tool("apply", "--yes")
        with open(self.dropin("kubelite"), "a") as f:
            f.write("RestartSec=1h\n")
        self.assertEqual(self.tool("check").returncode, 1)

    def test_not_managed_by_default_and_names_checked(self):
        self.config("[]")
        self.assertIn("not managed", next(l for l in self.tool("status").stdout.splitlines() if "restart" in l))
        self.config('["../../evil"]')
        self.assertEqual(self.tool("check").returncode, 2)
        self.assertEqual(os.listdir(self.units), [])


if __name__ == "__main__":
    unittest.main()
