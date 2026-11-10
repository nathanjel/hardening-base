"""hb-k8s's restart and linger items, as (namespace) root with systemctl and loginctl faked; the
other items not managed."""
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


# root's user manager runs while root lingers (and nobody stopped it); systemd-oomd as the test sets it
LINGER_SYSTEMCTL = """#!/bin/sh
echo "systemctl $*" >> {log}
case "$1 $2" in
  "is-active user@0.service")
    if [ -e "{linger}/root" ] && [ ! -e "{d}/stopped" ]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
  "is-active systemd-oomd.service")
    if [ -e "{d}/oomd" ]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
  "show user@0.service")
    if [ -e "{d}/oomd-kill" ]; then echo kill; else echo auto; fi ;;
  "start --no-block")
    if [ "$3" = user@0.service ]; then rm -f "{d}/stopped"; fi ;;
esac
exit 0
"""
# as logind 252: enabling linger starts the manager only for a user it hasn't started yet, so a
# manager stopped while a root session pins root's record (the "stopped" flag) stays stopped
LINGER_LOGINCTL = """#!/bin/sh
echo "loginctl $*" >> {log}
if [ "$1 $2" = "enable-linger root" ]; then mkdir -p "{linger}" && touch "{linger}/root"; fi
exit 0
"""


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
@unittest.skipUnless(os.path.exists("/snap/bin/microk8s"), "hb-k8s exits early without microk8s")
class LingerTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.bin, self.log, self.linger = f"{d}/bin", f"{d}/calls.log", f"{d}/linger"
        os.makedirs(self.bin)
        for name, text in (("systemctl", LINGER_SYSTEMCTL), ("loginctl", LINGER_LOGINCTL)):
            with open(f"{self.bin}/{name}", "w") as f:
                f.write(text.format(log=self.log, linger=self.linger, d=d))
            os.chmod(f"{self.bin}/{name}", 0o755)
        self.toml = f"{d}/hb.toml"
        self.config("linger_root = true")

    def config(self, line):
        with open(self.toml, "w") as f:
            f.write(f"[k8s]\n{line}\n")

    def flag(self, name):
        open(f"{self.d}/{name}", "w").close()

    def tool(self, *args):
        env = {**os.environ, "HB_CONFIG": self.toml, "HB_LINGER_DIR": self.linger, "HB_SYSTEMD_DIR": f"{self.d}/units",
               "HB_STATE": f"{self.d}/state", "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-k8s"), *args], env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              start_new_session=True)

    def line(self):
        return next(l for l in self.tool("status").stdout.splitlines() if l.split()[1:2] == ["linger"])

    def calls(self, prog):
        try:
            with open(self.log) as f:
                return [l.strip() for l in f if l.startswith(prog + " ")]
        except OSError:
            return []

    def enabled(self):
        return self.calls("loginctl").count("loginctl enable-linger root")

    def test_pending_then_applied(self):
        self.assertIn("root's user manager stops after each root session", self.line())
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.enabled(), 1)
        self.assertTrue(os.path.exists(f"{self.linger}/root"))
        self.assertIn("ok    linger         root lingers: its user manager runs from boot", self.line())
        self.assertEqual(self.tool("check").returncode, 0)
        self.tool("apply", "--yes")
        self.assertEqual(self.enabled(), 1)                    # nothing to do

    def test_a_stopped_manager_is_started_again(self):
        self.tool("apply", "--yes")
        self.flag("stopped")                                   # systemctl stop user@0, or terminate-user root
        self.assertIn("root lingers, but its user manager isn't running", self.line())
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(self.enabled(), 2)
        self.assertIn("systemctl start --no-block user@0.service", self.calls("systemctl"))
        self.assertEqual(self.tool("check").returncode, 0, r.stdout + r.stderr)

    def test_refused_where_systemd_oomd_watches_user_managers(self):
        self.flag("oomd")                                      # oomd runs, but leaves user@ alone: fine
        self.assertEqual(self.tool("check").returncode, 1)
        self.flag("oomd-kill")                                 # Fedora's systemd-oomd-defaults
        self.assertIn("systemd-oomd ends processes in root's user manager", self.line())
        self.assertEqual(self.tool("check").returncode, 2)
        self.tool("apply", "--yes")
        self.assertEqual(self.enabled(), 0)
        self.assertFalse(os.path.exists(f"{self.linger}/root"))

    def test_not_managed_by_default_and_never_undone(self):
        self.config("")
        self.assertIn("not managed", self.line())
        os.makedirs(self.linger)
        self.flag("linger/root")                               # root lingers, set by someone else
        self.assertEqual(self.tool("check").returncode, 0)
        self.tool("apply", "--yes")
        self.assertEqual(self.calls("loginctl"), [])           # neither enabled nor disabled
        self.assertTrue(os.path.exists(f"{self.linger}/root"))


if __name__ == "__main__":
    unittest.main()
