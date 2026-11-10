"""hb-harden's sshd drop-in (root_login and x11 share it) and its journal item, as (namespace) root
with sshd, systemctl, systemd-analyze and journalctl faked; the other items not managed."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

# sshd -T: the drop-in's values (read first, so they win), else the distribution's; -t fails on a flag
SSHD = """#!/bin/sh
echo "sshd $*" >> {log}
if [ "$1" = -t ]; then [ -e {d}/bad ] && {{ echo "bad config" >&2; exit 1; }}; exit 0; fi
v() {{ awk -v k="$1" 'tolower($1) == k {{print $2; exit}}' {sshd}/10-hb-harden.conf 2>/dev/null; }}
echo "permitrootlogin $(v permitrootlogin | grep . || echo without-password)"
echo "x11forwarding $(v x11forwarding | grep . || echo yes)"
"""
# journald: started when the test says (the "started" file holds the time, to the microsecond, as
# systemctl show --timestamp=us+utc prints it), or now when restarted
SYSTEMCTL = """#!/bin/sh
echo "systemctl $*" >> {log}
case "$1 $2" in
  "show systemd-journald.service") cat {d}/started 2>/dev/null ;;
  "restart systemd-journald") date -u '+%a %Y-%m-%d %H:%M:%S.%6N UTC' > {d}/started ;;
esac
exit 0
"""
# what systemd-analyze cat-config prints: journald.conf, then the drop-ins of both folders (hb's,
# and one standing in for /run/systemd/journald.conf.d) in the order of their names
ANALYZE = """#!/bin/sh
[ "$*" = "cat-config systemd/journald.conf" ] || exit 1
printf '# /etc/systemd/journald.conf\\n[Journal]\\n#SystemMaxUse=\\n'
for f in {journald}/*.conf {d}/run/journald.conf.d/*.conf; do [ -f "$f" ] && echo "${{f##*/}} $f"; done | LC_ALL=C sort |
  while read -r name f; do printf '\\n# %s\\n' "$f"; cat "$f"; done
"""
JOURNALCTL = """#!/bin/sh
echo "Archived and active journals take up 514.6M in the file system."
"""
def systemd_time(ns):
    """A time as systemctl show --timestamp=us+utc prints it."""
    return time.strftime("%a %Y-%m-%d %H:%M:%S", time.gmtime(ns // 10**9)) + f".{ns % 10**9 // 1000:06d} UTC"


HEADER = ("# Managed by hb-harden. Files here are read in name order and the first\n"
          "# value wins, so this one sorts before the distribution defaults.\n")


def can_fake_root():
    return shutil.which("unshare") is not None and subprocess.run(
        ["unshare", "-r", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
class HardenTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.bin, self.log = f"{d}/bin", f"{d}/calls.log"
        self.sshd, self.journald = f"{d}/sshd_config.d", f"{d}/journald.conf.d"
        os.makedirs(self.bin)
        os.makedirs(self.sshd)
        for name, text in (("sshd", SSHD), ("systemctl", SYSTEMCTL), ("systemd-analyze", ANALYZE),
                           ("journalctl", JOURNALCTL)):
            with open(f"{self.bin}/{name}", "w") as f:
                f.write(text.format(log=self.log, d=d, sshd=self.sshd, journald=self.journald))
            os.chmod(f"{self.bin}/{name}", 0o755)
        self.toml = f"{d}/hb.toml"
        self.dropin = f"{self.sshd}/10-hb-harden.conf"
        self.ours = f"{self.journald}/90-hb.conf"

    def config(self, *lines):
        with open(self.toml, "w") as f:
            f.write("[harden]\n" + "".join(f"{line}\n" for line in lines))

    def tool(self, *args):
        env = {**os.environ, "HB_CONFIG": self.toml, "HB_SSHD_DIR": self.sshd, "HB_JOURNALD_DIR": self.journald,
               "HB_STATE": f"{self.d}/state", "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-harden"), *args], env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              start_new_session=True)

    def line(self, item):
        return next(l for l in self.tool("status").stdout.splitlines() if l.split()[1:2] == [item])

    def calls(self):
        try:
            with open(self.log) as f:
                return [l.strip() for l in f]
        except OSError:
            return []

    def read(self, path):
        with open(path) as f:
            return f.read()

    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    # --- sshd ---

    def test_x11_pending_then_applied(self):
        self.config('x11_forwarding = "no"')
        self.assertIn(f"X11Forwarding yes → no (via {self.dropin})", self.line("x11"))
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.read(self.dropin), HEADER + "X11Forwarding no\n")
        self.assertEqual(os.stat(self.dropin).st_mode & 0o777, 0o600)
        self.assertIn("sshd -t", self.calls())
        self.assertIn("systemctl reload sshd", self.calls())
        self.assertIn("ok    x11            X11Forwarding no", self.line("x11"))
        self.assertEqual(self.tool("check").returncode, 0)

    def test_x11_keeps_the_root_login_line(self):
        self.write(self.dropin, HEADER + "PermitRootLogin no\n")     # as root_login wrote it before x11 existed
        self.config('permit_root_login = "no"', 'x11_forwarding = "no"')
        self.assertIn("PermitRootLogin no", self.line("root_login"))
        self.tool("apply", "--yes")
        self.assertEqual(self.read(self.dropin), HEADER + "PermitRootLogin no\nX11Forwarding no\n")
        self.assertEqual(self.tool("check").returncode, 0)

    def test_root_login_alone_writes_what_it_always_did(self):
        self.config('permit_root_login = "no"')
        self.tool("apply", "--yes")
        self.assertEqual(self.read(self.dropin), HEADER + "PermitRootLogin no\n")
        self.assertIn("not managed", self.line("x11"))

    def test_a_rejected_config_is_put_back(self):
        self.write(self.dropin, HEADER + "PermitRootLogin no\n")
        self.config('permit_root_login = "no"', 'x11_forwarding = "no"')
        open(f"{self.d}/bad", "w").close()
        self.tool("apply", "--yes")
        self.assertEqual(self.read(self.dropin), HEADER + "PermitRootLogin no\n")
        self.assertNotIn("systemctl reload sshd", self.calls())
        self.assertEqual(self.tool("check").returncode, 1)

    def test_x11_takes_yes_or_no(self):
        self.config('x11_forwarding = "off"')
        self.assertEqual(self.tool("check").returncode, 2)

    # --- journal ---

    def test_journal_pending_then_applied(self):
        self.config('journal_max_use = "2G"')
        self.assertIn(f"SystemMaxUse=(journald's default) → 2G via {self.ours}; the journal now takes 514.6M",
                      self.line("journal"))
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.read(self.ours),
                         "# Managed by hb-harden from hb.toml (harden.journal_max_use).\n[Journal]\nSystemMaxUse=2G\n")
        self.assertEqual(os.stat(self.ours).st_mode & 0o777, 0o644)
        self.assertEqual(os.stat(self.journald).st_mode & 0o777, 0o755)
        self.assertIn("systemctl restart systemd-journald", self.calls())
        self.assertIn("ok    journal        SystemMaxUse=2G (the journal now takes 514.6M)", self.line("journal"))
        self.assertEqual(self.tool("check").returncode, 0)

    def test_a_drop_in_read_after_ours_has_to_go(self):
        size = f"{self.journald}/size.conf"                   # sorts after 90-hb.conf, so it would win
        self.write(size, "[Journal]\nSystemMaxUse=500M\n")
        self.config('journal_max_use = "2G"')
        self.assertIn(f"{size} sets SystemMaxUse after hb's 90-hb.conf, so it would win: list it in harden.remove_files",
                      self.line("journal"))
        self.assertEqual(self.tool("check").returncode, 2)
        self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(self.ours))
        self.config('journal_max_use = "2G"', f'remove_files = ["{size}"]')
        self.assertIn(f"SystemMaxUse=500M ({size}) → 2G", self.line("journal"))
        self.tool("apply", "--yes")                            # files (first) takes size.conf away, then journal
        self.assertFalse(os.path.exists(size))
        self.assertEqual(self.tool("check").returncode, 0)

    def test_a_drop_in_read_before_ours_is_overruled(self):
        self.write(f"{self.journald}/10-size.conf", "[Journal]\nSystemMaxUse=500M\n")
        self.config('journal_max_use = "2G"')
        self.assertEqual(self.tool("check").returncode, 1)
        self.tool("apply", "--yes")
        self.assertEqual(self.tool("check").returncode, 0)

    def restarts(self):
        return self.calls().count("systemctl restart systemd-journald")

    def changed_ns(self):
        return max(os.stat(p).st_ctime_ns for p in (self.ours, self.journald))

    def test_journald_has_to_restart_to_read_it(self):
        self.config('journal_max_use = "2G"')
        self.tool("apply", "--yes")
        self.write(f"{self.d}/started", systemd_time(time.time_ns() - 3600 * 10**9))
        self.assertIn("journald started before its settings last changed", self.line("journal"))
        self.tool("apply", "--yes")
        self.assertEqual(self.restarts(), 2)
        self.assertEqual(self.tool("check").returncode, 0)

    def test_a_change_in_the_same_second_counts(self):
        self.config('journal_max_use = "2G"')
        self.tool("apply", "--yes")
        changed = self.changed_ns()
        self.write(f"{self.d}/started", systemd_time(changed - 1000))          # a microsecond before
        self.assertEqual(self.tool("check").returncode, 1)
        self.write(f"{self.d}/started", systemd_time(changed + 1000))          # a microsecond after
        self.assertEqual(self.tool("check").returncode, 0)

    def test_removing_a_folder_of_overrides_restarts_journald(self):
        """The same with a whole drop-in folder elsewhere (as /run/systemd/journald.conf.d) taken away:
        its own time goes with it, so the files item marks journald's settings as changed."""
        run = f"{self.d}/run/journald.conf.d"
        self.write(self.ours, "# Managed by hb-harden from hb.toml (harden.journal_max_use).\n[Journal]\nSystemMaxUse=2G\n")
        self.write(f"{run}/99-size.conf", "[Journal]\nSystemMaxUse=500M\n")   # sorts after 90-hb.conf
        self.write(f"{self.d}/started", systemd_time(time.time_ns() + 10**6))
        self.config('journal_max_use = "2G"', f'remove_files = ["{run}"]')
        self.assertIn(f"SystemMaxUse=500M ({run}/99-size.conf) → 2G", self.line("journal"))
        r = self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(run), r.stdout + r.stderr)
        self.assertEqual(self.restarts(), 1)
        self.assertEqual(self.tool("check").returncode, 0)

    def test_removing_an_override_restarts_journald(self):
        """hb's file already says 2G, but journald started while a later size.conf said 500M:
        taking size.conf away has to restart journald, though hb's own file doesn't change."""
        size = f"{self.journald}/size.conf"
        self.write(self.ours, "# Managed by hb-harden from hb.toml (harden.journal_max_use).\n[Journal]\nSystemMaxUse=2G\n")
        self.write(size, "[Journal]\nSystemMaxUse=500M\n")
        self.write(f"{self.d}/started", systemd_time(time.time_ns() + 10**6))  # after both were written
        self.config('journal_max_use = "2G"', f'remove_files = ["{size}"]')
        r = self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(size), r.stdout + r.stderr)
        self.assertEqual(self.restarts(), 1)
        self.assertEqual(self.tool("check").returncode, 0)

    def test_journal_takes_a_size(self):
        self.config('journal_max_use = "lots"')
        self.assertEqual(self.tool("check").returncode, 2)
        self.config("")
        self.assertIn("not managed", self.line("journal"))


if __name__ == "__main__":
    unittest.main()
