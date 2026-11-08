"""hb-install: which units it installs and which it removes."""
import glob
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

MARK = "# Managed by hb install"


def harness():
    """hb-install's functions without the root and config checks and the verb handling."""
    with open(os.path.join(REPO, "tools", "hb-install")) as f:
        lines = f.read().splitlines()
    out = []
    for line in lines:
        if line.startswith("source "):
            line = f'source "{os.path.join(REPO, "lib", "hb.sh")}"'
        if line in ("need_root", "need_config", 'item_main "$@"'):
            continue
        out.append(line)
    path = os.path.join(tempfile.mkdtemp(), "hb-install-functions")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    return path


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class UnitsTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.prefix, self.unitdir = os.path.join(d, "opt-hb"), os.path.join(d, "systemd")
        self.cfg = os.path.join(d, "hb.toml")
        write(self.cfg, "[install]\ntimers = []\n")
        self.ours = f"{MARK} from units/; changes made here are overwritten.\n[Unit]\nDescription=x\n"
        write(os.path.join(self.prefix, "units", "hb-status.service"), self.ours)
        write(os.path.join(self.prefix, "units", "hb-status.timer"), self.ours)

    def run_fn(self, fn):
        env = dict(os.environ, HB_CONFIG=self.cfg)
        p = subprocess.run(["bash", "-c", f'source "$1"; PREFIX="$2"; UNITDIR="$3"; {fn}', "_", harness(),
                            self.prefix, self.unitdir], env=env, capture_output=True, text=True)
        return p.returncode, p.stdout.strip(), p.stderr

    def test_other_tools_units_stay(self):
        write(os.path.join(self.unitdir, "hb-status.service"), self.ours)
        write(os.path.join(self.unitdir, "hb-status.timer"), self.ours)
        write(os.path.join(self.unitdir, "hb-webshell.service"),
              "# Managed by hb-webshell from hb.toml [webshell]; changes made here are overwritten.\n[Unit]\n")
        write(os.path.join(self.unitdir, "hb-handmade.service"), "[Unit]\nDescription=someone's own\n")
        self.assertEqual(self.run_fn("stale_units"), (0, "", ""))
        rc, out, _ = self.run_fn("chk_units")
        self.assertEqual((rc, out), (0, "2 units installed"))

    def test_ours_that_left_units_go(self):
        write(os.path.join(self.unitdir, "hb-status.service"), self.ours)
        write(os.path.join(self.unitdir, "hb-old.timer"), self.ours)
        write(os.path.join(self.unitdir, "hb-webshell.service"), "# Managed by hb-webshell\n")
        rc, out, _ = self.run_fn("chk_units")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "will install: hb-status.timer; will remove: hb-old.timer")

    def test_timers_are_read_when_checked_not_at_start(self):
        # apply copies the checkout's hb.toml in its config item; the timers item must see the new list
        script = f'source "$1"; printf \'[install]\\ntimers = ["hb-new"]\\n\' > "{self.cfg}"; load_timers; echo "${{TIMERS[*]}}"'
        p = subprocess.run(["bash", "-c", script, "_", harness()], env=dict(os.environ, HB_CONFIG=self.cfg),
                           capture_output=True, text=True)
        self.assertEqual(p.stdout.strip(), "hb-new", p.stderr)

    def test_every_unit_in_the_repo_is_marked(self):
        files = glob.glob(os.path.join(REPO, "units", "hb-*"))
        self.assertTrue(files)
        for path in files:
            with open(path) as f:
                self.assertTrue(f.readline().startswith(MARK), f"{os.path.basename(path)}: first line must be {MARK!r}")


def userns_ok():
    return subprocess.run(["unshare", "-r", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(userns_ok(), "needs unprivileged user namespaces (unshare -r)")
class EtcTest(unittest.TestCase):
    """Everything in /etc/hb is root's alone: a token placed by hand with mode 644 gets tightened."""

    def test_loose_files_are_found_and_tightened(self):
        d = tempfile.mkdtemp()
        etc, src = os.path.join(d, "etc-hb"), os.path.join(d, "checkout")
        write(os.path.join(src, "hb.toml"), "[install]\ntimers = []\n")
        write(os.path.join(etc, "hb.toml"), "[install]\ntimers = []\n")
        write(os.path.join(etc, "secrets", "supervoip-token"), "t0ken\n")
        os.chmod(etc, 0o700)
        os.chmod(os.path.join(etc, "hb.toml"), 0o600)
        os.chmod(os.path.join(etc, "secrets"), 0o755)
        os.chmod(os.path.join(etc, "secrets", "supervoip-token"), 0o644)     # as `sudo tee` leaves it
        script = (f'source "$1"; ETC="$2"; SRC="$3"; chk_config; echo "rc=$?"; fix_config; '
                  f'chk_config; echo "rc=$?"; stat -c "%a %n" "$2/secrets" "$2/secrets/supervoip-token"')
        p = subprocess.run(["unshare", "-r", "bash", "-c", script, "_", harness(), etc, src],
                           env=dict(os.environ, HB_CONFIG=os.path.join(etc, "hb.toml")), capture_output=True, text=True)
        lines = p.stdout.splitlines()
        self.assertEqual(lines[0], f"only root may read what is in {etc}; will tighten: "
                                   f"{etc}/secrets {etc}/secrets/supervoip-token", p.stderr)
        self.assertEqual(lines[1:4], ["rc=1", etc + "/hb.toml", "rc=0"])
        self.assertEqual(lines[4:], [f"700 {etc}/secrets", f"600 {etc}/secrets/supervoip-token"])


if __name__ == "__main__":
    unittest.main()
