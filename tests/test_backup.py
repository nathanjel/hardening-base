"""hb-backup's coverage report: missing paths, live reads, mounts and subvolumes left out.

Runs tools/hb-backup as root of a user and mount namespace, with restic and btrfs faked and hb's
own dispatcher (the state dump) replaced, so nothing outside a temp folder is read or written.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

RESTIC = """#!/bin/sh
echo "$*" >> {log}
exit 0
"""
# `btrfs subvolume list -o /` names one subvolume below a backed-up path; a snapshot is just "made"
BTRFS = """#!/bin/sh
case "$1 $2" in
  "subvolume list") echo "ID 300 gen 9 top level 5 path {subvol}" ;;
esac
exit 0
"""


def can_namespace():
    return shutil.which("unshare") is not None and subprocess.run(
        ["unshare", "-rm", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(can_namespace(), "needs unprivileged user and mount namespaces")
class CoverageTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for sub in ("a/inner", "a/subvol", "excl/inner2", "repo", "state", "cache", "snaps", "bin", "root/tools"):
            os.makedirs(f"{d}/{sub}")
        open(f"{d}/repo/config", "w").close()
        self.log = f"{d}/restic.log"
        for name, text in (("restic", RESTIC.format(log=self.log)),
                           ("btrfs", BTRFS.format(subvol=f"{d}/a/subvol".lstrip("/")))):
            with open(f"{d}/bin/{name}", "w") as f:
                f.write(text)
            os.chmod(f"{d}/bin/{name}", 0o755)
        with open(f"{d}/root/hb", "w") as f:                 # the state dump: nothing to do here
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(f"{d}/root/hb", 0o755)
        os.symlink(os.path.join(REPO, "tools", "hb-config"), f"{d}/root/tools/hb-config")

    def config(self, paths, exclude=()):
        with open(f"{self.d}/hb.toml", "w") as f:
            f.write(f'[backup]\nrepo = "{self.d}/repo"\npassword_file = "{self.d}/pw"\n'
                    f"paths = {list(paths)!r}\nexclude = {list(exclude)!r}\n"
                    f'[snapshot]\ndir = "{self.d}/snaps"\n'.replace("'", '"'))

    def tool(self, verb, mounts=True):
        d = self.d
        env = {**os.environ, "HB_CONFIG": f"{d}/hb.toml", "HB_STATE": f"{d}/state", "HB_CACHE": f"{d}/cache",
               "HB_ROOT": f"{d}/root", "PATH": f"{d}/bin" + os.pathsep + os.environ["PATH"]}
        # two bind mounts stand for mounts below the paths (a bind of a btrfs folder shows as btrfs)
        binds = (f"mount --bind {REPO}/tests {d}/a/inner && mount --bind {REPO}/docs {d}/excl/inner2 && "
                 if mounts else "")
        return subprocess.run(["unshare", "-rm", "sh", "-c", f"{binds}exec {REPO}/tools/hb-backup {verb}"],
                              env=env, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)

    def coverage(self):
        with open(f"{self.d}/state/hb-backup/last-coverage") as f:
            return sorted(f.read().splitlines())

    def test_run_records_what_it_covered_and_check_warns(self):
        d = self.d
        self.config([f"{d}/a", f"{d}/missing", f"{d}/excl"], exclude=[f"{d}/excl/inner2"])
        r = self.tool("run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.coverage(), sorted([
            f"live {d}/a", f"missing {d}/missing", f"live {d}/excl",
            f"left-out {d}/a/inner", f"left-out {d}/a/subvol", f"excluded {d}/excl/inner2"]))
        self.assertIn(f"not in the backup: {d}/a/inner", r.stdout)       # the run's log goes through tee
        with open(self.log) as f:
            backup = next(l for l in f if l.split()[2:3] == ["backup"])
        self.assertIn(f"{d}/a", backup.split())
        self.assertNotIn(f"{d}/missing", backup.split())
        r = self.tool("check", mounts=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("1 of backup.paths don't exist (hb backup status)", r.stdout)
        r = self.tool("status", mounts=False)
        self.assertIn("MISSING:", r.stdout)
        self.assertIn(f"{d}/a/inner, {d}/a/subvol", r.stdout)

    def test_left_out_mounts_warn_until_excluded(self):
        d = self.d
        self.config([f"{d}/a"])
        self.assertEqual(self.tool("run").returncode, 0)
        r = self.tool("check", mounts=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("left out 2 mounts or subvolumes below backup.paths", r.stdout)
        self.config([f"{d}/a"], exclude=[f"{d}/a/inner", f"{d}/a/subvol"])
        self.assertEqual(self.tool("run").returncode, 0)
        r = self.tool("check", mounts=False)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(r.stdout.startswith("ok: last backup 0 h ago"), r.stdout)


if __name__ == "__main__":
    unittest.main()
