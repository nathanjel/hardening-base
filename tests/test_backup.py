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

# restic records its arguments, and what it sees in each folder it is given
RESTIC = """#!/bin/sh
echo "$*" >> {log}
for a in "$@"; do [ -d "$a" ] && echo "SEES $a: $(ls -A "$a" | tr '\\n' ' ')" >> {log}; done
exit 0
"""
# `btrfs subvolume list -o /` names subvolumes below a backed-up path (or fails, with {fail}); a
# snapshot is a folder with a copy of the paths' marker files, made from {seed}
BTRFS = """#!/bin/sh
case "$1 $2" in
  "subvolume list") [ -e {fail} ] && {{ echo "ERROR: can't access '/'" >&2; exit 1; }}
                    echo "ID 300 gen 9 top level 5 path {subvol}"
                    echo "ID 301 gen 9 top level 5 path {subvol2}" ;;
  "subvolume snapshot") mkdir -p "$5" && [ -d {seed} ] && cp -a {seed}/. "$5" ;;
  "subvolume delete") rm -rf "$3" ;;
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
        self.flag, self.seed = f"{d}/btrfs-fails", f"{d}/seed"
        os.makedirs(f"{d}/a/data archive")
        for name, text in (("restic", RESTIC.format(log=self.log)),
                           ("btrfs", BTRFS.format(subvol=f"{d}/a/subvol".lstrip("/"), fail=self.flag, seed=self.seed,
                                                  subvol2=f"{d}/a/data archive".lstrip("/")))):
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

    def tool(self, verb, mounts=True, extra=""):
        d = self.d
        env = {**os.environ, "HB_CONFIG": f"{d}/hb.toml", "HB_STATE": f"{d}/state", "HB_CACHE": f"{d}/cache",
               "HB_ROOT": f"{d}/root", "PATH": f"{d}/bin" + os.pathsep + os.environ["PATH"]}
        # two bind mounts stand for mounts below the paths (a bind of a btrfs folder shows as btrfs)
        binds = (f"mount --bind {REPO}/tests {d}/a/inner && mount --bind {REPO}/docs {d}/excl/inner2 && "
                 if mounts else "") + extra
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
            f"left-out {d}/a/inner", f"left-out {d}/a/subvol", f"left-out {d}/a/data archive",
            f"excluded {d}/excl/inner2"]))
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
        self.assertIn("left out 3 mounts or subvolumes below backup.paths", r.stdout)
        self.config([f"{d}/a"], exclude=[f"{d}/a/inner", f"{d}/a/subvol", f"{d}/a/data archive"])
        self.assertEqual(self.tool("run").returncode, 0)
        r = self.tool("check", mounts=False)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(r.stdout.startswith("ok: last backup 0 h ago"), r.stdout)


    def test_a_failed_lookup_is_unknown_not_ok(self):
        d = self.d
        self.config([f"{d}/a"], exclude=[f"{d}/a/inner", f"{d}/a/subvol", f"{d}/a/data archive"])
        open(self.flag, "w").close()
        self.assertEqual(self.tool("run").returncode, 0)                 # the backup itself still runs
        self.assertIn("unknown btrfs subvolume list: ERROR: can't access '/'", self.coverage())
        r = self.tool("check", mounts=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("couldn't tell what it left out", r.stdout)
        with open(f"{d}/bin/findmnt", "w") as f:                          # and the mount table
            f.write("#!/bin/sh\necho 'findmnt: cannot open /proc/self/mountinfo' >&2\nexit 1\n")
        os.chmod(f"{d}/bin/findmnt", 0o755)
        os.unlink(self.flag)
        self.assertEqual(self.tool("run", mounts=False).returncode, 0)
        self.assertIn("unknown findmnt: findmnt: cannot open /proc/self/mountinfo", self.coverage())

    def test_a_listed_child_mount_is_covered_and_a_spaced_name_is_whole(self):
        d = self.d
        os.makedirs(f"{d}/a/my mount")
        self.config([f"{d}/a", f"{d}/a/inner"], exclude=[f"{d}/a/subvol", f"{d}/a/data archive"])
        r = self.tool("run", extra=f"mount --bind {REPO}/lib '{d}/a/my mount' && ")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cov = self.coverage()
        self.assertIn(f"live {d}/a/inner", cov)
        self.assertNotIn(f"left-out {d}/a/inner", cov)                    # listed: backed up on its own
        self.assertIn(f"left-out {d}/a/my mount", cov)                    # findmnt's \x20, decoded


def root_fs_dir():
    """A temp folder on the root filesystem (where the snapshot's copies go), or None."""
    base = os.path.expanduser("~/.cache")
    try:
        os.makedirs(base, exist_ok=True)
        return tempfile.mkdtemp(prefix="hb-test-backup-", dir=base) if os.stat(base).st_dev == os.stat("/").st_dev \
            else None
    except OSError:
        return None


@unittest.skipUnless(can_namespace(), "needs unprivileged user and mount namespaces")
class SnapshotReadTest(CoverageTest.__base__):
    """What restic actually sees: the snapshot's copy over a path, but never over a listed mount below it."""

    def setUp(self):
        self.h = root_fs_dir()
        if not self.h:
            self.skipTest("no folder on the root filesystem to test with")
        self.addCleanup(shutil.rmtree, self.h, True)
        CoverageTest.setUp(self)
        h = self.h
        for sub in ("b", "a/inner"):
            os.makedirs(f"{h}/{sub}")
            open(f"{h}/{sub}/live-file", "w").close()
        for sub in ("b", "a", "a/inner"):                                   # what the snapshot holds there
            os.makedirs(f"{self.seed}{h}/{sub}", exist_ok=True)
            open(f"{self.seed}{h}/{sub}/snapshot-file", "w").close()

    config = CoverageTest.config
    tool = CoverageTest.tool
    coverage = CoverageTest.coverage

    def sees(self, path):
        with open(self.log) as f:
            return next(l for l in f if l.startswith(f"SEES {path}:")).split(":", 1)[1].split()

    def test_the_snapshot_is_read_but_never_hides_a_listed_mount(self):
        h = self.h
        self.config([f"{h}/b", f"{h}/a", f"{h}/a/inner"])
        r = self.tool("run", mounts=False, extra=f"mount --bind {REPO}/tests {h}/a/inner && ")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.sees(f"{h}/b"), ["snapshot-file"])            # read from the snapshot
        self.assertIn("test_backup.py", self.sees(f"{h}/a/inner"))          # the live mount, not an empty copy
        cov = self.coverage()
        self.assertIn(f"snapshot {h}/b", cov)
        self.assertIn(f"live {h}/a", cov)                                   # said as it is: read live
        self.assertIn(f"live {h}/a/inner", cov)

if __name__ == "__main__":
    unittest.main()
