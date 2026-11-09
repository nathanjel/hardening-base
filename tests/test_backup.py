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
                    p="$(cat {prefix} 2>/dev/null)"         # / as a subvolume: paths carry its name
                    echo "ID 300 gen 9 top level 5 path ${{p}}{subvol}"
                    echo "ID 301 gen 9 top level 5 path ${{p}}{subvol2}" ;;
  "subvolume snapshot") mkdir -p "$5" && [ -d {seed} ] && cp -a {seed}/. "$5" ;;
  "subvolume delete") rm -rf "$3" ;;
esac
exit 0
"""
# findmnt as it is, except FSROOT of /, which can fail or name a root subvolume
FINDMNT = """#!/bin/sh
case "$*" in
  *FSROOT*) [ -e {fail} ] && {{ echo "findmnt: can't read /proc/self/mountinfo" >&2; exit 1; }}
            [ -e {answer} ] && {{ cat {answer}; exit 0; }} ;;
esac
exec {real} "$@"
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
        self.prefix, self.fsroot_fail, self.fsroot = f"{d}/subvol-prefix", f"{d}/fsroot-fails", f"{d}/fsroot"
        os.makedirs(f"{d}/a/data archive")
        for name, text in (("restic", RESTIC.format(log=self.log)),
                           ("btrfs", BTRFS.format(subvol=f"{d}/a/subvol".lstrip("/"), fail=self.flag, seed=self.seed,
                                                  subvol2=f"{d}/a/data archive".lstrip("/"), prefix=self.prefix)),
                           ("findmnt", FINDMNT.format(fail=self.fsroot_fail, answer=self.fsroot,
                                                      real=shutil.which("findmnt")))):
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

    def test_a_root_subvolume_prefix_is_taken_off(self):
        d = self.d
        with open(self.fsroot, "w") as f:
            f.write("/root\n")
        with open(self.prefix, "w") as f:
            f.write("root/")
        self.config([f"{d}/a"], exclude=[f"{d}/a/inner"])
        self.assertEqual(self.tool("run").returncode, 0)
        self.assertIn(f"left-out {d}/a/subvol", self.coverage())        # found through the prefix

    def test_a_failed_root_subvolume_lookup_is_unknown(self):
        d = self.d
        open(self.fsroot_fail, "w").close()                             # the mount table itself still reads
        with open(self.prefix, "w") as f:
            f.write("root/")
        self.config([f"{d}/a"], exclude=[f"{d}/a/inner"])
        self.assertEqual(self.tool("run").returncode, 0)
        cov = self.coverage()
        self.assertIn("unknown findmnt FSROOT of /: findmnt: can't read /proc/self/mountinfo", cov)
        self.assertNotIn(f"left-out {d}/a/inner", cov)                   # mounts were still checked
        r = self.tool("check", mounts=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("couldn't tell what it left out", r.stdout)

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

    def test_a_folder_inside_a_bind_mount_is_read_live(self):
        h = self.h
        os.makedirs(f"{h}/realsrc/sub")
        open(f"{h}/realsrc/sub/live-file", "w").close()
        os.makedirs(f"{h}/srv/sub")                                          # what lies under the mount
        os.makedirs(f"{self.seed}{h}/srv/sub", exist_ok=True)
        open(f"{self.seed}{h}/srv/sub/snapshot-file", "w").close()
        self.config([f"{h}/srv/sub"])
        r = self.tool("run", mounts=False, extra=f"mount --bind {h}/realsrc {h}/srv && ")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.sees(f"{h}/srv/sub"), ["live-file"])        # what is mounted there, not below it
        self.assertIn(f"live {h}/srv/sub", self.coverage())

# restic for a repository that isn't a folder: `cat config` exits with the code in {code} (restic's
# own: 10 no repository, 12 the password doesn't open it), saying why on stderr; the rest is logged
RESTIC_REMOTE = """#!/bin/sh
echo "$*" >> {log}
case "$*" in
  *"cat config"*) c="$(cat {code})"
                  [ "$c" = 0 ] || {{ echo "Fatal: reason $c"; echo "s3:https://example/bucket/hb"; }} >&2
                  exit "$c" ;;
esac
exit 0
"""


@unittest.skipUnless(can_namespace(), "needs unprivileged user and mount namespaces")
class RemoteRepoTest(CoverageTest.__base__):
    """S3 and the like: whether a repository is there is restic's to say, by its exit code; and the
    database dumps come before the backup."""

    def setUp(self):
        CoverageTest.setUp(self)
        d = self.d
        self.code = f"{d}/code"
        with open(f"{d}/bin/restic", "w") as f:
            f.write(RESTIC_REMOTE.format(log=self.log, code=self.code))
        with open(f"{d}/root/hb", "w") as f:                 # the dispatcher: records what it was asked
            f.write(f"#!/bin/sh\necho \"hb $*\" >> {self.log}\n")
        self.answer(0)

    tool = CoverageTest.tool

    def answer(self, code):
        with open(self.code, "w") as f:
            f.write(f"{code}\n")

    def config(self, extra=""):
        with open(f"{self.d}/hb.toml", "w") as f:
            f.write(f'[backup]\nrepo = "s3:https://s3.us-east-1.amazonaws.com/bucket/hb"\n'
                    f'password_file = "{self.d}/pw"\npaths = ["{self.d}/a"]\n{extra}'
                    f'[snapshot]\ndir = "{self.d}/snaps"\n')

    def logged(self):
        with open(self.log) as f:
            return [line.split() for line in f]

    def password(self):
        with open(f"{self.d}/pw", "w") as f:
            f.write("pw\n")

    def test_restic_says_whether_the_repository_is_there(self):
        self.config()
        r = self.tool("status", mounts=False)                     # restic would stop at the file
        self.assertIn(f"no password in {self.d}/pw: hb backup init makes the repository and it", r.stderr)
        self.password()
        for code, words in ((10, "no repository at s3:https://s3.us-east-1.amazonaws.com/bucket/hb yet: hb backup init"),
                            (12, f"the password in {self.d}/pw doesn't open the repository"),
                            (1, "can't open the repository at s3:https://s3.us-east-1.amazonaws.com/bucket/hb "
                                "(restic exit 1): Fatal: reason 1")):
            self.answer(code)
            r = self.tool("status", mounts=False)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn(words, r.stderr)
        self.answer(0)
        r = self.tool("status", mounts=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("snapshots", [w for line in self.logged() for w in line])

    def test_init_only_where_there_is_none(self):
        self.config()
        for code in (0, 12):
            self.answer(code)
            r = self.tool("init", mounts=False)
            self.assertEqual(r.returncode, 2)
            self.assertIn("a repository already exists at s3:", r.stderr)
        self.assertFalse(os.path.exists(f"{self.d}/pw"))          # no password made for a repository it can't open
        self.answer(1)
        r = self.tool("init", mounts=False)
        self.assertIn("can't tell whether there is a repository", r.stderr)
        self.answer(10)
        r = self.tool("init", mounts=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.getsize(f"{self.d}/pw") > 0)
        probe = next(l for l in self.logged() if "cat" in l)
        self.assertIn("--insecure-no-password", probe)            # asked without the password
        self.assertEqual(self.logged()[-1][2:], ["init"])

    def test_the_dumps_come_first_and_never_in_a_dry_run(self):
        rule = '{ images = ["postgres"], command = ["pg_dump"] }'
        self.config(f"dumps = [{rule}]\n")
        self.password()
        r = self.tool("run", mounts=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        steps = [l[1] if l[0] == "hb" else l[2] for l in self.logged() if l[0] == "hb" or l[2:3] == ["backup"]]
        self.assertEqual(steps, ["inventory", "dump", "backup"])
        os.unlink(self.log)
        r = self.tool("dry-run", mounts=False)
        self.assertIn("dry run: no database dumps", r.stderr)
        self.assertNotIn(["hb", "dump", "run"], self.logged())
        os.unlink(self.log)
        self.config()                                             # none configured: not asked at all
        self.tool("run", mounts=False)
        self.assertNotIn(["hb", "dump", "run"], self.logged())

    def test_a_failed_dump_never_stops_the_backup(self):
        self.config('dumps = [{ images = ["postgres"], command = ["pg_dump"] }]\n')
        self.password()
        with open(f"{self.d}/root/hb", "w") as f:
            f.write(f"#!/bin/sh\necho \"hb $*\" >> {self.log}\n[ \"$1\" = dump ] && exit 1\nexit 0\n")
        r = self.tool("run", mounts=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("database dumps incomplete (sudo hb dump status)", r.stderr)
        self.assertTrue(any(l[2:3] == ["backup"] for l in self.logged()))

    def test_a_pinned_restic_runs_only_as_that_version(self):
        self.config('restic_version = "9.9.9"\n')
        r = self.tool("run", mounts=False)
        self.assertEqual(r.returncode, 2)
        self.assertIn("restic 9.9.9 isn't at /usr/local/bin/restic (backup.restic_version): sudo hb install apply",
                      r.stderr)
        self.assertFalse(os.path.exists(self.log))                # the restic on PATH never ran


@unittest.skipUnless(can_namespace() and shutil.which("restic"), "needs restic and user namespaces")
class RealResticTest(unittest.TestCase):
    """The exit codes above, from restic itself, through a "local:" repository (not a plain folder, so
    the same way as S3)."""

    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(f"{d}/root/tools")
        with open(f"{d}/root/hb", "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(f"{d}/root/hb", 0o755)
        os.symlink(os.path.join(REPO, "tools", "hb-config"), f"{d}/root/tools/hb-config")
        with open(f"{d}/hb.toml", "w") as f:
            f.write(f'[backup]\nrepo = "local:{d}/repo"\npassword_file = "{d}/pw"\npaths = ["{d}/root"]\n')

    def tool(self, verb):
        d = self.d
        env = {**os.environ, "HB_CONFIG": f"{d}/hb.toml", "HB_STATE": f"{d}/state", "HB_CACHE": f"{d}/cache",
               "HB_ROOT": f"{d}/root"}
        return subprocess.run(["unshare", "-r", f"{REPO}/tools/hb-backup", *verb.split()], env=env,
                              capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)

    def test_init_once_then_the_password_opens_it(self):
        r = self.tool("status")
        self.assertIn(f"no password in {self.d}/pw", r.stderr)
        with open(f"{self.d}/pw", "w") as f:
            f.write("pw\n")
        r = self.tool("status")
        self.assertIn(f"no repository at local:{self.d}/repo yet: hb backup init", r.stderr)
        os.unlink(f"{self.d}/pw")
        r = self.tool("init")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.tool("init")
        self.assertEqual(r.returncode, 2)
        self.assertIn("a repository already exists", r.stderr)
        r = self.tool("status")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(f"{self.d}/pw", "w") as f:
            f.write("not-the-password\n")
        r = self.tool("status")
        self.assertIn(f"the password in {self.d}/pw doesn't open the repository", r.stderr)


if __name__ == "__main__":
    unittest.main()
