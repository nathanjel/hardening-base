"""hb-disk: the walk (sizes, hard links, mounts, skips), the report's tree, growth and
untouched folders, and the stored scan behind the check."""
import contextlib
import io
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

disk = load_tool("disk")
GB = disk.GB
DAY = disk.DAY
NOW = 1_800_000_000


def cfg(**over):
    d = {"show_gb": 2, "stale_roots": ["/home", "/srv"], "stale_days": 30, "stale_gb": 1,
         "stale_ignore": [], "skip": []}
    d.update(over)
    return {"disk": d, "snapshot": {"dir": "/nonexistent-snapshots"}}


def write(path, size, mtime=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"x" * size)
    if mtime:
        os.utime(path, (mtime, mtime))


def blocks(path):
    return os.lstat(path).st_blocks * 512


class WalkTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_sizes_hardlinks_symlinks_and_newest_file(self):
        a, b = os.path.join(self.d, "p", "a"), os.path.join(self.d, "p", "q", "b")
        write(a, 100_000, mtime=NOW - 50 * DAY)
        write(b, 300_000, mtime=NOW - 40 * DAY)
        os.link(b, os.path.join(self.d, "p", "q", "b-again"))          # counted once
        os.symlink(b, os.path.join(self.d, "p", "link"))               # a link, not the file
        os.utime(os.path.join(self.d, "p", "q"), (NOW, NOW))           # folder mtimes don't count
        r = disk.walk(self.d, keep=0)
        p = os.path.join(self.d, "p")
        link = blocks(os.path.join(self.d, "p", "link"))
        self.assertEqual(r["dirs"][p][0], blocks(a) + blocks(b) + link)
        self.assertEqual(r["dirs"][p][1], 3)
        self.assertEqual(r["dirs"][p][2], max(NOW - 40 * DAY, int(os.lstat(os.path.join(self.d, "p", "link")).st_mtime)))
        self.assertEqual(r["dirs"][os.path.join(p, "q")][2], NOW - 40 * DAY)
        self.assertEqual(r["dirs"][self.d][0], r["dirs"][p][0])

    def test_keep_skip_rules_and_unreadable(self):
        write(os.path.join(self.d, "big", "f"), 200_000)
        write(os.path.join(self.d, "small", "f"), 10)
        write(os.path.join(self.d, "skipped", "f"), 200_000)
        write(os.path.join(self.d, "mount", "f"), 200_000)
        r = disk.walk(self.d, skip=[os.path.join(self.d, "skipped")],
                      rules={os.path.join(self.d, "mount"): False}, keep=100_000)
        self.assertEqual(sorted(r["dirs"]), [self.d, os.path.join(self.d, "big")])
        self.assertEqual(r["dirs"][self.d][1], 2)
        if os.geteuid() != 0:
            locked = os.path.join(self.d, "locked")
            os.makedirs(locked)
            os.chmod(locked, 0)
            self.addCleanup(os.chmod, locked, 0o700)
            self.assertEqual(disk.walk(self.d)["unreadable"], 1)


class MountTest(unittest.TestCase):
    INFO = "\n".join([
        "22 1 0:37 / / rw,relatime shared:1 - btrfs /dev/md3 rw",
        "60 22 9:2 / /boot rw shared:30 - btrfs /dev/md2 rw",
        "61 60 9:1 / /boot/efi rw shared:31 - vfat /dev/md1 rw",
        "70 22 0:50 / /mnt/back\\040up rw - nfs host:/export rw",
        "80 22 0:51 / /tmp rw - tmpfs tmpfs rw",
        "90 22 7:1 / /var/lib/snapd/snap/core22/1 ro - squashfs /dev/loop1 ro",
        "91 22 0:37 /srv/data /mnt/data rw - btrfs /dev/md3 rw",
        "92 22 8:1 /sub /mnt/sub rw - ext4 /dev/sdb1 rw",
    ])

    def test_parse(self):
        m = disk.mounts(self.INFO)
        self.assertIn(("/mnt/back up", "nfs", "/"), m)
        self.assertEqual(len(m), 8)

    def test_walkable(self):
        self.assertTrue(disk.walkable("btrfs", "/", 0))
        self.assertTrue(disk.walkable("vfat", "/", 0))
        self.assertTrue(disk.walkable("btrfs", "/home", 256))      # a subvolume mounted on its own
        self.assertFalse(disk.walkable("btrfs", "/srv/data", 300))  # a folder bind-mounted
        self.assertFalse(disk.walkable("ext4", "/sub", 2))
        for fs in ("nfs", "tmpfs", "squashfs", "overlay"):
            self.assertFalse(disk.walkable(fs, "/", 0))


def scan(dirs, top="/", ts=NOW, keep=0):
    return {"dirs": dirs, "top": top, "ts": ts, "secs": 3.0, "unreadable": 0, "keep": keep}


class ReportTest(unittest.TestCase):
    DIRS = {
        "/": [100 * GB, 1000, NOW],
        "/home": [80 * GB, 800, NOW],
        "/home/al": [79 * GB, 790, NOW],
        "/home/al/old": [30 * GB, 300, NOW - 60 * DAY],
        "/home/al/old/inner": [29 * GB, 290, NOW - 61 * DAY],
        "/home/al/work": [40 * GB, 400, NOW - DAY],
        "/home/al/work/build": [5 * GB, 50, NOW - 45 * DAY],
        "/home/al/tiny-stale": [GB // 2, 5, NOW - 90 * DAY],
        "/srv": [10 * GB, 100, NOW],
        "/srv/keep": [9 * GB, 90, NOW - 100 * DAY],
        "/var": [9 * GB, 90, NOW - 200 * DAY],
    }

    def test_tree_joins_single_child_chains(self):
        lines = disk.tree(self.DIRS, "/", 2 * GB)
        names = [line.split(None, 2)[2] for line in lines]
        self.assertEqual(names[0], "/")
        self.assertIn("home/al", [n.strip() for n in names])         # /home is all /home/al
        self.assertIn("old/inner", [n.strip() for n in names])       # and old is all inner
        self.assertNotIn("tiny-stale", " ".join(names))              # under 2 GB
        work = next(line for line in lines if line.strip().endswith("work"))
        build = next(line for line in lines if line.strip().endswith("build"))
        self.assertGreater(len(build) - len(build.lstrip(" 0123456789.GB")),
                           len(work) - len(work.lstrip(" 0123456789.GB")))

    def test_stale_outermost_rooted_and_ignored(self):
        s = disk.stale(self.DIRS, cfg(), now=NOW)
        self.assertEqual([p for p, _, _ in s], ["/home/al/old", "/srv/keep", "/home/al/work/build"])
        s = disk.stale(self.DIRS, cfg(stale_ignore=["/srv"], stale_days=50), now=NOW)
        self.assertEqual([p for p, _, _ in s], ["/home/al/old"])

    def test_growth_names_the_place_that_grew(self):
        prev = {"/": [90 * GB, 0, 0], "/home": [70 * GB, 0, 0], "/home/al": [69 * GB, 0, 0],
                "/home/al/work": [31 * GB, 0, 0], "/home/al/old": [30 * GB, 0, 0],
                "/home/al/old/inner": [29 * GB, 0, 0], "/srv": [10 * GB, 0, 0], "/srv/keep": [9 * GB, 0, 0],
                "/var": [9 * GB, 0, 0]}
        g = disk.growth(self.DIRS, prev)
        # work grew 9 GB; build is new (5 GB, too little of it to stand for work); the parents
        # of work grew by the same 9 GB, so work names it
        self.assertEqual(g, [("/home/al/work", 9 * GB), ("/home/al/work/build", 5 * GB)])

    def test_report_sections(self):
        prev = scan({p: [v[0] - (GB if p in ("/", "/var") else 0)] + v[1:] for p, v in self.DIRS.items()},
                    ts=NOW - 7 * DAY)
        text = "\n".join(disk.report(scan(self.DIRS), cfg(), prev, now=NOW))
        self.assertIn("Biggest folders (2.0 GB or more)", text)
        self.assertIn("+1.0 GB in all", text)
        self.assertIn("+  1.0 GB  /var", text)
        self.assertIn("/home/al/old", text.split("Untouched")[1])


class StoredScanTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.tree = tempfile.mkdtemp()
        write(os.path.join(self.tree, "home", "al", "f"), 50_000, mtime=time.time() - 90 * DAY)
        orig = disk.scan_box
        self.addCleanup(setattr, disk, "scan_box", orig)

        def fake_box(c, progress=None):
            r = disk.walk(self.tree, keep=0)
            r.update(top=self.tree, ts=int(time.time()), secs=0.1, keep=0)
            return r
        disk.scan_box = fake_box
        self.addCleanup(setattr, disk.os, "geteuid", disk.os.geteuid)
        disk.os.geteuid = lambda: 0

    def test_scan_keeps_last_and_prev_and_check_reads_it(self):
        c = cfg(stale_roots=[self.tree], stale_gb=0.00001)
        self.assertEqual(disk.verdict(c), (0, "ok: no scan yet (hb-disk.timer runs one on Sundays)"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(disk.do_scan(c, quiet=True), 0)
        rc, line = disk.verdict(c)
        self.assertEqual(rc, 0)
        self.assertIn("1 folder untouched 30+ days", line)
        self.assertNotIn(self.tree, line)                            # counts only, never names
        write(os.path.join(self.tree, "home", "al", "g"), 50_000)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(disk.do_scan(c, quiet=True), 0)
        rc, line = disk.verdict(c)
        self.assertIn("since", line)
        self.assertNotIn("untouched", line)                          # g is new
        self.assertTrue(os.path.exists(os.path.join(disk.ddir(), "prev.json")))
        rc, line = disk.verdict(c, now=time.time() + 20 * DAY)
        self.assertEqual(rc, 1)
        self.assertIn("20 days ago", line)

    def test_folder_scan_keeps_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(disk.do_scan(cfg(), path=self.tree, quiet=True), 0)
        self.assertIn(f"Scan of {self.tree}", out.getvalue())
        self.assertFalse(os.path.exists(os.path.join(disk.ddir(), "last.json")))


if __name__ == "__main__":
    unittest.main()
