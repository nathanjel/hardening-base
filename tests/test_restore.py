"""hb-restore: the drill against a real restic repository in a temp folder, and getting files back."""
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

restore = load_tool("restore")
HAVE_RESTIC = shutil.which("restic") is not None


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


@unittest.skipUnless(HAVE_RESTIC, "restic not installed")
class DrillTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.tree = os.path.join(self.d, "tree")
        for i in range(30):
            write(os.path.join(self.tree, "home", f"f{i:02}.txt"), f"file {i}\n".encode() * (i + 1))
        write(os.path.join(self.tree, "etc", "hb.toml"), b"[backup]\n")
        write(os.path.join(self.tree, "state", "packages.txt"), b"restic\nwireguard-tools\n")
        write(os.path.join(self.tree, "big.bin"), os.urandom(3 * 10**6))
        write(os.path.join(self.tree, "empty"), b"")
        os.symlink("hb.toml", os.path.join(self.tree, "etc", "link"))
        pw = os.path.join(self.d, "pw")
        write(pw, b"test password\n")
        env = {"RESTIC_REPOSITORY": os.path.join(self.d, "repo"), "RESTIC_PASSWORD_FILE": pw,
               "RESTIC_CACHE_DIR": os.path.join(self.d, "cache")}
        for k, v in env.items():
            self.addCleanup(os.environ.pop, k, None)
            os.environ[k] = v
        subprocess.run(["restic", "init", "-q"], check=True, capture_output=True)
        subprocess.run(["restic", "backup", "-q", "--host", "box", "--tag", "hb", self.tree], check=True,
                       capture_output=True)
        self.addCleanup(setattr, restore.restic, "COMMAND", restore.restic.COMMAND)
        restore.restic.COMMAND = ["restic"]
        for name, value in (("DRILL_DIR", self.d), ("GET_DIR", self.d)):
            self.addCleanup(setattr, restore, name, getattr(restore, name))
            setattr(restore, name, value)
        notes = []
        self.addCleanup(setattr, restore.util, "notify", restore.util.notify)
        restore.util.notify = lambda *a: notes.append(a)
        self.notes = notes

    def cfg(self, **over):
        r = {"sample_files": 1000, "max_file_mb": 1, "must_have": [os.path.join(self.tree, "etc", "hb.toml"),
                                                                  os.path.join(self.tree, "state")],
             "drill_days": 92}
        r.update(over)
        return {"restore": r}

    def test_everything_matches(self):
        r = restore.drill(self.cfg(), host="box")
        self.assertTrue(r["ok"], r)
        # 30 + hb.toml + packages.txt; big.bin is over max_file_mb, empty files aren't picked
        self.assertEqual((r["files_in_snapshot"], r["sampled"], r["matched"], r["changed"]), (32, 32, 32, 0))
        self.assertEqual(restore.verdict(self.cfg())[0], 0)
        self.assertFalse([n for n in os.listdir(self.d) if n.startswith("hb-drill-")], "temp folder left behind")

    def test_sample_is_bounded_and_must_have_always_in(self):
        r = restore.drill(self.cfg(sample_files=5), host="box", rng=random.Random(1))
        self.assertTrue(r["ok"], r)
        self.assertLessEqual(r["sampled"], 7)
        self.assertGreaterEqual(r["sampled"], 5)

    def test_silent_corruption_is_caught(self):
        # same size, same mtime, different bytes: only a byte comparison notices
        path = os.path.join(self.tree, "home", "f03.txt")
        st = os.stat(path)
        with open(path, "r+b") as f:
            f.write(b"F")
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        r = restore.drill(self.cfg(), host="box")
        self.assertFalse(r["ok"])
        self.assertEqual(r["mismatched"], [path])
        rc, line = restore.verdict(self.cfg())
        self.assertEqual(rc, 2)
        self.assertIn("1 restored files differ", line)

    def test_changed_files_are_counted_not_compared(self):
        write(os.path.join(self.tree, "home", "f04.txt"), b"edited after the backup\n")
        os.remove(os.path.join(self.tree, "home", "f05.txt"))
        r = restore.drill(self.cfg(), host="box")
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["matched"], r["changed"]), (30, 2))

    def test_missing_must_have_fails(self):
        r = restore.drill(self.cfg(must_have=[os.path.join(self.tree, "nowhere")]), host="box")
        self.assertFalse(r["ok"])
        self.assertEqual(r["missing"], [os.path.join(self.tree, "nowhere")])

    def test_no_snapshot_for_host_fails_cleanly(self):
        r = restore.drill(self.cfg(), host="other")
        self.assertFalse(r["ok"])
        self.assertIn("no snapshots yet", r["errors"][0])

    def test_do_drill_notifies_once_per_outcome(self):
        restore.do_drill(self.cfg(), "box")
        self.assertEqual([n[:2] for n in self.notes], [("info", "restore.drill")])

    def test_get_into_a_folder(self):
        os.remove(os.path.join(self.tree, "home", "f07.txt"))
        to = os.path.join(self.d, "out")
        self.assertEqual(restore.do_get([os.path.join(self.tree, "home", "f07.txt")], "latest", to, "box"), 0)
        with open(to + os.path.join(self.tree, "home", "f07.txt"), "rb") as f:
            self.assertEqual(f.read(), b"file 7\n" * 8)
        self.assertFalse(os.path.exists(to + os.path.join(self.tree, "home", "f08.txt")))

    def test_get_by_default_makes_a_new_private_folder(self):
        path = os.path.join(self.tree, "home", "f07.txt")
        made = []
        for _ in range(2):
            before = set(os.listdir(self.d))
            self.assertEqual(restore.do_get([path], "latest", None, "box"), 0)
            made += sorted(set(os.listdir(self.d)) - before)
        self.assertEqual(len(set(made)), 2)                    # never a name someone could take first
        for name in made:
            self.assertTrue(name.startswith("hb-restore-"), name)
            folder = os.path.join(self.d, name)
            self.assertEqual(os.stat(folder).st_mode & 0o777, 0o700)
            self.assertTrue(os.path.exists(folder + path))

    def test_get_over_live_files_needs_a_yes(self):
        path = os.path.join(self.tree, "home", "f09.txt")
        write(path, b"newer\n")
        self.addCleanup(setattr, restore.util, "ask", restore.util.ask)
        restore.util.ask = lambda q: False
        self.assertEqual(restore.do_get([path], "latest", "/", "box"), 1)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"newer\n")


class HelpersTest(unittest.TestCase):
    def test_mtime_ns(self):
        self.assertEqual(restore.mtime_ns("2026-11-01T21:37:41.82057292+01:00"), 1793565461820572920)
        self.assertEqual(restore.mtime_ns("2026-11-01T20:37:41Z"), 1793565461 * 10**9)
        with self.assertRaises(ValueError):
            restore.mtime_ns("yesterday")

    def test_verdict_overdue_and_missing(self):
        temp_state(self)
        cfg = {"restore": {"drill_days": 92}}
        self.assertEqual(restore.verdict(cfg)[0], 1)
        restore.util.write_json(os.path.join(restore.util.state_dir("restore"), "drill.json"),
                                {"ts": int(time.time()) - 100 * 86400, "ok": True, "matched": 9})
        rc, line = restore.verdict(cfg)
        self.assertEqual(rc, 1)
        self.assertIn("100 days ago", line)
        self.assertEqual(restore.verdict(cfg, now=time.time() - 95 * 86400)[0], 0)


if __name__ == "__main__":
    unittest.main()
