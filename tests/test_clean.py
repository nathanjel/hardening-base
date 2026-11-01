"""hb-clean: which projects and caches count as idle, and what may be removed."""
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state  # noqa: E402

clean = load_tool("clean")
OLD = time.time() - 40 * 86400


def cfg(root, **over):
    c = {"project_roots": [root], "users": [], "idle_days": 14, "venv_idle_days": 90,
         "build_dirs": ["target", "build", "__pycache__", "cmake-build-*", "node_modules"],
         "cache_idle_days": 30, "docker": False}
    c.update(over)
    return c


def write(path, text="x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def age_tree(path, when=OLD):
    for root, dirs, files in os.walk(path):
        for n in dirs + files:
            os.utime(os.path.join(root, n), (when, when), follow_symlinks=False)
    os.utime(path, (when, when))


def make_repo(path, ignore, files):
    os.makedirs(path)
    write(os.path.join(path, ".gitignore"), "\n".join(ignore) + "\n")
    for rel, text in files.items():
        write(os.path.join(path, rel), text)
    subprocess.run(["git", "init", "-q", path], check=True)
    subprocess.run(["git", "-C", path, "add", "-A"], check=True)


class ProjectsTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def plan(self, **over):
        actions, notes = clean.plan_projects(cfg(self.root, **over), time.time())
        return {os.path.basename(a.desc.split(":")[0]): a for a in actions}, notes

    def test_idle_repo_loses_only_ignored_build_folders(self):
        repo = os.path.join(self.root, "idle")
        make_repo(repo, ["target/", "build/", "data/", ".env*", "*.log"], {
            "src/main.rs": "fn main(){}",
            "target/debug/app": "binary",
            "data/build/keep": "precious",       # inside an ignored data/ folder
            "pkg/data/build/keep": "precious",   # data/ anywhere in the path
            ".env.build/x": "secret",
            "run.log": "log",
        })
        age_tree(repo)
        actions, _ = self.plan()
        self.assertEqual(list(actions), ["idle"])
        a = actions["idle"]
        self.assertIn("delete target", a.desc)
        self.assertGreater(a.size, 0)
        a.fn()
        self.assertFalse(os.path.exists(os.path.join(repo, "target")))
        for kept in ("src/main.rs", "data/build/keep", "pkg/data/build/keep", ".env.build/x", "run.log"):
            self.assertTrue(os.path.exists(os.path.join(repo, kept)), kept)

    def test_active_repo_is_left_alone(self):
        repo = os.path.join(self.root, "busy")
        make_repo(repo, ["target/"], {"a.py": "1", "target/x": "y"})
        age_tree(repo)
        os.utime(os.path.join(repo, "a.py"))  # edited just now
        self.assertEqual(self.plan()[0], {})

    def test_build_output_alone_does_not_count_as_activity(self):
        repo = os.path.join(self.root, "built")
        make_repo(repo, ["build/"], {"a.c": "int x;", "build/a.o": "obj"})
        age_tree(repo)
        os.utime(os.path.join(repo, "build", "a.o"))  # rebuilt recently, sources untouched
        self.assertIn("built", self.plan()[0])

    def test_make_clean_preferred_and_venv_waits_longer(self):
        repo = os.path.join(self.root, "mk")
        make_repo(repo, ["build/", ".venv/"], {
            "Makefile": "clean:\n\trm -rf build\n", "build/x.o": "o", ".venv/lib/x": "v"})
        age_tree(repo)
        a = self.plan()[0]["mk"]
        self.assertIn("make clean", a.desc)
        self.assertIn("1 build folders", a.desc)  # .venv only after 90 idle days
        a.fn()
        self.assertFalse(os.path.exists(os.path.join(repo, "build")))
        self.assertTrue(os.path.exists(os.path.join(repo, ".venv")))
        found = clean.build_output(repo, cfg(self.root, venv_idle_days=30), 40)
        self.assertEqual(found, [os.path.join(repo, ".venv")])

    def test_repo_without_build_output_needs_no_action(self):
        repo = os.path.join(self.root, "plain")
        make_repo(repo, ["*.tmp"], {"README": "hi", "x.tmp": "t"})
        age_tree(repo)
        self.assertEqual(self.plan()[0], {})

    def test_nested_repos_and_skipped_folders(self):
        outer = os.path.join(self.root, "group", "outer")
        make_repo(outer, ["target/"], {"a": "1", "target/x": "y"})
        make_repo(os.path.join(self.root, "node_modules", "dep"), ["build/"], {"b": "1", "build/x": "y"})
        age_tree(self.root)
        found = list(clean.find_repos([self.root], {"node_modules"}))
        self.assertEqual(found, [outer])


class CachesTest(unittest.TestCase):
    def test_idle_entries_only(self):
        home = tempfile.mkdtemp()
        write(os.path.join(home, ".cache", "old", "f"), "x" * 5000)
        write(os.path.join(home, ".cache", "fresh", "f"), "y")
        write(os.path.join(home, ".npm", "_cacache", "idx"), "z")
        age_tree(os.path.join(home, ".cache", "old"))
        age_tree(os.path.join(home, ".npm"))
        os.symlink("/etc", os.path.join(home, ".cache", "link"))

        class FakePwd:
            @staticmethod
            def getpwnam(name):
                return type("pw", (), {"pw_dir": home})

        real = clean.pwd
        clean.pwd = FakePwd
        self.addCleanup(setattr, clean, "pwd", real)
        actions, _ = clean.plan_caches(cfg("/nonexistent", users=["someone"]), time.time())
        paths = sorted(a.desc.split(" ")[0] for a in actions)
        self.assertEqual(paths, [os.path.join(home, ".cache", "old"), os.path.join(home, ".npm", "_cacache")])
        for a in actions:
            a.fn()
        self.assertFalse(os.path.exists(os.path.join(home, ".cache", "old")))
        self.assertTrue(os.path.exists(os.path.join(home, ".cache", "fresh")))
        self.assertTrue(os.path.islink(os.path.join(home, ".cache", "link")))


class HelpersTest(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(clean.parse_size("15GB"), 15 * 10**9)
        self.assertEqual(clean.parse_size("8.52GB"), 8520000000)
        self.assertEqual(clean.parse_size("245kB"), 245000)
        self.assertEqual(clean.parse_size("0B"), 0)
        self.assertEqual(clean.parse_size("n/a"), 0)

    def test_remove_refuses_paths_outside_parent(self):
        parent, other = tempfile.mkdtemp(), tempfile.mkdtemp()
        write(os.path.join(other, "f"))
        clean.remove([other, os.path.join(parent, "..", os.path.basename(other))], parent)()
        self.assertTrue(os.path.exists(os.path.join(other, "f")))


def fake_registry(root, repos):
    """A registry storage tree: repos = {name: (tags, manifests)}, plus one blob."""
    v2 = os.path.join(root, "docker", "registry", "v2")
    write(os.path.join(v2, "blobs", "sha256", "ab", "ab01", "data"), "x" * 5000)
    for name, (tags, manifests) in repos.items():
        m = os.path.join(v2, "repositories", name, "_manifests")
        for t in range(tags):
            write(os.path.join(m, "tags", f"t{t}", "current", "link"), "sha256:ab01")
        for i in range(manifests):
            write(os.path.join(m, "revisions", "sha256", f"d{i}", "link"), f"sha256:d{i}")
        write(os.path.join(v2, "repositories", name, "_layers", "sha256", "ab01", "link"), "sha256:ab01")


class RegistryTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.base = tempfile.mkdtemp()
        fake_registry(os.path.join(self.base, "registry-claim-pvc-1"),
                      {"app": (2, 6), "team/web": (1, 3)})
        self.cfg = {"registry_dir": os.path.join(self.base, "registry-claim-*"), "registry_warn": "10GB"}

    def test_measured(self):
        reg = clean.registry_size(self.cfg)
        self.assertEqual((reg["images"], reg["tags"], reg["manifests"]), (2, 3, 9))
        self.assertGreaterEqual(reg["bytes"], 5000)
        self.assertIn("2 images, 3 tags, 9 manifests (watched, not cleaned; warns past 10GB)",
                      clean.registry_note(reg, self.cfg))

    def test_no_registry(self):
        self.assertIsNone(clean.registry_size(dict(self.cfg, registry_dir=os.path.join(self.base, "none-*"))))
        self.assertIsNone(clean.registry_size(dict(self.cfg, registry_dir="")))

    def check(self, warn):
        util = clean.util
        util.write_json(clean.report_paths()[0], {"ts": int(time.time()), "dry_run": True, "bytes": 2 * 10**9,
                                                  "actions": 1, "errors": [], "registry": clean.registry_size(self.cfg)})
        return clean.cmd_check(dict(self.cfg, registry_warn=warn))

    def test_check_mentions_size_and_warns_past_the_limit(self):
        from contextlib import redirect_stdout
        from io import StringIO
        for warn, rc, start, has in (("10GB", 0, "ok: 2.0 GB reclaimable (dry run) on ", "; registry "),
                                     ("1kB", 1, "warn: registry ", "(9 manifests), past clean.registry_warn 1kB")):
            out = StringIO()
            with redirect_stdout(out):
                self.assertEqual(self.check(warn), rc)
            self.assertTrue(out.getvalue().startswith(start), out.getvalue())
            self.assertIn(has, out.getvalue())


if __name__ == "__main__":
    unittest.main()
