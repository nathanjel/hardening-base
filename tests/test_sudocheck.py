"""hbkit.sudocheck: walking a path as written (links one hop at a time) and the one allowed-rule
form. Run as a normal user, every file here is the test's, so what the walk reaches shows in the
"is NAME's" problems; tests/test_harden.py has the root-owned cases (as namespace root)."""
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import tools  # noqa: E402,F401  (puts lib/ on the path)
from hbkit import sudocheck  # noqa: E402

ME = getpass.getuser()


class RootOnlyTest(unittest.TestCase):
    def setUp(self):
        d = self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(f"{d}/a/b")
        os.makedirs(f"{d}/real")
        with open(f"{d}/real/prog", "w") as f:
            f.write("#!/bin/sh\n")

    def walk(self, path):
        return sudocheck.root_only(path, top=self.d)

    def test_every_part_as_written_is_judged(self):
        out = self.walk(f"{self.d}/real/prog")
        self.assertEqual(out, [f"{self.d} is {ME}'s", f"{self.d}/real is {ME}'s", f"{self.d}/real/prog is {ME}'s"])

    def test_a_relative_link_with_dots_is_followed_from_its_real_folder(self):
        os.symlink("../../real/prog", f"{self.d}/a/b/link")
        out = self.walk(f"{self.d}/a/b/link")
        self.assertIn(f"{self.d}/a/b is {ME}'s", out)                 # the link's own folder
        self.assertIn(f"{self.d}/real/prog is {ME}'s", out)           # and where it leads

    def test_a_link_to_a_folder_mid_path(self):
        os.symlink(f"{self.d}/real", f"{self.d}/a/dir")
        out = self.walk(f"{self.d}/a/dir/prog")
        self.assertIn(f"{self.d}/a is {ME}'s", out)
        self.assertIn(f"{self.d}/real/prog is {ME}'s", out)

    def test_dots_and_links_resolve_as_the_kernel_does(self):
        # Codex round 2: collapsing hop/../helper first checked safe/helper; the kernel follows hop,
        # then takes "..": open/helper is what runs
        os.makedirs(f"{self.d}/safe")
        os.makedirs(f"{self.d}/open/child")
        for p in ("safe/helper", "open/helper"):
            with open(f"{self.d}/{p}", "w") as f:
                f.write("#!/bin/sh\n")
        os.symlink("../open/child", f"{self.d}/safe/hop")
        os.symlink("hop/../helper", f"{self.d}/safe/link")
        self.assertEqual(os.path.realpath(f"{self.d}/safe/link"), f"{self.d}/open/helper")
        out = self.walk(f"{self.d}/safe/link")
        self.assertIn(f"{self.d}/open/helper is {ME}'s", out)
        self.assertNotIn(f"{self.d}/safe/helper is {ME}'s", out)
        out = self.walk(f"{self.d}/a/../real/prog")                     # ".." in the path itself: the real parent
        self.assertIn(f"{self.d}/real/prog is {ME}'s", out)

    def test_a_link_has_to_be_roots_too(self):
        # Codex round 2: in a sticky folder the owner of a link may replace it
        os.symlink(f"{self.d}/real/prog", f"{self.d}/a/link")
        self.assertIn(f"{self.d}/a/link (a link) is {ME}'s", self.walk(f"{self.d}/a/link"))

    def test_refused_forms(self):
        self.assertEqual(self.walk("relative/prog"), ["relative/prog isn't a full path"])
        os.symlink(f"{self.d}/loop2", f"{self.d}/loop1")
        os.symlink(f"{self.d}/loop1", f"{self.d}/loop2")
        self.assertIn("too many symbolic links", self.walk(f"{self.d}/loop1")[-1])
        self.assertIn(f"{self.d}/real/none: no such file or directory", self.walk(f"{self.d}/real/none"))
        self.assertIn(f"/etc/passwd leads outside {self.d}", sudocheck.root_only("/etc/passwd", top=self.d)[0])

    def test_the_real_root(self):
        self.assertEqual(sudocheck.root_only("/bin/sh"), [])                  # /bin -> usr/bin, root's all the way
        self.assertIn(f"{self.d} is {ME}'s", sudocheck.root_only(f"{self.d}/real/prog"))


class AllowedRuleTest(unittest.TestCase):
    def test_the_one_form(self):
        self.assertEqual(sudocheck.allowed_rule("svc ALL=(root) NOPASSWD: /usr/libexec/helper"), (["/usr/libexec/helper"], None))
        self.assertEqual(sudocheck.allowed_rule("svc ALL = NOPASSWD: /a/x add, /a/y del 1"), (["/a/x", "/a/y"], None))
        self.assertEqual(sudocheck.allowed_rule("%svc host1=(root : root) NOPASSWD: /a/x"), (["/a/x"], None))
        self.assertEqual(sudocheck.allowed_rule("svc ALL=(root) NOPASSWD: /a/helper /etc/helper.conf -v"),
                         (["/a/helper", "/etc/helper.conf"], None))                  # the files its arguments name too

    def test_what_cant_be_read_from_the_rule(self):
        for rule, want in (("svc ALL=(root) NOPASSWD: NET_HELPER", "isn't a program's full path"),
                           ("svc ALL=(ALL) NOPASSWD:ALL", "isn't a program's full path"),
                           ("svc ALL=(root) NOPASSWD: !/bin/sh", "isn't a program's full path"),
                           ("svc ALL=(root) NOPASSWD: sudoedit /etc/x", "isn't a program's full path"),
                           ("svc ALL=(root) NOPASSWD:SETENV: /a/x", "':', '=' or"),        # another tag
                           ("svc ALL=(root) NOPASSWD: /a/*", "is a pattern"),
                           ("svc ALL=(root) /a/x", "one form only"),
                           ("Defaults:svc !authenticate", "one form only"),
                           # Codex round 2: a second grant after ':', and a folder (anything in it)
                           ("svc ALL=(root) NOPASSWD: /safe/helper : ALL=(root) NOPASSWD: /writable/evil", "':', '=' or"),
                           ("svc ALL=(root) NOPASSWD: /a/x arg=1", "':', '=' or"),
                           ("svc ALL=(root) NOPASSWD: /a/x a\\,b", "':', '=' or"),
                           ("svc ALL=(root) NOPASSWD: /usr/libexec/", "is a folder"),
                           # Codex round 3: a host field that swallowed a whole first grant
                           ("svc ALL=(root)NOPASSWD:/writable/evil:ALL=(root) NOPASSWD: /usr/bin/id", "':', '=' or"),
                           ("svc ALL=(root)NOPASSWD:/writable/evil,ALL=(root) NOPASSWD: /usr/bin/id", "':', '=' or"),
                           ("svc,other ALL=(root) NOPASSWD: /a/x", "one form only"),
                           # Codex round 4: an interpreter runs whatever it is given
                           ("svc ALL=(root) NOPASSWD: /usr/bin/bash /home/svc/job.sh", "runs whatever it is given"),
                           ("svc ALL=(root) NOPASSWD: /usr/bin/python3.13 /x.py", "runs whatever it is given"),
                           ("svc ALL=(root) NOPASSWD: /usr/bin/env /x", "runs whatever it is given"),
                           # Codex round 6: sudo runs /a/x for "/a/x#y" ('#' starts its comment)
                           ("svc ALL=(root) NOPASSWD: /a/x#y", "holds '#'"),
                           ("svc ALL=(root) NOPASSWD: /a/x /etc/x.conf#y", "holds '#'")):
            with self.subTest(rule):
                self.assertIn(want, sudocheck.allowed_rule(rule)[1])


# a sudoers file, and what sudo reads in it (cvtsudoers -f json agrees; see below): Codex round 6
SAMPLE = r"""## the stock file's comments
# %wheel ALL=(ALL) NOPASSWD: ALL
#includedir /etc/sudoers.d
#1000 ALL=(ALL) NOPASSWD: ALL
%#1001 ALL=(ALL) NOPASSWD: ALL
alice ALL=(#0) NOPASSWD: ALL
bob ALL=(root) NOPASSWD: /usr/local/bin/tool#x
carl ALL=(root) NOPASSWD: /usr/local/bin/tool arg # 1, /usr/bin/true
Defaults:dora !\
   authenticate
erin ALL=(ALL) \
NOPASSWD: ALL
# a note that ends in a backslash \
fred ALL=(ALL) NOPASSWD: ALL
gina ALL=(root) /bin/a # a comment that does too \
hal ALL=(root) NOPASSWD: ALL
Defaults:ian lecture_file="/x#y", !authenticate
"""
READ = [(3, "#includedir /etc/sudoers.d"),
        (4, "#1000 ALL=(ALL) NOPASSWD: ALL"),
        (5, "%#1001 ALL=(ALL) NOPASSWD: ALL"),
        (6, "alice ALL=(#0) NOPASSWD: ALL"),
        (7, "bob ALL=(root) NOPASSWD: /usr/local/bin/tool"),
        (8, "carl ALL=(root) NOPASSWD: /usr/local/bin/tool arg"),
        (9, "Defaults:dora ! authenticate"),
        (11, "erin ALL=(ALL) NOPASSWD: ALL"),
        (14, "fred ALL=(ALL) NOPASSWD: ALL"),
        (15, "gina ALL=(root) /bin/a"),
        (16, "hal ALL=(root) NOPASSWD: ALL"),
        (17, 'Defaults:ian lecture_file="/x#y", !authenticate')]


class SudoersLinesTest(unittest.TestCase):
    """Codex round 6: hb's scans read sudoers a line at a time and took every '#' for a comment,
    so "#1000 ALL=(ALL) NOPASSWD: ALL" (a uid), "(#0)", and a setting continued on the next line
    went unseen, and "/usr/local/bin/tool#x" was checked as a file sudo never runs."""

    def test_lines_as_sudo_reads_them(self):
        self.assertEqual(sudocheck.sudoers_lines(SAMPLE), READ)

    def test_a_quote_or_backslash_keeps_the_rest_of_the_line(self):
        # sudo may read the '#' in a string or escaped; nothing after it may be cut from the scan
        self.assertEqual(sudocheck.sudoers_lines('Defaults x="a#b", !authenticate\nbob ALL=(root) /x \\#y, NOPASSWD: ALL\n'),
                         [(1, 'Defaults x="a#b", !authenticate'), (2, "bob ALL=(root) /x \\#y, NOPASSWD: ALL")])

    def test_includes(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cases = (("#includedir /etc/sudoers.d\n", ["--includedir", "/etc/sudoers.d"], 0),
                 ("@includedir /etc/sudoers.d\n", ["--includedir", "/etc/sudoers.d"], 0),
                 ("#includedir /etc/sudoers.d\n", [], 2),                      # in a sudoers.d file
                 ("@includedir /etc/other.d\n", ["--includedir", "/etc/sudoers.d"], 2),
                 ("#include /etc/sudoers.local\n", ["--includedir", "/etc/sudoers.d"], 2),
                 ("#include /etc/sudoers.d\n", ["--includedir", "/etc/sudoers.d"], 2),     # only the folder form
                 ("@include sudoers.local\n", ["--includedir", "/etc/sudoers.d"], 2))
        for text, opts, rc in cases:
            with self.subTest(text=text, opts=opts):
                with open(f"{d}/sudoers", "w") as f:
                    f.write("root ALL=(ALL) ALL\n" + text)
                r = subprocess.run([sys.executable, "-B", sudocheck.__file__, "lines", *opts, f"{d}/sudoers"],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, rc, r.stdout)
                if rc:
                    self.assertIn(f"{d}/sudoers:2: {text.strip()} has sudo read rules hb doesn't check", r.stdout)
                else:
                    self.assertEqual(r.stdout.splitlines()[0], "1:root ALL=(ALL) ALL")

    @unittest.skipUnless(shutil.which("cvtsudoers"), "no cvtsudoers (sudo's own parser)")
    def test_sudo_reads_the_sample_the_same(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        sample = SAMPLE.replace("#includedir /etc/sudoers.d\n", "")
        with open(f"{d}/sudoers", "w") as f:
            f.write(sample)
        r = subprocess.run(["cvtsudoers", "-f", "json", f"{d}/sudoers"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        parsed = json.loads(r.stdout)
        sudo = {}                     # whom sudo lets in without a password: their commands, or Defaults
        for spec in parsed.get("User_Specs", []):
            u = spec["User_List"][0]
            who = u["username"] if "username" in u else f"#{u['userid']}" if "userid" in u else f"%#{u['usergid']}"
            for c in spec["Cmnd_Specs"]:
                if {"authenticate": False} in c.get("Options", []):
                    sudo[who] = [x["command"] for x in c["Commands"]]
        for entry in parsed.get("Defaults", []):
            if {"authenticate": False} in entry.get("Options", []):
                sudo[entry["Binding"][0]["username"]] = "Defaults"
        hb = {}                       # what hb-harden's nopasswd scan finds in the same lines
        for _, text in sudocheck.sudoers_lines(sample):
            if re.search(r"NOPASSWD|!\s*authenticate", text):
                first = text.split()[0]
                hb[first.split(":", 1)[1] if first.startswith("Defaults:") else first] = text
        self.assertEqual(set(hb), set(sudo))
        self.assertEqual(sudo["bob"], ["/usr/local/bin/tool"])        # what the scan hands the allowed check
        self.assertEqual(hb["bob"], "bob ALL=(root) NOPASSWD: /usr/local/bin/tool")

if __name__ == "__main__":
    unittest.main()
