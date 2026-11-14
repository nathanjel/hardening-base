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
from unittest import mock

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


class HbProblemsTest(unittest.TestCase):
    """What root runs from hb's tree (a PAM code check, fail2ban's actions, the break-glass alert)
    must be root's alone: the folders above the tree, everything in it and hb.toml (Codex reviews of
    hb fail2ban: the dispatcher alone was checked, not the tool and the libraries it runs). The
    test's own uid stands in for root's."""

    def setUp(self):
        saved = sudocheck.ROOT_UIDS
        sudocheck.ROOT_UIDS = frozenset({0, os.getuid()})
        self.addCleanup(setattr, sudocheck, "ROOT_UIDS", saved)
        d = self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o755)
        self.root = f"{d}/opt/hb"
        for rel, mode in (("hb", 0o755), ("tools/hb-totp", 0o755), ("tools/hb-notify", 0o755),
                          ("lib/hbkit/util.py", 0o644)):
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
            with open(path, "w") as f:
                f.write("x\n")
            os.chmod(path, mode)
        for folder in (f"{d}/opt", self.root, f"{self.root}/tools", f"{self.root}/lib", f"{self.root}/lib/hbkit"):
            os.chmod(folder, 0o755)
        os.makedirs(f"{d}/etc/hb", mode=0o700)
        os.chmod(f"{d}/etc", 0o755)
        self.cfg = f"{d}/etc/hb/hb.toml"
        with open(self.cfg, "w") as f:
            f.write("")
        os.chmod(self.cfg, 0o600)

    def problems(self, *host_files):
        return sudocheck.hb_problems(self.root, list(host_files or [self.cfg]), top=self.d)

    def test_a_tree_of_roots_is_safe(self):
        self.assertEqual(self.problems(), [])
        self.assertEqual(sudocheck.hb_problems(self.root, [], top=self.d), [])

    def test_anything_others_can_change_is_named(self):
        gname = sudocheck.name_of(gid=os.getgid())
        cases = (("lib/hbkit/util.py", 0o664, f"can be written by group {gname}"),
                 ("tools/hb-notify", 0o757, "can be written by anyone"),
                 ("lib", 0o775, f"can be written by group {gname}"),
                 ("lib/hbkit", 0o1757, "can be written by anyone"),          # sticky inside the tree: a new module
                 ("tools", 0o1757, "can be written by anyone"),              # a new tool, which hb check runs
                 ("", 0o1757, "can be written by anyone"),                   # the tree itself: a new hb.toml
                 ("", 0o757, "can be written by anyone"))
        for rel, mode, why in cases:
            p = os.path.join(self.root, rel).rstrip("/")
            before = os.stat(p).st_mode & 0o7777
            os.chmod(p, mode)
            self.assertEqual(self.problems(), [f"{p} {why}"], (rel, oct(mode)))
            os.chmod(p, before)
        self.assertEqual(self.problems(), [])

    def test_the_folders_above_and_the_host_file(self):
        os.chmod(f"{self.d}/opt", 0o757)
        self.assertEqual(self.problems(), [f"{self.d}/opt can be written by anyone"])
        os.chmod(f"{self.d}/opt", 0o1757)                                    # above it, a sticky folder is safe
        self.assertEqual(self.problems(), [])
        os.chmod(f"{self.d}/opt", 0o755)
        os.chmod(self.cfg, 0o606)
        self.assertEqual(self.problems(), [f"{self.cfg} can be written by anyone"])
        os.chmod(self.cfg, 0o600)
        os.chmod(f"{self.d}/etc/hb", 0o707)
        self.assertEqual(self.problems(), [f"{self.d}/etc/hb can be written by anyone"])
        os.chmod(f"{self.d}/etc/hb", 0o700)

    def test_links_on_the_way_to_the_tree(self):
        # Codex round 3: links above ROOT, or naming ROOT, are followed as the kernel would; the
        # tree is walked where it really is
        os.symlink("opt", f"{self.d}/opt-link")
        os.symlink("opt/hb", f"{self.d}/hb-link")
        for root in (f"{self.d}/opt-link/hb", f"{self.d}/hb-link"):
            self.assertEqual(sudocheck.hb_problems(root, [self.cfg], top=self.d), [], root)
        os.chmod(f"{self.root}/tools/hb-notify", 0o757)
        self.assertEqual(sudocheck.hb_problems(f"{self.d}/hb-link", [], top=self.d),
                         [f"{self.root}/tools/hb-notify can be written by anyone"])
        os.chmod(f"{self.root}/tools/hb-notify", 0o755)
        os.chmod(f"{self.d}/opt", 0o757)                                   # where the link leads is judged
        self.assertEqual(sudocheck.hb_problems(f"{self.d}/hb-link", [], top=self.d),
                         [f"{self.d}/opt can be written by anyone"])

    def test_a_host_file_reached_by_a_link(self):
        link = f"{self.d}/etc/hb/link.toml"
        os.symlink("hb.toml", link)                                         # judged where it leads, the link too
        self.assertEqual(self.problems(link), [])
        os.chmod(self.cfg, 0o606)
        self.assertEqual(self.problems(link), [f"{self.cfg} can be written by anyone"])
        os.chmod(self.cfg, 0o600)
        os.unlink(link)
        os.symlink("gone.toml", link)                                       # there, but leading nowhere
        self.assertEqual(self.problems(link), [f"{self.d}/etc/hb/gone.toml: no such file or directory"])

    def test_a_host_file_not_made_yet(self):
        # Codex review: /etc/hb/hb.toml comes before the tree's own; an open /etc/hb let others make it
        missing = f"{self.d}/etc/hb/other.toml"
        self.assertEqual(self.problems(missing), [])
        for mode in (0o707, 0o1707):                                         # a sticky bit doesn't stop a new file
            os.chmod(f"{self.d}/etc/hb", mode)
            self.assertEqual(self.problems(missing), [f"{self.d}/etc/hb can be written by anyone"], oct(mode))
        os.chmod(f"{self.d}/etc/hb", 0o700)
        deeper = f"{self.d}/etc/nohb/hb.toml"                                # its folder isn't there either
        self.assertEqual(self.problems(deeper), [])
        os.chmod(f"{self.d}/etc", 0o1757)
        self.assertEqual(self.problems(deeper), [f"{self.d}/etc can be written by anyone"])
        self.assertEqual(self.problems(self.cfg), [])                        # one that is there: as root_only judges it
        os.makedirs(f"{self.d}/etc/a", mode=0o755)                          # the folders above the one there
        os.chmod(f"{self.d}/etc", 0o757)
        self.assertEqual(self.problems(f"{self.d}/etc/a/b/hb.toml"), [f"{self.d}/etc can be written by anyone"])
        os.chmod(f"{self.d}/etc", 0o755)
        os.chmod(f"{self.d}", 0o757)
        self.assertEqual(self.problems(deeper)[0], f"{self.d} can be written by anyone")

    def test_someone_elses_files(self):
        sudocheck.ROOT_UIDS = frozenset({0})
        # the tree isn't walked once a folder on the way to it fails; the host file is still judged
        self.assertEqual(self.problems(), [f"{p} is {ME}'s" for p in (self.d, f"{self.d}/opt", self.root,
                                                                      f"{self.d}/etc", f"{self.d}/etc/hb", self.cfg)])
        inside = f"{self.root}/hb.toml"                                    # each problem once
        with open(inside, "w") as f:
            f.write("")
        os.chmod(inside, 0o606)
        sudocheck.ROOT_UIDS = frozenset({0, os.getuid()})
        self.assertEqual(self.problems(inside), [f"{inside} can be written by anyone"])
        os.unlink(inside)
        sudocheck.ROOT_UIDS = frozenset({0, os.getuid()})
        os.chmod(f"{self.root}/lib", 0o775)
        with mock.patch.object(sudocheck.os, "lstat", side_effect=fake_owner(f"{self.root}/tools/hb-notify")):
            self.assertEqual(self.problems(), [f"{self.root}/lib can be written by group "
                                               f"{sudocheck.name_of(gid=os.getgid())}",
                                               f"{self.root}/tools/hb-notify is nobody's"])

    def test_no_links_in_the_tree(self):
        # Codex reviews: a tool imports the libraries beside its real path, so a link moves them,
        # out of the tree (to a protected tool elsewhere) or up a level inside it (tools/x -> ../x
        # imports from the folder above the tree)
        os.makedirs(f"{self.d}/other/tools", mode=0o755)
        with open(f"{self.d}/other/tools/hb-totp", "w") as f:
            f.write("x\n")
        with open(f"{self.root}/hb-notify", "w") as f:
            f.write("x\n")
        tool = f"{self.root}/tools/hb-totp"
        os.unlink(tool)
        why = "is a link (hb's tree has none: a tool imports from beside where it really is)"
        for target in (f"{self.d}/other/tools/hb-totp", "../hb-notify", "hb-notify", "..", "missing", "/etc/passwd"):
            os.symlink(target, tool)
            self.assertEqual(self.problems(), [f"{tool} {why}"], target)
            os.unlink(tool)
        self.assertEqual(self.problems(), [])

    @unittest.skipIf(os.geteuid() == 0, "root reads a folder of mode 000")
    def test_a_folder_it_cant_read(self):
        os.chmod(f"{self.root}/lib/hbkit", 0o000)
        self.addCleanup(os.chmod, f"{self.root}/lib/hbkit", 0o755)
        self.assertEqual(self.problems(), [f"{self.root}/lib/hbkit: permission denied"])

    def test_the_command(self):
        tool = [sys.executable, "-IB", os.path.join(tools.REPO, "lib", "hbkit", "sudocheck.py"), "tree", "--top", self.d]
        os.makedirs(f"{self.d}/srv", mode=0o755)
        r = subprocess.run(tool + [self.root, self.cfg, f"{self.d}/srv/hb.toml"], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.splitlines()[0]), (1, f"{self.d} is {ME}'s"))  # its own ROOT_UIDS
        self.assertEqual(r.stdout.splitlines()[-2:], [f"{self.cfg} is {ME}'s", f"{self.d}/srv is {ME}'s"])  # both files
        # Codex round 2: a missing host file given as a relative path looped forever
        r = subprocess.run(tool + [self.root, "missing.toml", "no/such/hb.toml"], capture_output=True, text=True,
                           timeout=10, cwd=self.d)
        self.assertEqual(r.stdout.splitlines()[-2:], ["missing.toml isn't a full path", "no/such/hb.toml isn't a full path"])
        self.assertEqual(sudocheck.hb_problems(self.root, ["hb.toml"], top=self.d), ["hb.toml isn't a full path"])
        r = subprocess.run(tool, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("sudocheck.py tree [--top DIR] ROOT [FILE...]", r.stderr)


def fake_owner(path):
    """os.lstat, with PATH someone else's (uid 65534)."""
    real = os.lstat

    def lstat(p, *a, **k):
        st = real(p, *a, **k)
        if p != path:
            return st
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 65534) + tuple(st)[5:])
    return lstat


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
