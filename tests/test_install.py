"""hb-install: which units it installs and which it removes."""
import bz2
import glob
import hashlib
import os
import platform
import shutil
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

    def test_a_link_is_broken_until_the_file_itself_is_there(self):
        # a link in /etc/hb can lead to a world-readable or user-owned secret elsewhere
        d = tempfile.mkdtemp()
        etc, outside = os.path.join(d, "etc-hb"), os.path.join(d, "home", "token")
        write(os.path.join(etc, "hb.toml"), "[install]\ntimers = []\n")
        write(outside, "t0ken\n")
        os.chmod(etc, 0o700)
        os.chmod(os.path.join(etc, "hb.toml"), 0o600)
        os.chmod(outside, 0o644)
        os.makedirs(os.path.join(etc, "secrets"), mode=0o700)
        os.symlink(outside, os.path.join(etc, "secrets", "supervoip-token"))
        script = 'source "$1"; ETC="$2"; SRC=""; chk_config; echo "rc=$?"; fix_config; chk_config >/dev/null; echo "rc=$?"'
        p = subprocess.run(["unshare", "-r", "bash", "-c", script, "_", harness(), etc],
                           env=dict(os.environ, HB_CONFIG=os.path.join(etc, "hb.toml")), capture_output=True, text=True)
        self.assertEqual(p.stdout.splitlines(), [
            f"links in {etc} lead where this can't vouch for: {etc}/secrets/supervoip-token (put the file itself there)",
            "rc=2", "rc=2"], p.stderr)
        self.assertEqual(oct(os.stat(outside).st_mode & 0o777), "0o644")      # the target isn't touched

    def test_hb_toml_or_the_folder_as_a_link_is_never_followed(self):
        for what in ("hb.toml", "folder"):
            d = tempfile.mkdtemp()
            etc, outside = os.path.join(d, "etc-hb"), os.path.join(d, "home", "hb.toml")
            write(outside, "[install]\ntimers = []\n")
            os.chmod(outside, 0o644)
            if what == "hb.toml":
                os.makedirs(etc, mode=0o700)
                os.symlink(outside, os.path.join(etc, "hb.toml"))
            else:
                os.symlink(os.path.dirname(outside), etc)
            script = 'source "$1"; ETC="$2"; SRC=""; chk_config; echo "rc=$?"; fix_config; echo "fix=$?"'
            p = subprocess.run(["unshare", "-r", "bash", "-c", script, "_", harness(), etc],
                               env=dict(os.environ, HB_CONFIG=outside), capture_output=True, text=True)
            lines = p.stdout.splitlines()
            self.assertTrue(lines[0].startswith(f"links in {etc} lead where this can't vouch for: "), (what, lines))
            self.assertEqual(lines[1:], ["rc=2", "fix=1"], what)
            self.assertEqual(oct(os.stat(outside).st_mode & 0o777), "0o644", what)     # never chmod'ed through it


# curl as fix_restic calls it: logs the URL, writes {src} to the -o file
CURL = """#!/bin/sh
out=""
while [ $# -gt 1 ]; do [ "$1" = -o ] && out="$2"; shift; done
echo "$1" >> {log}
cp {src} "$out"
"""


@unittest.skipUnless(userns_ok(), "needs unprivileged user namespaces (unshare -r)")
class ResticTest(unittest.TestCase):
    """The restic item: the pinned release, installed only with the SHA-256 it should have."""

    ARCH = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())

    def setUp(self):
        if not self.ARCH:
            self.skipTest("restic releases are tested for x86_64 and aarch64")
        d = self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.bin, self.log, self.asset = f"{d}/usr-local-bin/restic", f"{d}/curl.log", f"{d}/release.bz2"
        os.makedirs(os.path.dirname(self.bin))
        os.makedirs(f"{d}/path")
        write(f"{d}/path/curl", CURL.format(log=self.log, src=self.asset))
        os.chmod(f"{d}/path/curl", 0o755)
        self.release("0.19.1")

    def release(self, says):
        """The release file: a restic that says it is version `says`. Its SHA-256 is returned."""
        data = bz2.compress(f"#!/bin/sh\necho 'restic {says} compiled with go1.26 on linux/{self.ARCH}'\n".encode())
        with open(self.asset, "wb") as f:
            f.write(data)
        self.sha = hashlib.sha256(data).hexdigest()
        return self.sha

    def run_fn(self, script, version="0.19.1", sha=None):
        sha = self.sha if sha is None else sha
        write(f"{self.d}/hb.toml", f'[backup]\nrestic_version = "{version}"\nrestic_sha256 = "{sha}"\n')
        env = dict(os.environ, HB_CONFIG=f"{self.d}/hb.toml", PATH=f"{self.d}/path" + os.pathsep + os.environ["PATH"])
        p = subprocess.run(["unshare", "-r", "bash", "-c", f'source "$1"; RESTIC_BIN="$2"; {script}', "_", harness(),
                            self.bin], env=env, capture_output=True, text=True)
        return p.stdout.splitlines(), p.stderr

    def test_not_managed_without_a_version(self):
        out, _ = self.run_fn('chk_restic; echo "rc=$?"', version="", sha="")
        self.assertEqual(out, ["not managed (backup.restic_version is empty; hb backup uses the restic on PATH)", "rc=0"])

    def test_the_settings_are_checked(self):
        out, _ = self.run_fn('chk_restic; echo "rc=$?"', version="latest")
        self.assertEqual(out, ["backup.restic_version must look like 0.19.1", "rc=2"])
        out, _ = self.run_fn('chk_restic; echo "rc=$?"', sha="abc")
        self.assertEqual(out, [f"backup.restic_sha256 must be the SHA-256 of restic_0.19.1_linux_{self.ARCH}.bz2 "
                               "(from the release's SHA256SUMS)", "rc=2"])

    def test_installed_when_the_hash_matches(self):
        out, err = self.run_fn('chk_restic; echo "rc=$?"; fix_restic; echo "fix=$?"; chk_restic; echo "rc=$?"')
        self.assertEqual(out, [f"will install restic 0.19.1 at {self.bin} (restic_0.19.1_linux_{self.ARCH}.bz2, "
                               "SHA-256 checked)", "rc=1", "fix=0", f"restic 0.19.1 at {self.bin}", "rc=0"], err)
        self.assertEqual(oct(os.stat(self.bin).st_mode & 0o777), "0o755")
        with open(self.log) as f:
            self.assertEqual(f.read().split(), ["https://github.com/restic/restic/releases/download/v0.19.1/"
                                                f"restic_0.19.1_linux_{self.ARCH}.bz2"])

    def test_never_installed_with_another_hash(self):
        out, err = self.run_fn('fix_restic; echo "fix=$?"', sha="0" * 64)
        self.assertEqual(out, ["fix=1"])
        self.assertIn(f"SHA-256 is {self.sha}, not backup.restic_sha256: not installed", err)
        self.assertFalse(os.path.exists(self.bin))

    def test_never_installed_when_it_says_another_version(self):
        self.release("0.18.0")
        out, err = self.run_fn('fix_restic; echo "fix=$?"')
        self.assertEqual(out, ["fix=1"])
        self.assertIn("doesn't say it is restic 0.19.1: not installed", err)
        self.assertFalse(os.path.exists(self.bin))

    def test_another_version_or_a_loose_file_is_replaced(self):
        write(self.bin, "#!/bin/sh\necho 'restic 0.18.0 compiled with go1.24 on linux/x'\n")
        os.chmod(self.bin, 0o755)
        out, _ = self.run_fn('chk_restic; echo "rc=$?"')
        self.assertEqual(out[0], f"will replace restic 0.18.0 compiled with go1.24 on linux/x at {self.bin} with "
                                 f"restic 0.19.1 (restic_0.19.1_linux_{self.ARCH}.bz2, SHA-256 checked)")
        os.chmod(self.bin, 0o775)                                  # anyone in its group could change it
        out, _ = self.run_fn('chk_restic; echo "rc=$?"; fix_restic; chk_restic')
        self.assertTrue(out[0].startswith(f"{self.bin} isn't a file only root can change: will replace it"), out)
        self.assertEqual(out[1:], ["rc=1", f"restic 0.19.1 at {self.bin}"])

    def test_a_link_there_is_replaced_never_written_through(self):
        target = f"{self.d}/elsewhere"
        write(target, "someone's file\n")
        os.symlink(target, self.bin)
        out, _ = self.run_fn('chk_restic; echo "rc=$?"; fix_restic; chk_restic')
        self.assertTrue(out[0].startswith(f"{self.bin} isn't a file only root can change"), out)
        self.assertEqual(out[2], f"restic 0.19.1 at {self.bin}")
        self.assertFalse(os.path.islink(self.bin))
        with open(target) as f:
            self.assertEqual(f.read(), "someone's file\n")


class NeedsItemTest(unittest.TestCase):
    """The needs item reads the hb.toml apply is about to install, and knows a git checkout needs git."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.src, self.prefix, self.fake, self.empty = f"{d}/checkout", f"{d}/opt-hb", f"{d}/fake", f"{d}/empty"
        write(f"{self.src}/hb.toml", '[wg]\naddress = "10.0.0.1/24"\n')
        os.makedirs(self.empty)
        # a python3 that says what it was given
        write(f"{self.fake}/python3", '#!/bin/sh\necho "config=${HB_CONFIG:-} git=${HB_NEEDS_GIT:-} $3"\n')
        os.chmod(f"{self.fake}/python3", 0o755)

    def run_fn(self, fn, hb_root, path=None, **env):
        e = {k: v for k, v in os.environ.items() if not k.startswith("HB_")}
        e.update(HB_NEEDS_PATH=self.empty, PATH=path or os.environ["PATH"], **env)
        p = subprocess.run(["bash", "-c", f'source "$1"; PREFIX="$2"; SRC="$3"; HB_ROOT="$4"; {fn}', "_", harness(),
                            self.prefix, self.src, hb_root], env=e, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout.strip()

    def test_from_a_checkout_its_hb_toml(self):
        rc, out = self.run_fn("chk_needs", REPO, path=f"{self.fake}:{os.environ['PATH']}")
        self.assertEqual(out, f"config={self.src}/hb.toml git= check")
        os.makedirs(f"{self.src}/.git")
        rc, out = self.run_fn("chk_needs", REPO, path=f"{self.fake}:{os.environ['PATH']}")
        self.assertEqual(out, f"config={self.src}/hb.toml git=1 check")

    def test_the_installed_copy_reads_its_own(self):
        self.prefix = REPO
        rc, out = self.run_fn("chk_needs", REPO, path=f"{self.fake}:{os.environ['PATH']}")
        self.assertEqual(out, "config= git= check")
        rc, out = self.run_fn("chk_needs", REPO, path=f"{self.fake}:{os.environ['PATH']}", HB_CONFIG="/x/hb.toml")
        self.assertEqual(out, "config=/x/hb.toml git= check")

    def test_it_reports_through_needs_py(self):
        rc, out = self.run_fn("chk_needs", REPO)
        self.assertEqual(rc, 2, out)
        self.assertIn("hb installs when applied: wg wg-quick (hb wg apply)", out)
        rc, out = self.run_fn("needs list", REPO)
        self.assertIn("  MISSING  wireguard-tools   wg wg-quick", out)

    def test_a_crash_is_no_todo(self):
        # Fable review 9: exit 1 would read as "apply would change something", and apply would offer it
        write(f"{self.fake}/python3", "#!/bin/sh\necho boom; exit 1\n")
        rc, out = self.run_fn("chk_needs", REPO, path=f"{self.fake}:{os.environ['PATH']}")
        self.assertEqual((rc, out), (2, "boom\nneeds.py ended with exit 1"))

    def test_without_python3_at_all(self):
        bash = shutil.which("bash")
        os.symlink(bash, f"{self.empty}/bash")
        rc, out = self.run_fn("chk_needs", REPO, path=self.empty)
        self.assertEqual((rc, out), (2, "missing: python3 (mandatory). Install: dnf install -y python3"))


class VerbsTest(unittest.TestCase):
    """hb install itself (not root's check): the needs verb, and plan/apply saying the needs first."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.prefix, self.cfg, self.empty = f"{d}/opt-hb", f"{d}/hb.toml", f"{d}/empty"
        write(self.cfg, "[install]\ntimers = []\n")
        os.makedirs(self.empty)
        with open(os.path.join(REPO, "tools", "hb-install")) as f:
            text = f.read()
        self.assertEqual(text.count("\nneed_root\n"), 1)
        text = text.replace("\nneed_root\n", "\n").replace(
            'source "$(dirname "$(readlink -f "$0")")/../lib/hb.sh"', f'source "{REPO}/lib/hb.sh"')
        self.script = f"{d}/hb-install"
        write(self.script, text)

    def run_install(self, *args):
        e = {k: v for k, v in os.environ.items() if not k.startswith("HB_")}
        e.update(HB_PREFIX=self.prefix, HB_CONFIG=self.cfg, HB_NEEDS_PATH=self.empty)
        p = subprocess.run(["bash", self.script, *args], env=e, capture_output=True, text=True, timeout=300)
        return p.returncode, p.stdout, p.stderr

    def test_needs_lists_everything(self):
        rc, out, _ = self.run_install("needs")
        self.assertEqual(rc, 2)                          # nothing on the (empty) PATH
        self.assertTrue(out.startswith("What hb runs on "), out[:200])
        self.assertIn("missing, needed here: dnf install -y ", out)

    def test_a_first_plan_starts_with_the_whole_list(self):
        rc, out, _ = self.run_install("plan")
        self.assertTrue(out.startswith("What hb runs on "), out[:200])
        self.assertLess(out.index("missing, needed here:"), out.index("would change  code"))

    def test_a_later_plan_starts_with_one_line(self):
        os.makedirs(self.prefix)
        rc, out, _ = self.run_install("plan")
        self.assertTrue(out.startswith("needs: missing: "), out[:200])
        self.assertNotIn("What hb runs on", out)

    def test_status_has_needs_first(self):
        rc, out, _ = self.run_install("status")
        self.assertTrue(out.startswith("FAIL  needs          missing: "), out[:200])

    def test_the_list_comes_even_when_hb_toml_is_broken(self):
        # Fable review 1: hb config's check used to end the run before the list could say anything
        write(self.cfg, "[install\n")
        rc, out, err = self.run_install("plan")
        self.assertEqual(rc, 2)
        self.assertIn("Settings: hb.toml unread (TOMLDecodeError", out)
        self.assertIn("cannot read config", err)
        rc, out, err = self.run_install("needs")
        self.assertIn("missing, needed here:", out)


if __name__ == "__main__":
    unittest.main()
