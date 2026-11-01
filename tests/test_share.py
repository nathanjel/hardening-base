"""hb-share: the smb.conf it renders from hb.toml, and the share lines it refuses."""
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

ME = pwd.getpwuid(os.getuid())


def harness():
    """hb-share's functions without the root check and the verb handling, sourced from the repo."""
    with open(os.path.join(REPO, "tools", "hb-share")) as f:
        lines = f.read().splitlines()
    out, skip = [], False
    for line in lines:
        if line.startswith("source "):
            line = f'source "{os.path.join(REPO, "lib", "hb.sh")}"'
        if line in ("need_root", "item_main \"$@\""):
            continue
        if line.startswith('if [ "${1:-}" = password ]'):
            skip = True
        if not skip:
            out.append(line)
        if skip and line == "fi":
            skip = False
    path = os.path.join(tempfile.mkdtemp(), "hb-share-functions")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    return path


class ShareConfTest(unittest.TestCase):
    def run_fn(self, shares, fn):
        d = tempfile.mkdtemp()
        cfg = os.path.join(d, "hb.toml")
        with open(cfg, "w") as f:
            f.write(f'[wg]\naddress = "10.77.0.1/24"\n\n[share]\nuser = "{ME.pw_name}"\n'
                    f"shares = {shares!r}\n".replace("'", '"'))
        env = dict(os.environ, HB_CONFIG=cfg, HB_STATE=d)
        p = subprocess.run(["bash", "-c", f'source "$1"; {fn}', "_", harness()], env=env,
                           capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr

    def test_rendered(self):
        rc, conf, err = self.run_fn(["work ~/workspaces", "drop /srv/drop/"], "smb_wanted")
        self.assertEqual(rc, 0, err)
        for want in ("\tbind interfaces only = no\n", "\thosts allow = 10.77.0.0/24\n", "\thosts deny = ALL\n",
                     "\tserver min protocol = SMB3_11\n", "\tserver signing = mandatory\n",
                     "\tmap to guest = never\n", "\tdisable netbios = yes\n", "\tmap archive = no\n",
                     f"[work]\n\tpath = {ME.pw_dir}/workspaces\n\tvalid users = {ME.pw_name}\n\tread only = no\n",
                     "[drop]\n\tpath = /srv/drop\n"):
            self.assertIn(want, conf)
        self.assertNotIn("[homes]", conf)
        self.assertNotIn("[printers]", conf)
        testparm = shutil.which("testparm")
        if testparm:                            # Samba installed: its own parser has the last word
            path = os.path.join(tempfile.mkdtemp(), "smb.conf")
            with open(path, "w") as f:
                f.write(conf)
            p = subprocess.run([testparm, "-s", path], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertNotIn("Unknown parameter", p.stderr)

    def test_unit_keeps_smb_to_the_tunnel(self):
        # Samba can't bind to a WireGuard interface, so the kernel filter is one of the three fences
        rc, unit, err = self.run_fn(["work ~/workspaces"], "dropin_wanted")
        self.assertEqual(rc, 0, err)
        self.assertIn("[Service]\nIPAddressDeny=any\nIPAddressAllow=localhost 10.77.0.0/24\n", unit)

    def test_bad_lines_are_refused(self):
        for shares in (["no-path"], ["bad/name /srv/x"], ["x relative/path"], ["x /a /b"]):
            rc, out, _ = self.run_fn(shares, "prereq")
            self.assertEqual(rc, 2, shares)
            self.assertTrue(out.strip(), shares)


if __name__ == "__main__":
    unittest.main()
