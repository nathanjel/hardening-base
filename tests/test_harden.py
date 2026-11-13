"""hb-harden's sshd drop-in (root_login and x11 share it), its journal item, its admins item and its
NOPASSWD audit, as (namespace) root with sshd, systemctl, systemd-analyze, journalctl and the
account tools faked; the other items not managed."""
import json
import os
import shutil
import struct
import zlib
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

# sshd -T: the drop-in's values (read first, so they win), else the distribution's; -t fails on a flag
SSHD = """#!/bin/sh
echo "sshd $*" >> {log}
if [ "$1" = -t ]; then [ -e {d}/bad ] && {{ echo "bad config" >&2; exit 1; }}; exit 0; fi
v() {{ awk -v k="$1" 'tolower($1) == k {{print $2; exit}}' {sshd}/10-hb-harden.conf 2>/dev/null; }}
echo "permitrootlogin $(v permitrootlogin | grep . || echo without-password)"
echo "x11forwarding $(v x11forwarding | grep . || echo yes)"
"""
# journald: started when the test says (the "started" file holds the time, to the microsecond, as
# systemctl show --timestamp=us+utc prints it), or now when restarted
SYSTEMCTL = """#!/bin/sh
echo "systemctl $*" >> {log}
case "$1 $2" in
  "show systemd-journald.service") cat {d}/started 2>/dev/null ;;
  "restart systemd-journald") date -u '+%a %Y-%m-%d %H:%M:%S.%6N UTC' > {d}/started ;;
esac
exit 0
"""
# what systemd-analyze cat-config prints: journald.conf, then the drop-ins of both folders (hb's,
# and one standing in for /run/systemd/journald.conf.d) in the order of their names
ANALYZE = """#!/bin/sh
[ "$*" = "cat-config systemd/journald.conf" ] || exit 1
printf '# /etc/systemd/journald.conf\\n[Journal]\\n#SystemMaxUse=\\n'
for f in {journald}/*.conf {d}/run/journald.conf.d/*.conf; do [ -f "$f" ] && echo "${{f##*/}} $f"; done | LC_ALL=C sort |
  while read -r name f; do printf '\\n# %s\\n' "$f"; cat "$f"; done
"""
JOURNALCTL = """#!/bin/sh
echo "Archived and active journals take up 514.6M in the file system."
"""
def systemd_time(ns):
    """A time as systemctl show --timestamp=us+utc prints it."""
    return time.strftime("%a %Y-%m-%d %H:%M:%S", time.gmtime(ns // 10**9)) + f".{ns % 10**9 // 1000:06d} UTC"


HEADER = ("# Managed by hb-harden. Files here are read in name order and the first\n"
          "# value wins, so this one sorts before the distribution defaults.\n")


def can_fake_root():
    return shutil.which("unshare") is not None and subprocess.run(
        ["unshare", "-r", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
class HardenTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.bin, self.log = f"{d}/bin", f"{d}/calls.log"
        self.sshd, self.journald = f"{d}/sshd_config.d", f"{d}/journald.conf.d"
        os.makedirs(self.bin)
        os.makedirs(self.sshd)
        for name, text in (("sshd", SSHD), ("systemctl", SYSTEMCTL), ("systemd-analyze", ANALYZE),
                           ("journalctl", JOURNALCTL)):
            with open(f"{self.bin}/{name}", "w") as f:
                f.write(text.format(log=self.log, d=d, sshd=self.sshd, journald=self.journald))
            os.chmod(f"{self.bin}/{name}", 0o755)
        os.makedirs(f"{d}/sudoers.d")                 # the host's /etc/sudoers is root's alone (0440)
        with open(f"{d}/sudoers", "w") as f:
            f.write("root ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n")
        self.toml = f"{d}/hb.toml"
        self.dropin = f"{self.sshd}/10-hb-harden.conf"
        self.ours = f"{self.journald}/90-hb.conf"

    def config(self, *lines):
        with open(self.toml, "w") as f:
            f.write("[harden]\n" + "".join(f"{line}\n" for line in lines))

    def tool(self, *args):
        env = {**os.environ, "HB_CONFIG": self.toml, "HB_SSHD_DIR": self.sshd, "HB_JOURNALD_DIR": self.journald,
               "HB_STATE": f"{self.d}/state", "HB_SUDOERS": f"{self.d}/sudoers", "HB_SUDOERS_DIR": f"{self.d}/sudoers.d",
               "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-harden"), *args], env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              start_new_session=True)

    def line(self, item):
        return next(l for l in self.tool("status").stdout.splitlines() if l.split()[1:2] == [item])

    def calls(self):
        try:
            with open(self.log) as f:
                return [l.strip() for l in f]
        except OSError:
            return []

    def read(self, path):
        with open(path) as f:
            return f.read()

    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    # --- sshd ---

    def test_x11_pending_then_applied(self):
        self.config('x11_forwarding = "no"')
        self.assertIn(f"X11Forwarding yes → no (via {self.dropin})", self.line("x11"))
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.read(self.dropin), HEADER + "X11Forwarding no\n")
        self.assertEqual(os.stat(self.dropin).st_mode & 0o777, 0o600)
        self.assertIn("sshd -t", self.calls())
        self.assertIn("systemctl reload sshd", self.calls())
        self.assertIn("ok    x11            X11Forwarding no", self.line("x11"))
        self.assertEqual(self.tool("check").returncode, 0)

    def test_x11_keeps_the_root_login_line(self):
        self.write(self.dropin, HEADER + "PermitRootLogin no\n")     # as root_login wrote it before x11 existed
        self.config('permit_root_login = "no"', 'x11_forwarding = "no"')
        self.assertIn("PermitRootLogin no", self.line("root_login"))
        self.tool("apply", "--yes")
        self.assertEqual(self.read(self.dropin), HEADER + "PermitRootLogin no\nX11Forwarding no\n")
        self.assertEqual(self.tool("check").returncode, 0)

    def test_root_login_alone_writes_what_it_always_did(self):
        self.config('permit_root_login = "no"')
        self.tool("apply", "--yes")
        self.assertEqual(self.read(self.dropin), HEADER + "PermitRootLogin no\n")
        self.assertIn("not managed", self.line("x11"))

    def test_a_rejected_config_is_put_back(self):
        self.write(self.dropin, HEADER + "PermitRootLogin no\n")
        self.config('permit_root_login = "no"', 'x11_forwarding = "no"')
        open(f"{self.d}/bad", "w").close()
        self.tool("apply", "--yes")
        self.assertEqual(self.read(self.dropin), HEADER + "PermitRootLogin no\n")
        self.assertNotIn("systemctl reload sshd", self.calls())
        self.assertEqual(self.tool("check").returncode, 1)

    def test_x11_takes_yes_or_no(self):
        self.config('x11_forwarding = "off"')
        self.assertEqual(self.tool("check").returncode, 2)

    # --- journal ---

    def test_journal_pending_then_applied(self):
        self.config('journal_max_use = "2G"')
        self.assertIn(f"SystemMaxUse=(journald's default) → 2G via {self.ours}; the journal now takes 514.6M",
                      self.line("journal"))
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.read(self.ours),
                         "# Managed by hb-harden from hb.toml (harden.journal_max_use).\n[Journal]\nSystemMaxUse=2G\n")
        self.assertEqual(os.stat(self.ours).st_mode & 0o777, 0o644)
        self.assertEqual(os.stat(self.journald).st_mode & 0o777, 0o755)
        self.assertIn("systemctl restart systemd-journald", self.calls())
        self.assertIn("ok    journal        SystemMaxUse=2G (the journal now takes 514.6M)", self.line("journal"))
        self.assertEqual(self.tool("check").returncode, 0)

    def test_a_drop_in_read_after_ours_has_to_go(self):
        size = f"{self.journald}/size.conf"                   # sorts after 90-hb.conf, so it would win
        self.write(size, "[Journal]\nSystemMaxUse=500M\n")
        self.config('journal_max_use = "2G"')
        self.assertIn(f"{size} sets SystemMaxUse after hb's 90-hb.conf, so it would win: list it in harden.remove_files",
                      self.line("journal"))
        self.assertEqual(self.tool("check").returncode, 2)
        self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(self.ours))
        self.config('journal_max_use = "2G"', f'remove_files = ["{size}"]')
        self.assertIn(f"SystemMaxUse=500M ({size}) → 2G", self.line("journal"))
        self.tool("apply", "--yes")                            # files (first) takes size.conf away, then journal
        self.assertFalse(os.path.exists(size))
        self.assertEqual(self.tool("check").returncode, 0)

    def test_a_drop_in_read_before_ours_is_overruled(self):
        self.write(f"{self.journald}/10-size.conf", "[Journal]\nSystemMaxUse=500M\n")
        self.config('journal_max_use = "2G"')
        self.assertEqual(self.tool("check").returncode, 1)
        self.tool("apply", "--yes")
        self.assertEqual(self.tool("check").returncode, 0)

    def restarts(self):
        return self.calls().count("systemctl restart systemd-journald")

    def changed_ns(self):
        return max(os.stat(p).st_ctime_ns for p in (self.ours, self.journald))

    def test_journald_has_to_restart_to_read_it(self):
        self.config('journal_max_use = "2G"')
        self.tool("apply", "--yes")
        self.write(f"{self.d}/started", systemd_time(time.time_ns() - 3600 * 10**9))
        self.assertIn("journald started before its settings last changed", self.line("journal"))
        self.tool("apply", "--yes")
        self.assertEqual(self.restarts(), 2)
        self.assertEqual(self.tool("check").returncode, 0)

    def test_a_change_in_the_same_second_counts(self):
        self.config('journal_max_use = "2G"')
        self.tool("apply", "--yes")
        changed = self.changed_ns()
        self.write(f"{self.d}/started", systemd_time(changed - 1000))          # a microsecond before
        self.assertEqual(self.tool("check").returncode, 1)
        self.write(f"{self.d}/started", systemd_time(changed + 1000))          # a microsecond after
        self.assertEqual(self.tool("check").returncode, 0)

    def test_removing_a_folder_of_overrides_restarts_journald(self):
        """The same with a whole drop-in folder elsewhere (as /run/systemd/journald.conf.d) taken away:
        its own time goes with it, so the files item marks journald's settings as changed."""
        run = f"{self.d}/run/journald.conf.d"
        self.write(self.ours, "# Managed by hb-harden from hb.toml (harden.journal_max_use).\n[Journal]\nSystemMaxUse=2G\n")
        self.write(f"{run}/99-size.conf", "[Journal]\nSystemMaxUse=500M\n")   # sorts after 90-hb.conf
        self.write(f"{self.d}/started", systemd_time(time.time_ns() + 10**6))
        self.config('journal_max_use = "2G"', f'remove_files = ["{run}"]')
        self.assertIn(f"SystemMaxUse=500M ({run}/99-size.conf) → 2G", self.line("journal"))
        r = self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(run), r.stdout + r.stderr)
        self.assertEqual(self.restarts(), 1)
        self.assertEqual(self.tool("check").returncode, 0)

    def test_removing_an_override_restarts_journald(self):
        """hb's file already says 2G, but journald started while a later size.conf said 500M:
        taking size.conf away has to restart journald, though hb's own file doesn't change."""
        size = f"{self.journald}/size.conf"
        self.write(self.ours, "# Managed by hb-harden from hb.toml (harden.journal_max_use).\n[Journal]\nSystemMaxUse=2G\n")
        self.write(size, "[Journal]\nSystemMaxUse=500M\n")
        self.write(f"{self.d}/started", systemd_time(time.time_ns() + 10**6))  # after both were written
        self.config('journal_max_use = "2G"', f'remove_files = ["{size}"]')
        r = self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(size), r.stdout + r.stderr)
        self.assertEqual(self.restarts(), 1)
        self.assertEqual(self.tool("check").returncode, 0)

    def test_journal_takes_a_size(self):
        self.config('journal_max_use = "lots"')
        self.assertEqual(self.tool("check").returncode, 2)
        self.config("")
        self.assertIn("not managed", self.line("journal"))


# Accounts and groups for the admins item: one script plays getent, id, useradd, groupadd, usermod,
# gpasswd, visudo, sudo -l -U and hb-totp, keeping users and groups in {d}/db.json (a user's primary
# group is its "primary", else its own; group ids are stable hashes of the names). visudo refuses a
# file that says BROKEN, or every single file while {d}/visudo-refuses-files exists; sudo -l -U reads
# the sudoers files as sudo does (in name order, skipping names with a dot; later Defaults print
# later); hb-totp ready says yes for users with a file in {d}/enrolled.
ACCOUNTS = """#!/usr/bin/env python3
import json, os, re, shutil, sys, zlib
d = {d!r}
me, a = os.path.basename(sys.argv[0]), sys.argv[1:]
with open(d + "/calls.log", "a") as f:
    f.write(me + " " + " ".join(a) + "\\n")
db = json.load(open(d + "/db.json"))
def save(): json.dump(db, open(d + "/db.json", "w"))
U, G = db["users"], db["groups"]
def gid(g): return 2000 + zlib.crc32(g.encode()) % 50000
def primary(u): return U[u].get("primary", u)
def pw(u): return f"{{u}}:x:1000:{{gid(primary(u))}}::/home/{{u}}:{{U[u]['shell']}}"
if me == "getent":
    kind, name = (a + [None])[:2]
    if kind == "passwd" and name is None:
        print("\\n".join(pw(u) for u in U)); sys.exit(0)
    if kind == "passwd" and name in U:
        print(pw(name)); sys.exit(0)
    if kind == "group":
        name = next((g for g in G if str(gid(g)) == name), name)
        if name in G:
            print(f"{{name}}:x:{{gid(name)}}:{{','.join(G[name])}}"); sys.exit(0)
    sys.exit(2)
if me == "id" and a[:1] != ["-nG"]:
    os.execv("/usr/bin/id", ["id"] + a)                # hb's own `id -u`
if me == "id":
    name = a[-1]
    if name not in U: sys.exit(1)
    print(" ".join(dict.fromkeys([primary(name)] + [g for g in G if name in G[g]])))
elif me == "useradd":
    if a[:1] == ["-D"]:
        print("HOME=/home"); sys.exit(0)
    name = a[-1]
    if name in U: sys.exit(9)
    U[name] = {{"shell": a[a.index("-s") + 1], "home": "-m" in a}}; G.setdefault(name, []); save()
    if os.path.exists(d + "/useradd-fails-home"): sys.exit(12)      # as useradd: the account first, then the home
    if "-m" in a: os.makedirs(os.path.join(os.environ["HB_HOME_BASE"], name), exist_ok=True)
elif me == "userdel":
    name = a[-1]
    if name not in U: sys.exit(6)
    if "-r" in a: shutil.rmtree(os.path.join(os.environ["HB_HOME_BASE"], name), ignore_errors=True)
    del U[name]
    for g in list(G):
        if name in G[g]: G[g].remove(name)
    if G.get(name) == []: del G[name]
    save()
elif me == "groupadd":
    if a[-1] in G: sys.exit(9)
    G[a[-1]] = []; save()
elif me == "usermod":
    g, name = a[a.index("-aG") + 1], a[-1]
    if g not in G or name not in U: sys.exit(6)
    G[g].append(name); save()
elif me == "gpasswd":
    name, g = a[a.index("-d") + 1], a[-1]
    if name not in G.get(g, []): sys.exit(3)
    G[g].remove(name); save()
elif me == "visudo":
    if "-cqf" in a and os.path.exists(d + "/visudo-refuses-files"): sys.exit(1)
    files = [a[a.index("-cqf") + 1]] if "-cqf" in a else [os.environ["HB_SUDOERS"]] + [
        os.path.join(os.environ["HB_SUDOERS_DIR"], f) for f in os.listdir(os.environ["HB_SUDOERS_DIR"])]
    sys.exit(1 if any("BROKEN" in open(f).read() for f in files if os.path.isfile(f)) else 0)
elif me == "sudo":
    if a[:2] != ["-l", "-U"]: sys.exit(1)
    u = a[2]
    # a Polish sudo translates its headings unless it runs in C
    may = "may run the following commands" if os.environ.get("LC_ALL") == "C" or not os.environ.get("HB_FAKE_POLISH") \\
        else "może uruchamiać następujące polecenia"
    if os.path.exists(f"{{d}}/sudo-l-{{u}}.txt"):      # what a real sudo printed, given by the test
        print(open(f"{{d}}/sudo-l-{{u}}.txt").read().replace("may run the following commands", may), end=""); sys.exit(0)
    mine = {{primary(u)}} | {{g for g in G if u in G[g]}}
    def applies(who): return who == u or (who.startswith("%") and who[1:] in mine)
    sdir = os.environ["HB_SUDOERS_DIR"]
    files = [os.environ["HB_SUDOERS"]] + [os.path.join(sdir, f) for f in sorted(os.listdir(sdir)) if "." not in f and not f.endswith("~")]
    defaults, bound, cmds = [], [], []
    for f in files:
        for line in open(f).read().splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            if re.match(r"Defaults[>!]", line):
                bound.append(line); continue
            m = re.match(r"Defaults(?::(\\S+))?\\s+(.*)", line)
            if m:
                if m.group(1) is None or applies(m.group(1)): defaults += [e.strip() for e in m.group(2).split(", ")]
                continue
            if line.startswith("Cmnd_Alias"): continue
            who, rest = line.split(None, 1)
            if applies(who): cmds.append(rest.split("=", 1)[1].strip())
    print(f"Matching Defaults entries for {{u}} on box:\\n    " + ", ".join(defaults) + "\\n")
    if bound:
        print(f"Runas and Command-specific defaults for {{u}}:\\n" + "\\n".join("    " + b for b in bound) + "\\n")
    print(f"User {{u}} {{may}} on box:\\n" + "\\n".join("    " + c for c in cmds))
elif me == "hb-totp":
    sys.exit(0 if a[:1] == ["ready"] and all(os.path.exists(f"{{d}}/enrolled/{{u}}") for u in a[1:]) else 1)
"""
PAM_SUDO = """#%PAM-1.0
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    optional     pam_keyinit.so revoke
session    required     pam_limits.so
session    include      system-auth
"""
# /etc/pam.d/sudo-i as Fedora and AL2023 ship it
PAM_SUDO_I = """#%PAM-1.0
auth       include      sudo
account    include      sudo
password   include      sudo
session    optional     pam_keyinit.so force revoke
session    include      sudo
"""
# sudopam.py with its write failing, as a full disk or a read-only /etc would
FAILING_SUDOPAM = """import runpy, sys
if sys.argv[1:2] == ["write"]:
    print("write: no space left on device"); sys.exit(2)
sys.argv[0] = {real!r}
runpy.run_path({real!r}, run_name="__main__")
"""


class Accounts(unittest.TestCase):
    """hb-harden with the account tools faked (no tests of its own)."""
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.bin, self.sudoers_d, self.pam = f"{d}/bin", f"{d}/sudoers.d", f"{d}/pam-sudo"
        for sub in ("bin", "sudoers.d", "enrolled", "libexec", "home"):
            os.makedirs(f"{d}/{sub}")
            os.chmod(f"{d}/{sub}", 0o755)
        with open(f"{self.bin}/accounts", "w") as f:
            f.write(ACCOUNTS.format(d=d))
        os.chmod(f"{self.bin}/accounts", 0o755)
        for name in ("getent", "id", "useradd", "userdel", "groupadd", "usermod", "gpasswd", "visudo", "sudo", "hb-totp"):
            os.symlink("accounts", f"{self.bin}/{name}")
        self.db({"mallory": {"shell": "/bin/bash"}}, {"systemd-journal": [], "docker": [], "microk8s": ["mallory"]})
        with open(f"{d}/sudoers", "w") as f:
            f.write("root ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n")
        with open(self.pam, "w") as f:
            f.write(PAM_SUDO)
        os.chmod(self.pam, 0o644)
        self.pam_i = f"{d}/pam-sudo-i"
        with open(self.pam_i, "w") as f:
            f.write(PAM_SUDO_I)
        self.toml = f"{d}/hb.toml"
        self.config('admins = ["alice"]', 'admin_groups = ["systemd-journal"]', 'admin_not_in = ["docker", "microk8s"]')

    def db(self, users, groups):
        with open(f"{self.d}/db.json", "w") as f:
            json.dump({"users": users, "groups": groups}, f)

    def read_db(self):
        with open(f"{self.d}/db.json") as f:
            return json.load(f)

    def config(self, *lines, extra=""):
        with open(self.toml, "w") as f:
            f.write("[harden]\n" + "".join(f"{line}\n" for line in lines) + extra)

    def tool(self, *args, env=None):
        env = {**os.environ, "HB_CONFIG": self.toml, "HB_STATE": f"{self.d}/state", "HB_SUDOERS": f"{self.d}/sudoers",
               "HB_SUDOERS_DIR": self.sudoers_d, "HB_PAM_SUDO": self.pam, "HB_PAM_SUDO_I": self.pam_i,
               "HB_TOTP": f"{self.bin}/hb-totp",
               "HB_ROOT_ONLY_TOP": self.d, "HB_HOME_BASE": f"{self.d}/home", "PATH": self.bin + os.pathsep + os.environ["PATH"],
               **(env or {})}
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-harden"), *args], env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              start_new_session=True)

    def line(self, item):
        return next(l for l in self.tool("status").stdout.splitlines() if l.split()[1:2] == [item])

    def rule(self):
        with open(f"{self.sudoers_d}/10-hb-admins") as f:
            return f.read()

    def pam_text(self):
        with open(self.pam) as f:
            return f.read()

    def write(self, path, text):
        with open(path, "w") as f:
            f.write(text)


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
class AdminsTest(Accounts):
    def test_not_managed_by_default(self):
        self.config()
        self.assertIn("not managed", self.line("admins"))
        calls = ""
        if os.path.exists(f"{self.d}/calls.log"):
            with open(f"{self.d}/calls.log") as f:
                calls = f.read()
        self.assertNotIn("useradd", calls)

    def test_made_then_ready_once_enrolled(self):
        self.assertIn("todo  admins         group hb-admins; create alice; the sudo rule", self.line("admins"))
        r = self.tool("apply", "--yes")
        db = self.read_db()
        self.assertEqual(db["users"]["alice"], {"shell": "/bin/bash", "home": True})
        self.assertEqual(sorted(g for g, m in db["groups"].items() if "alice" in m), ["hb-admins", "systemd-journal"])
        self.assertIn("alice", db["groups"])                            # their own group (useradd -U)
        self.assertIn("alice can't sudo until enrolled: sudo hb totp enrol alice", r.stdout + r.stderr)
        self.assertEqual(self.rule(), (
            "# Managed by hb harden (harden.admins); changes made here are overwritten.\n"
            f"# Members of hb-admins answer sudo with their code (hb totp, through {self.pam}). After one,\n"
            "# sudo asks again once 60 minutes pass without a sudo, for all of their sessions (sudo -K: at once).\n"
            'Defaults:%hb-admins timestamp_type=global, timestamp_timeout=60, passprompt="[sudo] code for %p: "\n'
            "%hb-admins ALL=(ALL) ALL\n"))
        self.assertEqual(os.stat(f"{self.sudoers_d}/10-hb-admins").st_mode & 0o777, 0o440)
        self.assertEqual([f for f in os.listdir(self.sudoers_d)], ["10-hb-admins"])        # no temp file left
        self.assertIn(f"pam_exec.so quiet expose_authtok {self.bin}/hb-totp verify\nauth       include      system-auth",
                      self.pam_text())
        self.assertIn("[success=ignore auth_err=1 ignore=1 default=die] pam_succeed_if.so quiet user ingroup hb-admins",
                      self.pam_text())
        self.assertEqual(os.stat(self.pam).st_mode & 0o777, 0o644)
        backups = [os.path.join(p, f) for p, _, fs in os.walk(f"{self.d}/state/backup") for f in fs]
        self.assertTrue(any(b.endswith("pam-sudo") for b in backups), backups)
        self.assertIn("todo  admins         alice can't sudo until enrolled in hb totp: sudo hb totp enrol alice",
                      self.line("admins"))
        open(f"{self.d}/enrolled/alice", "w").close()
        self.assertEqual(self.line("admins"), "ok    admins         alice: in hb-admins and systemd-journal, out of docker "
                         "microk8s; sudo takes their code, then stays open 60 idle minutes for all of their sessions")
        before = (self.rule(), self.pam_text())
        self.tool("apply", "--yes")                                     # again: nothing changes
        self.assertEqual((self.rule(), self.pam_text()), before)

    def test_root_without_sudo_and_strangers_are_taken_out(self):
        self.db({"alice": {"shell": "/bin/bash"}, "mallory": {"shell": "/bin/bash"}},
                {"systemd-journal": ["alice"], "docker": ["alice"], "microk8s": [], "hb-admins": ["alice", "mallory"]})
        open(f"{self.d}/enrolled/alice", "w").close()
        self.assertIn("alice out of docker (root without sudo); mallory out of hb-admins (not in harden.admins)",
                      self.line("admins"))
        self.tool("apply", "--yes")
        g = self.read_db()["groups"]
        self.assertEqual((g["docker"], g["hb-admins"]), ([], ["alice"]))
        self.assertTrue(self.line("admins").startswith("ok "))

    def test_primary_groups_count_and_are_refused(self):
        # Codex round 1: getent group lists only the others; gpasswd can't take a primary group away
        self.db({"alice": {"shell": "/bin/bash", "primary": "docker"}}, {"systemd-journal": [], "docker": [], "microk8s": []})
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("alice's primary group is docker (root without sudo); hb doesn't change primary groups", self.line("admins"))
        self.db({"mallory": {"shell": "/bin/bash", "primary": "hb-admins"}},
                {"systemd-journal": [], "docker": [], "microk8s": [], "hb-admins": []})
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("mallory has hb-admins as their primary group but isn't in harden.admins", self.line("admins"))
        self.assertFalse(os.path.exists(f"{self.sudoers_d}/10-hb-admins"))
        self.assertEqual(self.pam_text(), PAM_SUDO)

    def test_settings_elsewhere_that_could_undo_the_gate_are_refused_first(self):
        # Codex rounds 1-2: Defaults outside hb's rule can change the timeout, switch authentication
        # off, exempt the group, or route around the gate (another PAM stack, another account's
        # password); they are refused before anything changes, and found again after
        for line in ("Defaults:%hb-admins timestamp_timeout=-1, !authenticate",
                     "Defaults>root timestamp_timeout=-1",
                     "Defaults:%hb-admins exempt_group=hb-admins",
                     "Defaults:%hb-admins pam_service=system-auth",
                     "Defaults pam_login_service=system-auth",
                     "Defaults:%hb-admins rootpw",
                     "Defaults targetpw"):
            with self.subTest(line):
                self.write(f"{self.sudoers_d}/20-local", line + "\n")
                r = self.tool("apply", "--yes")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn(f"sudo settings outside hb's rule could undo its gate (how long it stays open, whether "
                              f"or how it asks): {self.sudoers_d}/20-local:1:{line}", self.line("admins"))
                self.assertFalse(os.path.exists(f"{self.sudoers_d}/10-hb-admins"))
                self.assertEqual(self.pam_text(), PAM_SUDO)
        self.write(f"{self.sudoers_d}/20-local", "Defaults:%hb-admins exempt_group=hb-admins\n")
        self.assertIn(f"{self.sudoers_d}/20-local: Defaults:%hb-admins exempt_group=hb-admins", self.line("nopasswd"))

    def test_what_sudo_reports_decides(self):
        # Codex round 2: the Runas and command-specific Defaults sudo prints between the sections
        self.tool("apply", "--yes")
        open(f"{self.d}/enrolled/alice", "w").close()
        self.assertTrue(self.line("admins").startswith("ok "))
        listing = ("Matching Defaults entries for alice on box:\n    env_reset, timestamp_type=global, timestamp_timeout=60\n\n"
                   "Runas and Command-specific defaults for alice:\n    Defaults>root timestamp_timeout=-1, rootpw\n"
                   "    Defaults!/usr/bin/x pam_service=other, exempt_group=hb-admins\n\n"
                   "User alice may run the following commands on box:\n    (ALL) ALL\n")
        self.write(f"{self.d}/sudo-l-alice.txt", listing)
        line = self.line("admins")
        self.assertTrue(line.startswith("FAIL"), line)
        for want in ("timestamp_timeout=-1, not 60", "rootpw (sudo would ask for another account's password",
                     "pam_service=other (another PAM stack", "exempt_group=hb-admins (sudo asks its members nothing)"):
            self.assertIn(want, line)
        self.write(f"{self.d}/sudo-l-alice.txt", listing.split("Runas")[0] +
                   "User alice may run the following commands on box:\n    (ALL) ALL\n    (ALL) NOPASSWD: ALL\n")
        self.assertIn("a rule lets them in without the code: (ALL) NOPASSWD: ALL", self.line("admins"))

    def test_rules_naming_the_groups_are_refused_before_anyone_joins(self):
        # Codex round 3: joining a group brings its rules; refused before any membership changes
        journal_gid = 2000 + zlib.crc32(b"systemd-journal") % 50000          # the fake's group ids
        for line in ("%hb-admins ALL=(ALL) NOPASSWD: ALL", "%:systemd-journal ALL=(ALL) ALL",
                     f"%#{journal_gid} ALL=(ALL) NOPASSWD: ALL",                  # Codex round 4: by number
                     "alice ALL=(ALL) NOPASSWD: ALL", "%alice ALL=(ALL) ALL",       # the account and its own group
                     "User_Alias OPS = bob, alice"):
            with self.subTest(line):
                self.write(f"{self.sudoers_d}/20-local", line + "\n")
                r = self.tool("apply", "--yes")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn(f"sudo rules outside hb's name an admin, their own group or a group they would be in, "
                              f"and would apply to them: {self.sudoers_d}/20-local:1:{line}", self.line("admins"))
                self.assertNotIn("alice", self.read_db()["users"])
        self.write(f"{self.sudoers_d}/20-local", "%hb-adminsX ALL=(ALL) ALL\nmalice ALL=(ALL) ALL\n")   # other names
        self.assertNotIn("sudo rules outside hb's", self.line("admins"))

    def test_sudoers_is_read_as_sudo_reads_it(self):
        # Codex round 6: a '#' before digits is a uid, not a comment, and a line ending in a
        # backslash goes on in the next: the one-line greps missed what came after either
        for text, kind, found in (
                ("#1002, alice ALL=(ALL) NOPASSWD: ALL", "rules", "1:#1002, alice ALL=(ALL) NOPASSWD: ALL"),
                ("Defaults:#1002 timestamp_timeout=-1", "settings", "1:Defaults:#1002 timestamp_timeout=-1"),
                ("Defaults:%hb-admins \\\n  timestamp_timeout=-1", "settings", "1:Defaults:%hb-admins timestamp_timeout=-1"),
                ("@include /etc/sudoers.local", "settings",
                 "1: @include /etc/sudoers.local has sudo read rules hb doesn't check: review by hand")):
            with self.subTest(text):
                self.write(f"{self.sudoers_d}/20-local", text + "\n")
                r = self.tool("apply", "--yes")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn(f"sudo {kind} outside hb's", self.line("admins"))
                self.assertIn(f"{self.sudoers_d}/20-local:{found}", self.line("admins"))
                self.assertNotIn("alice", self.read_db()["users"])
        self.write(f"{self.sudoers_d}/20-local", "# alice may \\\nmalice ALL=(ALL) ALL\n")     # a comment never goes on
        self.assertNotIn("outside hb's", self.line("admins"))

    def test_a_failure_after_joining_takes_the_memberships_back(self):
        # Codex round 3: taking hb's rule out isn't enough when membership brings other rules
        self.write(f"{self.d}/sudo-l-alice.txt",
                   "Matching Defaults entries for alice on box:\n    timestamp_type=global, timestamp_timeout=60\n\n"
                   "User alice may run the following commands on box:\n    (ALL) ALL\n    (ALL) NOPASSWD: ALL\n")
        r = self.tool("apply", "--yes")
        self.assertIn("a rule lets them in without the code: (ALL) NOPASSWD: ALL: taking", r.stdout + r.stderr)
        self.assertIn("took back the memberships this apply added: alice:hb-admins alice:systemd-journal", r.stdout + r.stderr)
        self.assertIn("deleted alice again, made by this apply", r.stdout + r.stderr)    # Codex round 4
        self.assertFalse(os.path.exists(f"{self.sudoers_d}/10-hb-admins"))
        db = self.read_db()
        self.assertEqual((db["groups"]["hb-admins"], db["groups"]["systemd-journal"]), ([], []))
        self.assertNotIn("alice", db["users"])

    def test_a_half_made_account_goes_again(self):
        # Codex round 5: useradd writes the account, then fails on the home (exit 12)
        open(f"{self.d}/useradd-fails-home", "w").close()
        r = self.tool("apply", "--yes")
        self.assertIn("useradd alice failed", r.stdout + r.stderr)
        self.assertIn("deleted alice again, made by this apply", r.stdout + r.stderr)
        self.assertNotIn("alice", self.read_db()["users"])

    def test_a_home_without_its_account_is_left_alone(self):
        # Codex round 5: useradd -m adopts it, and a rollback's userdel -r would remove it
        os.makedirs(f"{self.d}/home/alice")
        self.write(f"{self.d}/home/alice/notes", "kept\n")
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn(f"{self.d}/home/alice exists, but there's no account alice: move it away first", self.line("admins"))
        self.assertNotIn("alice", self.read_db()["users"])
        self.assertTrue(os.path.exists(f"{self.d}/home/alice/notes"))

    def test_the_timestamp_records_have_to_stay_roots(self):
        # Codex round 5: a timestamp owner other than root could write an unlock
        line = "Defaults timestampowner=nobody, timestampdir=/var/tmp/nobody-ts"
        self.write(f"{self.sudoers_d}/20-local", line + "\n")
        self.assertIn(f"{self.sudoers_d}/20-local:1:{line}", self.line("admins"))
        os.unlink(f"{self.sudoers_d}/20-local")
        self.tool("apply", "--yes")
        open(f"{self.d}/enrolled/alice", "w").close()
        self.write(f"{self.d}/sudo-l-alice.txt",
                   "Matching Defaults entries for alice on box:\n    timestamp_type=global, timestamp_timeout=60, "
                   "timestampowner=nobody\n\nUser alice may run the following commands on box:\n    (ALL) ALL\n")
        self.assertIn("timestampowner=nobody (whoever owns the records could write an unlock)", self.line("admins"))

    def test_the_check_runs_even_with_the_rule_unchanged(self):
        # Codex round 4: a new admin group changes what applies while hb's rule stays the same
        self.tool("apply", "--yes")
        open(f"{self.d}/enrolled/alice", "w").close()
        self.assertTrue(self.line("admins").startswith("ok "))
        db = self.read_db()
        db["groups"]["ops-readers"] = []
        self.db(db["users"], db["groups"])
        self.config('admins = ["alice"]', 'admin_groups = ["systemd-journal", "ops-readers"]', 'admin_not_in = ["docker", "microk8s"]')
        self.write(f"{self.d}/sudo-l-alice.txt",
                   "Matching Defaults entries for alice on box:\n    timestamp_type=global, timestamp_timeout=60\n\n"
                   "User alice may run the following commands on box:\n    (ALL) ALL\n    (ALL) NOPASSWD: ALL\n")
        rule = self.rule()
        r = self.tool("apply", "--yes")
        self.assertIn("took back the memberships this apply added: alice:ops-readers", r.stdout + r.stderr)
        self.assertEqual(self.read_db()["groups"]["ops-readers"], [])
        self.assertEqual(self.rule(), rule)                                 # hb's rule was there before: it stays
        self.assertIn("alice", self.read_db()["users"])                     # and so does the account

    def test_tty_tickets_counts(self):
        # Codex round 4: !tty_tickets turns a per-terminal unlock into a shared one
        self.config('admins = ["alice"]', "admin_sudo_shared = false")
        self.write(f"{self.sudoers_d}/20-local", "Defaults>root !tty_tickets\n")
        self.assertIn(f"{self.sudoers_d}/20-local:1:Defaults>root !tty_tickets", self.line("admins"))
        os.unlink(f"{self.sudoers_d}/20-local")
        self.tool("apply", "--yes")
        open(f"{self.d}/enrolled/alice", "w").close()
        self.write(f"{self.d}/sudo-l-alice.txt",
                   "Matching Defaults entries for alice on box:\n    timestamp_type=tty, timestamp_timeout=60\n\n"
                   "Runas and Command-specific defaults for alice:\n    Defaults>root !tty_tickets\n\n"
                   "User alice may run the following commands on box:\n    (ALL) ALL\n")
        self.assertIn("tty_tickets set (it changes timestamp_type)", self.line("admins"))

    def test_sudo_i_has_to_reach_the_gate(self):
        # Codex round 3: sudo -i asks with its own service, whatever the Defaults say
        for text in ("auth include system-auth\n", "auth sufficient pam_unix.so\n" + PAM_SUDO_I, ""):
            with self.subTest(text):
                self.write(self.pam_i, text)
                r = self.tool("apply", "--yes")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("(what sudo -i asks with) authenticates other than by 'auth include sudo' alone", self.line("admins"))
                self.assertEqual(self.pam_text(), PAM_SUDO)
        os.unlink(self.pam_i)
        self.assertIn("which sudo -i uses", self.line("admins"))

    def test_sudos_listing_is_read_in_c(self):
        # Codex round 3: a translated heading hid the commands
        self.tool("apply", "--yes", env={"HB_FAKE_POLISH": "1", "LANG": "pl_PL.UTF-8"})
        open(f"{self.d}/enrolled/alice", "w").close()
        r = self.tool("status", env={"HB_FAKE_POLISH": "1", "LANG": "pl_PL.UTF-8"})
        self.assertIn("ok    admins ", r.stdout)

    def test_changing_the_group_never_leaves_a_grant_without_its_gate(self):
        # Codex round 2: the gate moved to the new group while the old rule still granted the old one
        open(f"{self.d}/enrolled/alice", "w").close()
        open(f"{self.d}/enrolled/mallory", "w").close()
        self.db({"mallory": {"shell": "/bin/bash"}}, {"systemd-journal": [], "docker": [], "microk8s": []})
        self.config('admins = ["alice", "mallory"]')
        self.tool("apply", "--yes")
        self.assertIn("%hb-admins ALL=(ALL) ALL", self.rule())
        self.config('admins = ["alice"]', 'admin_group = "ops"')
        open(f"{self.d}/visudo-refuses-files", "w").close()
        self.tool("apply", "--yes")                                        # the new rule refused: nothing moves
        self.assertIn("%hb-admins ALL=(ALL) ALL", self.rule())
        self.assertIn("ingroup hb-admins", self.pam_text())
        os.unlink(f"{self.d}/visudo-refuses-files")
        fake = f"{self.d}/sudopam-failing.py"
        self.write(fake, FAILING_SUDOPAM.format(real=os.path.join(REPO, "lib", "hbkit", "sudopam.py")))
        r = self.tool("apply", "--yes", env={"HB_SUDOPAM": fake})          # the gate can't move: no grant left
        self.assertIn("took hb-admins's sudo away first: the code gate moves to ops", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(f"{self.sudoers_d}/10-hb-admins"))
        self.assertIn("ingroup hb-admins", self.pam_text())
        self.tool("apply", "--yes")
        self.assertIn("%ops ALL=(ALL) ALL", self.rule())
        self.assertIn("ingroup ops", self.pam_text())
        self.assertNotIn("ingroup hb-admins", self.pam_text())

    def test_per_terminal_and_every_time(self):
        self.config('admins = ["alice"]', "admin_sudo_shared = false", 'admin_group = "ops"', 'admin_shell = "/bin/sh"')
        self.tool("apply", "--yes")
        self.assertIn("Defaults:%ops timestamp_type=tty, timestamp_timeout=60,", self.rule())
        self.assertIn("in the terminal it was typed in", self.rule())
        self.assertIn("ingroup ops", self.pam_text())
        self.assertEqual(self.read_db()["users"]["alice"]["shell"], "/bin/sh")
        open(f"{self.d}/enrolled/alice", "w").close()
        self.assertIn("stays open 60 idle minutes in that terminal", self.line("admins"))
        self.config('admins = ["alice"]', "admin_sudo_minutes = 0", 'admin_group = "ops"', 'admin_shell = "/bin/sh"')
        self.tool("apply", "--yes")
        self.assertIn("timestamp_type=global, timestamp_timeout=0,", self.rule())
        self.assertIn("sudo asks for one every time", self.rule())
        self.assertEqual(self.pam_text().count("pam_succeed_if"), 1)
        self.assertIn("sudo takes their code every time", self.line("admins"))

    def test_refusals_change_nothing(self):
        cases = (('admins = ["root"]', "root can't be one"),
                 ('admins = ["rescue"]', "break-glass account"),
                 ('admins = ["Alice!"]', "isn't a login name"),
                 ('admins = ["alice"]\nadmin_groups = ["nosuch"]', "there's no group nosuch"),
                 ('admins = ["alice"]\nadmin_groups = ["docker"]\nadmin_not_in = ["docker"]', "in both"),
                 ('admins = ["alice"]\nadmin_not_in = ["hb-admins"]', "names hb-admins itself"),
                 ('admins = ["alice"]\nadmin_sudo_minutes = -5', "whole number"),
                 ('admins = ["alice"]\nadmin_shell = "/nonexistent/sh"', "isn't a program"))
        for conf, want in cases:
            with self.subTest(conf):
                self.config(conf, extra='[breakglass]\nuser = "rescue"\n')
                r = self.tool("apply", "--yes")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn(want, self.line("admins"))
                self.assertEqual(self.pam_text(), PAM_SUDO)
                self.assertFalse(os.path.exists(f"{self.sudoers_d}/10-hb-admins"))
                self.assertNotIn("alice", self.read_db()["users"])
        for pam, want in (("@include common-auth\n", "exactly one 'auth include system-auth'"),
                          ("auth sufficient pam_unix.so\n" + PAM_SUDO, "an auth line comes before"),
                          ("AUTH sufficient pam_unix.so\n" + PAM_SUDO, "an auth line comes before")):
            self.write(self.pam, pam)
            self.config('admins = ["alice"]')
            self.assertIn(want, self.line("admins"))

    def test_the_code_checker_has_to_be_roots_alone(self):
        # Codex round 1: applied from a checkout, sudo's PAM file would run a user's program as root
        os.chmod(f"{self.bin}/accounts", 0o777)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn(f"the code checker {self.bin}/hb-totp can be changed by others ({self.bin}/accounts can be written "
                      "by anyone): apply with the installed hb", self.line("admins"))
        self.assertEqual(self.pam_text(), PAM_SUDO)
        self.assertNotIn("alice", self.read_db()["users"])

    def test_a_failed_pam_write_installs_no_rule(self):
        # Codex round 1: the rule goes in only after the code check, so a password never gets a chance
        fake = f"{self.d}/sudopam-failing.py"
        self.write(fake, FAILING_SUDOPAM.format(real=os.path.join(REPO, "lib", "hbkit", "sudopam.py")))
        r = self.tool("apply", "--yes", env={"HB_SUDOPAM": fake})
        self.assertIn("sudo's PAM file not changed, so neither is the rule", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(f"{self.sudoers_d}/10-hb-admins"))
        self.assertEqual(self.pam_text(), PAM_SUDO)
        self.assertNotIn("alice", self.read_db()["groups"]["hb-admins"])       # and the membership back out

    def test_a_rule_visudo_refuses_isnt_installed(self):
        open(f"{self.d}/visudo-refuses-files", "w").close()
        r = self.tool("apply", "--yes")
        self.assertIn("visudo rejects the rule; nothing changed", r.stdout + r.stderr)
        self.assertEqual(os.listdir(self.sudoers_d), [])                   # neither the rule nor its temp file
        self.assertEqual(self.pam_text(), PAM_SUDO)                          # the rule is checked before anything moves

    def test_a_set_visudo_refuses_takes_hbs_rule_back_out(self):
        self.config('admins = ["alice"]', 'admin_group = "BROKEN"')       # visudo here refuses "BROKEN"
        self.assertIn("isn't a group name", self.line("admins"))           # caught before visudo
        self.config('admins = ["alice"]', 'admin_shell = "/bin/sh"')
        with open(f"{self.d}/sudoers", "a") as f:
            f.write("# BROKEN\n")                                          # the whole set then fails visudo -cq
        r = self.tool("apply", "--yes")
        self.assertIn("visudo reports an error in the sudo rules with hb's: taking", r.stdout + r.stderr)
        self.assertIn("admins: not applied", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(f"{self.sudoers_d}/10-hb-admins"))
        with open(f"{self.d}/sudoers") as f:                               # a rule that was there comes back as it was
            text = f.read()
        self.write(f"{self.d}/sudoers", text.replace("# BROKEN\n", ""))
        self.tool("apply", "--yes")
        good = self.rule()
        self.config('admins = ["alice"]', 'admin_shell = "/bin/sh"', "admin_sudo_minutes = 30")
        self.write(f"{self.d}/sudoers", text)
        r = self.tool("apply", "--yes")
        self.assertIn("putting", r.stdout + r.stderr)
        self.assertEqual(self.rule(), good)


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
class NopasswdTest(Accounts):
    def setUp(self):
        super().setUp()
        self.helper = f"{self.d}/libexec/net-helper"
        self.write(self.helper, "#!/bin/sh\n")
        os.chmod(self.helper, 0o755)
        self.write(f"{self.sudoers_d}/90-cloud-init-users", "ec2-user ALL=(ALL) NOPASSWD:ALL\n")
        self.write(f"{self.sudoers_d}/svc", f"Defaults:svc !pam_session\nsvc ALL=(root) NOPASSWD: {self.helper}\n")

    def allow(self, *rules):
        self.config("nopasswd_allowed = [" + ", ".join(json.dumps(r) for r in rules) + "]")

    def only_svc(self, rule_line, allowed=None):
        if os.path.exists(f"{self.sudoers_d}/90-cloud-init-users"):
            os.unlink(f"{self.sudoers_d}/90-cloud-init-users")
        self.write(f"{self.sudoers_d}/svc", rule_line + "\n")
        self.allow(allowed or rule_line)
        return self.line("nopasswd")

    def test_only_rules_written_out_pass(self):
        self.allow(f"svc   ALL=(root)  NOPASSWD:   {self.helper}")                    # spaces don't count
        line = self.line("nopasswd")
        self.assertTrue(line.startswith("FAIL"), line)
        self.assertIn(f"{self.sudoers_d}/90-cloud-init-users: ec2-user ALL=(ALL) NOPASSWD:ALL", line)
        self.assertNotIn("svc ALL", line)
        os.unlink(f"{self.sudoers_d}/90-cloud-init-users")
        self.assertEqual(self.line("nopasswd"),
                         "ok    nopasswd       no NOPASSWD rules beyond files listed for removal and 1 allowed in harden.nopasswd_allowed")
        self.config()
        self.assertIn(f"rules that skip the password: {self.sudoers_d}/svc: svc ALL=(root) NOPASSWD: {self.helper}",
                      self.line("nopasswd"))

    def test_an_allowed_rule_fails_when_others_can_change_what_it_runs(self):
        rule = f"svc ALL=(root) NOPASSWD: {self.helper}"
        os.chmod(self.helper, 0o777)
        self.assertIn(f"{self.helper} can be written by anyone, and an allowed rule runs it", self.only_svc(rule))
        os.chmod(self.helper, 0o1777)                     # Codex round 1: a sticky bit doesn't protect a file
        self.assertIn(f"{self.helper} can be written by anyone", self.line("nopasswd"))
        os.chmod(self.helper, 0o755)
        os.chmod(f"{self.d}/libexec", 0o777)
        self.assertIn(f"{self.d}/libexec can be written by anyone", self.line("nopasswd"))
        os.chmod(f"{self.d}/libexec", 0o1777)             # a sticky folder keeps root's entries in it root's
        self.assertTrue(self.line("nopasswd").startswith("ok "))

    def test_a_link_counts_with_the_folder_it_sits_in(self):
        # Codex round 1: resolving the link first hid who can replace it
        os.makedirs(f"{self.d}/open")
        os.chmod(f"{self.d}/open", 0o777)
        os.symlink(self.helper, f"{self.d}/open/helper")
        self.assertIn(f"{self.d}/open can be written by anyone", self.only_svc(f"svc ALL=(root) NOPASSWD: {self.d}/open/helper"))
        os.chmod(f"{self.d}/open", 0o755)
        self.assertTrue(self.line("nopasswd").startswith("ok "))         # a link in root's folder to root's program

    def test_aliases_and_other_forms_are_refused(self):
        # Codex round 1: an alias names no path, so nothing was checked
        for rule, want in ((f"svc ALL=(root) NOPASSWD: NET_HELPER", "isn't a program's full path"),
                           ("svc ALL=(root) NOPASSWD: ALL", "isn't a program's full path"),
                           (f"svc ALL=(root) NOPASSWD: {self.d}/libexec/*", "is a pattern"),
                           (f"svc ALL=(root) NOPASSWD:SETENV: {self.helper}", "':', '=' or")):
            with self.subTest(rule):
                self.assertIn(want, self.only_svc(rule))

    def test_what_an_argument_names_counts_and_interpreters_are_refused(self):
        # Codex round 4: /usr/bin/bash /home/svc/job.sh checked only bash
        data = f"{self.d}/libexec/job.conf"
        self.write(data, "x\n")
        os.chmod(data, 0o666)
        self.assertIn(f"{data} can be written by anyone, and an allowed rule runs it",
                      self.only_svc(f"svc ALL=(root) NOPASSWD: {self.helper} {data}"))
        os.chmod(data, 0o644)
        self.assertTrue(self.line("nopasswd").startswith("ok "))
        self.assertIn("runs whatever it is given", self.only_svc(f"svc ALL=(root) NOPASSWD: /usr/bin/bash {data}"))

    def test_switching_authentication_off_counts(self):
        os.unlink(f"{self.sudoers_d}/90-cloud-init-users")
        self.allow(f"svc ALL=(root) NOPASSWD: {self.helper}")
        self.write(f"{self.sudoers_d}/20-quiet", "Defaults:svc !authenticate\n")
        self.assertIn(f"{self.sudoers_d}/20-quiet: Defaults:svc !authenticate", self.line("nopasswd"))
        self.allow(f"svc ALL=(root) NOPASSWD: {self.helper}", "Defaults:svc !authenticate")
        self.assertIn("hb checks allowed rules of one form only", self.line("nopasswd"))

    def test_sudoers_is_read_as_sudo_reads_it(self):
        # Codex round 6: "#1000" is a uid (not a comment), a backslash goes on in the next line,
        # a comment never does; the one-line grep missed the first three
        os.unlink(f"{self.sudoers_d}/90-cloud-init-users")
        self.allow(f"svc ALL=(root) NOPASSWD: {self.helper}")
        for text, found in (("#1000 ALL=(ALL) NOPASSWD: ALL", "#1000 ALL=(ALL) NOPASSWD: ALL"),
                            ("bob ALL=(#0) NOPASSWD: ALL", "bob ALL=(#0) NOPASSWD: ALL"),
                            ("Defaults:bob !\\\n   authenticate", "Defaults:bob ! authenticate"),
                            ("# bob may \\\nbob ALL=(ALL) NOPASSWD: ALL", "bob ALL=(ALL) NOPASSWD: ALL")):
            with self.subTest(text):
                self.write(f"{self.sudoers_d}/20-local", text + "\n")
                self.assertIn(f"rules that skip the password: {self.sudoers_d}/20-local: {found}", self.line("nopasswd"))
        self.write(f"{self.sudoers_d}/20-local", "@include /etc/sudoers.local\n")
        self.assertIn(f"{self.sudoers_d}/20-local:1: @include /etc/sudoers.local has sudo read rules hb doesn't check",
                      self.line("nopasswd"))
        os.unlink(f"{self.sudoers_d}/20-local")
        # the allowed rule, continued and with a comment: as sudo reads it, it's the one written out
        self.write(f"{self.sudoers_d}/svc", f"svc ALL=(root) \\\n    NOPASSWD: {self.helper}   # the net helper\n")
        self.assertTrue(self.line("nopasswd").startswith("ok "), self.line("nopasswd"))

    def test_a_sudoers_hb_cant_read_fails(self):
        # it passed as "ok", with grep's "Permission denied" in the line
        if not os.path.exists("/etc/shadow") or os.access("/etc/shadow", os.R_OK):
            self.skipTest("needs a file only the real root can read")
        out = self.tool("status", env={"HB_SUDOERS": "/etc/shadow"}).stdout
        line = next(l for l in out.splitlines() if l.split()[1:2] == ["nopasswd"])
        self.assertTrue(line.startswith("FAIL") and "/etc/shadow: Permission denied" in line, line)

    def test_the_program_sudo_runs_is_the_one_checked(self):
        # Codex round 6: sudo runs net-helper for "net-helper#x" ('#' starts its comment), and hb
        # checked the file net-helper#x, which can be root's while net-helper isn't
        self.write(f"{self.helper}#x", "#!/bin/sh\n")
        os.chmod(f"{self.helper}#x", 0o755)
        os.chmod(self.helper, 0o777)
        rule = f"svc ALL=(root) NOPASSWD: {self.helper}#x"
        self.assertIn(f"rules that skip the password: {self.sudoers_d}/svc: svc ALL=(root) NOPASSWD: {self.helper}",
                      self.only_svc(rule))
        self.assertIn(f"{self.helper} can be written by anyone, and an allowed rule runs it",
                      self.only_svc(rule, allowed=f"svc ALL=(root) NOPASSWD: {self.helper}"))

    def test_an_acl_counts(self):
        # Codex round 1: the group bits of a file with an ACL are its mask, so they hide named writers
        rule = f"svc ALL=(root) NOPASSWD: {self.helper}"
        self.assertTrue(self.only_svc(rule).startswith("ok "))
        # what setfacl -m u:65534:rwx writes: owner rwx, user 65534 rwx, group r-x, mask rwx, other r-x
        acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, perm, uid) for tag, perm, uid in (
            (0x01, 7, 0xFFFFFFFF), (0x02, 7, 65534), (0x04, 5, 0xFFFFFFFF), (0x10, 7, 0xFFFFFFFF), (0x20, 5, 0xFFFFFFFF)))
        try:
            os.setxattr(self.helper, "system.posix_acl_access", acl)
        except OSError as e:
            self.skipTest(f"the file system takes no ACLs: {e}")
        self.assertEqual(os.stat(self.helper).st_mode & 0o777, 0o775)       # the mask shows as the group bits
        self.assertIn(f"{self.helper} has an access ACL", self.line("nopasswd"))

    def test_files_listed_for_removal_dont_count(self):
        self.config(f'remove_files = ["{self.sudoers_d}/90-cloud-init-users"]',
                    f'nopasswd_allowed = ["svc ALL=(root) NOPASSWD: {self.helper}"]')
        self.assertTrue(self.line("nopasswd").startswith("ok "))


if __name__ == "__main__":
    unittest.main()
