"""Phase 6: hb-upgrade's night (commands faked), the busy.d checks on fake inputs, the digest and its banner line."""
import contextlib
import datetime
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO, load_tool, temp_state  # noqa: E402

up = load_tool("upgrade")
digest = load_tool("digest")
status = load_tool("status")
BUSY = os.path.join(REPO, "busy.d")
NIGHT = datetime.datetime.combine(datetime.date.today(), datetime.time(5, 0))   # inside the 07:00 window

SNAP_LIST = """Name      Version   Rev    Tracking       Publisher    Notes
core22    20260824  2955   latest/stable  canonical**  base
microk8s  v1.35.6   9072   1.35/stable    canonical**  classic,held
snapd     2.77.1    28254  latest/stable  canonical**  snapd
"""


def cfg(**over):
    c = {"upgrade": {"enabled": True, "window_end": "07:00", "snaps": ["microk8s", "snapd"], "snapshot_days": 3,
                     "force_after_days": 0},
         "snapshot": {"dir": tempfile.mkdtemp(), "keep_days": 14}, "digest": {"reminders": []}}
    c["upgrade"].update(over)
    return c


class Fake:
    """Answers util.run for the commands a night uses, and records them."""

    def __init__(self):
        self.calls, self.restart = [], 1        # dnf needs-restarting -r: 1 = reboot needed
        self.dnf_rc, self.kernel, self.rpm_fails = 0, os.uname().release, False
        self.rpm = ["bash.x86_64 5.2-1", "kernel-core.x86_64 7.2.13-200"]

    def __call__(self, *cmd, **kw):
        self.calls.append(cmd)
        if cmd[:2] == ("rpm", "-qa"):
            return 0, "\n".join(self.rpm) + "\n", ""
        if cmd[:3] == ("dnf", "upgrade", "--refresh"):
            if self.dnf_rc == 0:
                self.rpm = ["bash.x86_64 5.2-2", "kernel-core.x86_64 7.2.14-200"]
            return self.dnf_rc, "", "Error: cannot download repomd.xml" if self.dnf_rc else ""
        if cmd[:2] == ("dnf", "needs-restarting"):
            return self.restart, "Reboot is required to fully utilize these updates.\n" if self.restart else "", ""
        if cmd[:3] == ("rpm", "-q", "kernel-core"):
            if self.rpm_fails:
                return 1, "", "error: rpmdb open failed"
            return 0, f"kernel-core-{self.kernel}  Sun 01 Nov 2026\n", ""
        if cmd[:2] == ("snap", "list"):
            return 0, SNAP_LIST, ""
        return 0, "", ""

    def did(self, *prefix):
        return any(c[:len(prefix)] == prefix for c in self.calls)


class UpgradeTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.fake, self.busy, self.notes = Fake(), [], []
        for name, val in (("run", self.fake), ("busy", lambda: list(self.busy)), ("ask", lambda q: False),
                          ("notify", lambda *a: self.notes.append(a))):
            self.addCleanup(setattr, up.util, name, getattr(up.util, name))
            setattr(up.util, name, val)

    def test_snap_holds(self):
        rc, line = up.chk_snaps(cfg())
        self.assertEqual(rc, 1)
        self.assertIn("snapd", line)
        self.assertNotIn("microk8s", line)                     # already held
        self.assertEqual(up.chk_snaps(cfg(snaps=["microk8s"]))[0], 0)
        self.assertEqual(up.chk_snaps(cfg(snaps=["lxd"]))[0], 2)

    def test_reboot_reason(self):
        why, unknown = up.reboot_reason()
        self.assertIn("Reboot is required", why)
        self.assertIsNone(unknown)
        self.fake.restart = 0
        self.assertEqual(up.reboot_reason(), (None, None))
        self.fake.kernel = "9.9.9-1.fc44.x86_64"               # a newer kernel than the one running
        self.assertIn("9.9.9", up.reboot_reason()[0])
        self.fake.restart = 2                                  # dnf itself failed: the kernel comparison decides
        self.assertIn("9.9.9", up.reboot_reason()[0])

    def test_a_reboot_check_that_cant_answer_says_so(self):
        for rc, text in ((2, "exit 2"), (127, "not installed"), (124, "timed out")):
            self.fake.restart = rc
            self.assertEqual(up.reboot_reason(), (None, f"dnf needs-restarting -r: {text}"))
        self.fake.restart, self.fake.rpm_fails = 0, True       # dnf says no, but the kernel list is unreadable
        self.assertEqual(up.reboot_reason(), (None, "rpm can't list kernel-core (exit 1)"))
        self.fake.rpm_fails = False
        c = cfg(snaps=["microk8s"])                            # held already, so only the reboot speaks
        self.fake.restart = 127
        self.assertEqual(up.do_run(c, now=NIGHT), 0)           # no reboot: nothing says one is needed
        self.assertFalse(self.fake.did("systemctl", "reboot"))
        rc, line = up.verdict(c)
        self.assertEqual(rc, 1)
        self.assertIn("can't tell whether a reboot is needed: dnf needs-restarting -r: not installed", line)
        self.fake.restart = 0                                  # the next night it answers: ok again
        up.save_state({**up.load_state(), "night": "earlier"})
        up.do_run(c, now=NIGHT)
        self.assertEqual(up.verdict(c)[0], 0)

    def test_window(self):
        self.assertTrue(up.in_window(cfg(), datetime.datetime(2026, 11, 2, 4, 30)))
        self.assertFalse(up.in_window(cfg(), datetime.datetime(2026, 11, 2, 7, 0)))

    def test_busy_night_then_idle(self):
        c = cfg()
        self.busy = ["tmux session web runs claude"]
        self.assertEqual(up.do_run(c, now=NIGHT), 0)
        st = up.load_state()
        self.assertEqual(st["dnf"]["changed"], ["bash.x86_64", "kernel-core.x86_64"])
        self.assertEqual(st["reboot"]["busy"], "tmux session web runs claude")
        self.assertFalse(self.fake.did("systemctl", "reboot"))
        self.assertFalse(self.fake.did("snap", "refresh", "microk8s"))    # a microk8s refresh waits too
        self.assertTrue(self.fake.did(up.util.HB, "snapshot", "create", "upgrade"))
        dnf_runs = sum(1 for c_ in self.fake.calls if c_[:2] == ("dnf", "upgrade"))
        self.busy = []                                                  # 30 minutes later: idle
        up.do_run(c, now=NIGHT)
        self.assertEqual(sum(1 for c_ in self.fake.calls if c_[:2] == ("dnf", "upgrade")), dnf_runs)  # once a night
        self.assertTrue(self.fake.did("snap", "refresh", "microk8s", "snapd"))
        self.assertTrue(self.fake.did("systemctl", "reboot"))
        self.assertIn("rebooted_at", up.load_state()["reboot"])

    def test_no_reboot_needed(self):
        self.fake.restart, self.fake.kernel = 0, os.uname().release
        self.assertEqual(up.do_run(cfg(), now=NIGHT), 0)
        self.assertFalse(self.fake.did("systemctl", "reboot"))
        self.assertTrue(up.verdict(cfg(snaps=["microk8s"]))[1].startswith("ok: "))

    def test_forced_after_days(self):
        self.busy = ["load 3.1"]
        up.save_state({"night": datetime.date.today().isoformat(), "dnf": {"at": int(time.time()), "rc": 0},
                       "snaps": {"at": 1, "rc": 0}, "reboot": {"needed_since": int(time.time()) - 9 * 86400}})
        self.assertEqual(up.verdict(cfg(snaps=["microk8s"]))[0], 1)                      # waiting more than 7 days: shown
        up.do_run(cfg(force_after_days=0), now=NIGHT)
        self.assertFalse(self.fake.did("systemctl", "reboot"))
        up.do_run(cfg(force_after_days=8), now=NIGHT)
        self.assertTrue(self.fake.did("systemctl", "reboot"))
        self.assertTrue(any(n[1] == "upgrade.reboot" and n[0] == "warn" for n in self.notes))

    def test_dnf_failure(self):
        self.fake.dnf_rc, self.fake.restart = 1, 0
        self.assertEqual(up.do_run(cfg(), now=NIGHT), 2)
        self.assertEqual(self.notes[0][:2], ("warn", "upgrade.dnf"))
        self.assertEqual(up.verdict(cfg(snaps=["microk8s"]))[0], 2)

    def test_outside_the_window_does_nothing(self):
        c = cfg(window_end="00:00")
        self.assertEqual(up.do_run(c, now=NIGHT), 0)
        self.assertEqual(self.fake.calls, [])

    def test_old_upgrade_snapshots_go(self):
        c = cfg()
        old = (datetime.datetime.now() - datetime.timedelta(days=5)).strftime("%Y%m%d-%H%M")
        new = datetime.datetime.now().strftime("%Y%m%d-%H%M")
        for n in (f"upgrade-{old}", f"upgrade-{new}", f"phase1-{old}"):
            os.mkdir(os.path.join(c["snapshot"]["dir"], n))
        up.snapshot(c)
        deleted = [x[3] for x in self.fake.calls if x[:3] == ("btrfs", "subvolume", "delete")]
        self.assertEqual([os.path.basename(p) for p in deleted], [f"upgrade-{old}"])

    def test_zero_days_means_no_snapshot_and_none_left(self):
        c = cfg(snapshot_days=0)
        old = (datetime.datetime.now() - datetime.timedelta(days=5)).strftime("%Y%m%d-%H%M")
        new = datetime.datetime.now().strftime("%Y%m%d-%H%M")
        for n in (f"upgrade-{old}", f"upgrade-{new}", f"phase1-{old}"):
            os.mkdir(os.path.join(c["snapshot"]["dir"], n))
        up.snapshot(c)
        self.assertFalse(any("create" in x for x in self.fake.calls), self.fake.calls)
        deleted = sorted(os.path.basename(x[3]) for x in self.fake.calls if x[:3] == ("btrfs", "subvolume", "delete"))
        self.assertEqual(deleted, sorted([f"upgrade-{old}", f"upgrade-{new}"]))   # hb snapshot's own stay

    def test_hold(self):
        self.assertEqual(up.do_hold("2h"), 0)
        r = subprocess.run([os.path.join(BUSY, "hold")], env={**os.environ, "HB_STATE": up.util.STATE},
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("hold until", r.stdout)
        self.assertEqual(up.do_hold("9d"), 2)
        up.do_hold("off")
        r = subprocess.run([os.path.join(BUSY, "hold")], env={**os.environ, "HB_STATE": up.util.STATE})
        self.assertEqual(r.returncode, 0)


def can_fake_root():
    return shutil.which("unshare") is not None and subprocess.run(
        ["unshare", "-r", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
class SnapshotToolTest(unittest.TestCase):
    """tools/hb-snapshot as (namespace) root, with btrfs faked: prune and delete."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.snaps, self.bin = os.path.join(self.d, "snaps"), os.path.join(self.d, "bin")
        os.makedirs(self.snaps)
        os.makedirs(self.bin)
        self.log = os.path.join(self.d, "btrfs.log")
        with open(os.path.join(self.bin, "btrfs"), "w") as f:
            f.write(f'#!/bin/sh\necho "$*" >> {self.log}\n'
                    '[ "$1 $2" = "subvolume delete" ] && rmdir "$3"\nexit 0\n')
        os.chmod(os.path.join(self.bin, "btrfs"), 0o755)
        self.toml = os.path.join(self.d, "hb.toml")
        with open(self.toml, "w") as f:
            f.write(f'[snapshot]\ndir = "{self.snaps}"\nkeep_days = 1\n')
        now = datetime.datetime.now()
        self.old = f"phase1-{(now - datetime.timedelta(days=8)).strftime('%Y%m%d-%H%M')}"
        self.new = f"upgrade-{now.strftime('%Y%m%d-%H%M')}"
        for n in (self.old, self.new, "backup-run"):
            os.mkdir(os.path.join(self.snaps, n))

    def tool(self, *args):
        env = {**os.environ, "HB_CONFIG": self.toml, "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-snapshot"), *args],
                              env=env, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
                              start_new_session=True)   # no terminal: confirm can't prompt anyone

    def left(self):
        return sorted(os.listdir(self.snaps))

    def test_check_warns_and_prune_takes_only_the_old(self):
        r = self.tool("check")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("1 snapshots older than 1 days", r.stdout)
        self.assertEqual(self.tool("prune", "--yes").returncode, 0)
        self.assertEqual(self.left(), sorted([self.new, "backup-run"]))

    def test_delete_one(self):
        r = self.tool("delete", self.new, "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.left(), sorted([self.old, "backup-run"]))

    def test_delete_refuses_what_isnt_a_snapshot(self):
        for name in ("backup-run", "../x-20261108-0430", "nope-20261108-0430", ""):
            r = self.tool("delete", name, "--yes")
            self.assertEqual(r.returncode, 2, (name, r.stdout, r.stderr))
        self.assertFalse(os.path.exists(self.log))
        self.assertEqual(len(self.left()), 3)

    def test_delete_asks(self):
        r = self.tool("delete", self.new)                # no tty, no --yes: no
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(self.new, self.left())


class BusyChecksTest(unittest.TestCase):
    """The busy.d scripts on fake inputs (env overrides), as hb runs them."""

    def run_check(self, name, **env):
        p = subprocess.run([os.path.join(BUSY, name)], env={**os.environ, "HB_ROOT": REPO, **env},
                           capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip()

    def test_load(self):
        f = os.path.join(tempfile.mkdtemp(), "loadavg")
        for avg, want in (("0.5 2.5 1.0", 1), ("3.0 1.2 1.0", 0)):
            with open(f, "w") as fh:
                fh.write(f"{avg} 1/100 1234\n")
            self.assertEqual(self.run_check("load", HB_LOADAVG=f)[0], want, avg)

    def test_builds(self):
        proc = tempfile.mkdtemp()

        def task(pid, comm, argv):
            os.mkdir(os.path.join(proc, pid))
            with open(os.path.join(proc, pid, "comm"), "w") as f:
                f.write(comm + "\n")
            with open(os.path.join(proc, pid, "cmdline"), "wb") as f:
                f.write(b"\0".join(a.encode() for a in argv) + b"\0")

        task("10", "bash", ["-bash"])
        task("11", "python3", ["/usr/bin/python3", "-m", "http.server"])
        self.assertEqual(self.run_check("builds", HB_PROC=proc)[0], 0)
        task("12", "docker", ["/usr/bin/docker", "build", "-t", "x", "."])
        rc, out = self.run_check("builds", HB_PROC=proc)
        self.assertEqual((rc, "image build" in out), (1, True))
        shutil.rmtree(os.path.join(proc, "12"))
        task("13", "cargo", ["cargo", "test"])
        self.assertEqual(self.run_check("builds", HB_PROC=proc), (1, "cargo is running (pid 13)"))

    def test_web_shell_input(self):
        state, pts = tempfile.mkdtemp(), tempfile.mkdtemp()
        with open(os.path.join(state, "activity"), "w") as f:
            f.write(f"{int(time.time()) - 120}\n")
        rc, out = self.run_check("sessions", HB_PTS=pts, HB_WEBSHELL_STATE=state)
        self.assertEqual((rc, "the web shell 2 min ago" in out), (1, True))
        with open(os.path.join(state, "activity"), "w") as f:
            f.write(f"{int(time.time()) - 7200}\n")
        self.assertEqual(self.run_check("sessions", HB_PTS=pts, HB_WEBSHELL_STATE=state)[0], 0)

    @unittest.skipUnless(shutil.which("tmux"), "no tmux")
    def test_tmux(self):
        d = tempfile.mkdtemp()
        os.mkdir(os.path.join(d, "tmux-test"), 0o700)
        sock = os.path.join(d, "tmux-test", "default")
        tmux = ["tmux", "-S", sock, "-f", "/dev/null"]
        self.addCleanup(subprocess.run, tmux + ["kill-server"], capture_output=True)
        subprocess.run(tmux + ["new-session", "-d", "-s", "idle", "bash", "--norc"], check=True)
        time.sleep(0.3)
        self.assertEqual(self.run_check("tmux", HB_TMUX_DIR=d)[0], 0)
        subprocess.run(tmux + ["new-session", "-d", "-s", "agent", "sleep", "60"], check=True)
        time.sleep(0.3)
        self.assertEqual(self.run_check("tmux", HB_TMUX_DIR=d), (1, "tmux session agent runs sleep"))


class DigestTest(unittest.TestCase):
    def setUp(self):
        self.state = temp_state(self)
        now = time.time()
        with open(os.path.join(self.state, "status.json"), "w") as f:
            json.dump({"ts": now, "checks": {"backup": {"level": "ok", "detail": "ok: last backup 3 h ago"},
                                             "clean": {"level": "ok", "detail": "ok: 92 GB reclaimable (dry run)"},
                                             "health.disk": {"level": "ok", "detail": "ok: / 41%"},
                                             "share": {"level": "warn", "detail": "warn: pending smb"}}}, f)
        os.makedirs(os.path.join(self.state, "upgrade"))
        with open(os.path.join(self.state, "upgrade", "state.json"), "w") as f:
            json.dump({"dnf": {"at": now - 3600, "rc": 0, "changed": ["bash.x86_64", "kernel-core.x86_64"]},
                       "reboot": {"needed_since": now - 8 * 86400, "busy": "tmux session web runs claude",
                                  "why": "kernel 7.2.14 is installed"}}, f)

    def test_compose(self):
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        c = {"digest": {"reminders": [f"{yesterday} clean.dry_run = false", "2999-01-01 not yet", "soon whatever"]}}
        text, short, rem = digest.compose(c)
        self.assertIn("A REBOOT HAS WAITED", text)
        self.assertIn("upgrade: 2 packages, new kernel, reboot waiting", short)
        self.assertIn("backup last backup 3 h ago", short)
        self.assertIn("WARN  share: warn: pending smb", text)
        self.assertEqual(rem, [f"{yesterday}: clean.dry_run = false", "(not a date: 'soon whatever')"])
        banner = status.render({"ts": time.time(), "checks": {"backup": {"level": "ok", "detail": "ok"}}}, [],
                               {"ts": time.time(), "short": short, "reminders": rem})
        self.assertIn("last night: upgrade: 2 packages", banner)
        self.assertIn(f"reminder: {yesterday}: clean.dry_run = false", banner)
        stale = status.render({"ts": time.time(), "checks": {}}, [], {"ts": time.time() - 2 * 86400, "short": "x"})
        self.assertNotIn("last night", stale)

    def test_drift_and_disk_scan(self):
        now = time.time()
        os.makedirs(os.path.join(self.state, "inventory"))
        with open(os.path.join(self.state, "inventory", "drift.jsonl"), "w") as f:
            f.write(json.dumps({"ts": now - 2 * 86400, "changes": ["package added: old"]}) + "\n")
            f.write(json.dumps({"ts": now - 3600, "changes": [f"package added: p{i}" for i in range(14)]}) + "\n")
        with open(os.path.join(self.state, "status.json")) as f:
            cache = json.load(f)
        cache["checks"]["disk"] = {"level": "ok", "detail": "ok: scanned 01 Nov: 192.3 GB in 2.3 M files"}
        with open(os.path.join(self.state, "status.json"), "w") as f:
            json.dump(cache, f)
        text, short, _ = digest.compose({"digest": {"reminders": []}}, now=now)
        self.assertIn("changes:   14 in 24 h (hb inventory drift)", text)
        self.assertIn("  package added: p11\n  and 2 more", text)
        self.assertNotIn("package added: old", text)
        self.assertIn("disk scan: scanned 01 Nov: 192.3 GB in 2.3 M files (hb disk)", text)
        self.assertIn("14 changes to the system", short)


if __name__ == "__main__":
    unittest.main()
