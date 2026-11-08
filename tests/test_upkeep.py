"""Phase 6: hb-upgrade's night (commands faked), the busy.d checks on fake inputs, the digest and its banner line."""
import contextlib
import copy
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
    u = copy.deepcopy(up.config.DEFAULTS["upgrade"])
    u.update({"enabled": True, "snaps": ["microk8s", "snapd"], "snapshot_days": 3}, **over)
    return {"upgrade": u, "snapshot": {"dir": tempfile.mkdtemp(), "keep_days": 14}, "digest": {"reminders": []}}


class Fake:
    """Answers util.run for the commands a night uses, and records them."""

    def __init__(self):
        self.calls, self.restart = [], 1        # dnf needs-restarting -r: 1 = reboot needed
        self.dnf_rc, self.kernel, self.grubby_fails, self.grubby_out = 0, os.uname().release, False, None
        self.rpm = ["bash.x86_64 5.2-1", "kernel-core.x86_64 7.2.13-200"]
        self.rpm_after = ["bash.x86_64 5.2-2", "kernel-core.x86_64 7.2.14-200"]
        self.release, self.newest, self.repoquery_rc = "2023.12.20261102", "2023.12.20261116", 0
        self.active, self.tests, self.kw, self.check_rc = set(), {}, [], 0

    def __call__(self, *cmd, **kw):
        self.calls.append(cmd)
        self.kw.append((cmd, kw))
        if cmd[:2] == ("rpm", "-q") and cmd[-1] == "system-release":
            return 0, self.release + "\n", ""
        if cmd[:2] == ("dnf", "repoquery"):                     # dnf 4 prints its own newline after --qf
            return self.repoquery_rc, f"{self.newest}\n\n" if self.repoquery_rc == 0 else "", \
                "Error: Failed to download metadata" if self.repoquery_rc else ""
        if cmd == ("dnf", "check"):
            return self.check_rc, "glibc-2.34-1.x86_64 is a duplicate with glibc-2.34-2.x86_64\n" if self.check_rc else "", ""
        if cmd[:3] == ("systemctl", "is-active", "--quiet"):
            return (0 if cmd[3] in self.active else 3), "", ""
        if cmd and cmd[0] in self.tests:                         # an upgrade.after test, e.g. sshd -t
            return self.tests[cmd[0]], "", "error in /etc/ssh/sshd_config line 9" if self.tests[cmd[0]] else ""
        if cmd == ("grubby", "--default-kernel"):           # the kernel the next boot starts
            if self.grubby_out is not None:
                return 0, self.grubby_out, ""
            return (1, "", "grubby: error") if self.grubby_fails else (0, f"/boot/vmlinuz-{self.kernel}\n", "")
        if cmd[:2] == ("rpm", "-qa") and cmd[-1] == "kernel*":   # a newer kernel line, installed beside the default
            return 0, f"1761000000 kernel-core {self.kernel}\n1762000000 kernel6.12 6.12.40-1.amzn2023.x86_64\n", ""
        if cmd[:2] == ("rpm", "-qa"):
            return 0, "\n".join(self.rpm) + "\n", ""
        if cmd[:3] == ("dnf", "upgrade", "--refresh"):
            if self.dnf_rc == 0:
                self.rpm = self.rpm_after
            return self.dnf_rc, "", "Error: cannot download repomd.xml" if self.dnf_rc else ""
        if cmd[:2] == ("dnf", "needs-restarting"):
            return self.restart, "Reboot is required to fully utilize these updates.\n" if self.restart else "", ""
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

    def test_with_upgrade_off_only_the_hold_is_managed(self):
        # a box that updates some other way still wants microk8s held, refreshed when someone chooses
        off = cfg(enabled=False, snaps=["microk8s", "snapd"])
        self.assertEqual(up.verdict(off), (1, "warn: snaps: will hold auto-refresh for snapd "
                                              "(you refresh them when you choose instead)"))
        self.assertEqual(up.do_plan(off, apply=True, yes=True), 1)    # the fake snap list doesn't change
        self.assertTrue(self.fake.did("snap", "refresh", "--hold", "microk8s", "snapd"))
        self.assertEqual(up.verdict(cfg(enabled=False, snaps=["microk8s"])),
                         (0, "ok: snaps: microk8s held; nothing refreshes them until you do (sudo snap refresh NAME)"))
        self.assertEqual(up.verdict(cfg(enabled=False, snaps=[])), (0, "ok: not managed"))
        old = (up.os.geteuid, up.config.load)
        self.addCleanup(lambda: (setattr(up.os, "geteuid", old[0]), setattr(up.config, "load", old[1])))
        up.os.geteuid, up.config.load = (lambda: 0), (lambda: off)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(up.main(["hb-upgrade", "run"]), 0)
        self.assertEqual(out.getvalue(), "not managed (upgrade.enabled is false); only the snap hold is\n")
        self.assertFalse(self.fake.did("dnf", "upgrade", "--refresh", "-y"))

    def test_reboot_reason(self):
        why, unknown = up.reboot_reason()
        self.assertIn("Reboot is required", why)
        self.assertIsNone(unknown)
        self.fake.restart = 0
        self.assertEqual(up.reboot_reason(), (None, None))
        self.fake.kernel = "9.9.9-1.fc44.x86_64"               # the next boot starts another kernel
        self.assertIn("9.9.9", up.reboot_reason()[0])
        self.fake.restart = 2                                  # dnf itself failed: the kernel comparison decides
        self.assertIn("9.9.9", up.reboot_reason()[0])

    def test_a_kernel_installed_beside_the_boot_default_is_no_reason_to_reboot(self):
        # AL2023: kernel6.12 installed after the running 6.1, but grubby still boots the running one.
        # Rebooting for it would boot the same kernel again, every night.
        self.fake.restart = 0
        self.assertEqual(up.reboot_reason(), (None, None))
        self.assertEqual(up.do_run(cfg(snaps=["microk8s"]), now=NIGHT), 0)
        self.assertFalse(self.fake.did("systemctl", "reboot"))

    def test_grubby_without_a_kernel_in_its_answer_is_unknown(self):
        self.fake.restart, self.fake.grubby_out = 0, "/boot\n"   # what grubby prints without root, exit 0
        self.assertEqual(up.reboot_reason(), (None, "grubby --default-kernel: no kernel in its answer"))

    def test_a_reboot_check_that_cant_answer_says_so(self):
        for rc, text in ((2, "exit 2"), (127, "not installed"), (124, "timed out")):
            self.fake.restart = rc
            self.assertEqual(up.reboot_reason(), (None, f"dnf needs-restarting -r: {text}"))
        self.fake.restart, self.fake.grubby_fails = 0, True    # dnf says no, but the boot kernel is unknown
        self.assertEqual(up.reboot_reason(), (None, "grubby --default-kernel: exit 1"))
        self.fake.grubby_fails = False
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


class AmazonLinuxUpgradeTest(unittest.TestCase):
    """Stage 4 on Amazon Linux 2023: a resolved release, security only, one repository, the after rules,
    and reboots left to a person."""

    setUp = UpgradeTest.setUp

    AL = dict(release="latest", security_only=True, repos=["amazonlinux"], reboot="never", snaps=["microk8s"],
              refresh_snaps=False, snapshot_days=0)

    def upgrade_call(self):
        return next(((c, kw) for c, kw in self.fake.kw if c[:2] == ("dnf", "upgrade")), (None, None))

    def test_the_newest_release_is_resolved_then_named(self):
        self.fake.restart = 0
        self.assertEqual(up.do_run(cfg(**self.AL), now=NIGHT), 0)
        cmd, kw = self.upgrade_call()
        self.assertEqual(cmd, ("dnf", "upgrade", "--refresh", "-y", "--disablerepo=*", "--enablerepo=amazonlinux",
                               "--setopt=amazonlinux.skip_if_unavailable=False", "--releasever=2023.12.20261116",
                               "--security"))
        self.assertIsNone(kw["timeout"])                      # an RPM transaction is never killed halfway
        q = next(c for c in self.fake.calls if c[:2] == ("dnf", "repoquery"))
        self.assertIn("--releasever=latest", q)
        self.assertIn("--enablerepo=amazonlinux", q)
        st = up.load_state()
        self.assertEqual(st["dnf"]["release"], "2023.12.20261116")
        self.assertIn("dnf 2023.12.20261116: 2 packages", up.summary(st))
        self.assertFalse(self.fake.did("snap", "refresh", "microk8s"))   # held only: never refreshed here

    def test_another_major_version_or_no_answer_means_no_upgrade(self):
        for newest, rc, text in (("2025.0.20270301", 0, "is another major version than 2023.12.20261102"),
                                 ("", 1, "can't tell the newest release (Error: Failed to download metadata)")):
            self.fake.newest, self.fake.repoquery_rc, self.fake.calls, self.fake.kw = newest, rc, [], []
            up.save_state({})
            self.assertEqual(up.do_run(cfg(**self.AL), now=NIGHT), 2)
            self.assertEqual(self.upgrade_call(), (None, None))
            vrc, line = up.verdict(cfg(**self.AL))
            self.assertEqual(vrc, 2)
            self.assertIn(text, line)

    def test_a_pinned_release_is_used_as_it_is(self):
        self.fake.restart = 0
        up.do_run(cfg(**dict(self.AL, release="2023.12.20261102")), now=NIGHT)
        self.assertIn("--releasever=2023.12.20261102", self.upgrade_call()[0])
        self.assertFalse(self.fake.did("dnf", "repoquery"))

    def test_after_rules_restart_only_what_changed_and_ran(self):
        rules = [{"packages": ["openssh-server", "openssl-libs"], "test": ["/usr/sbin/sshd", "-t"], "unit": "sshd"},
                 {"unit": "microk8s-management-firewall", "action": "reload-or-restart"},   # every night
                 {"packages": ["fail2ban-server"], "test": ["/usr/bin/fail2ban-client", "-t"], "unit": "fail2ban"},
                 {"packages": ["amazon-ssm-agent"], "unit": "amazon-ssm-agent"}]
        self.fake.rpm = ["openssh-server.aarch64 9.9p1-15", "amazon-ssm-agent.aarch64 3.3.5600.0-1",
                         "fail2ban-server.noarch 1.1.0-1"]
        self.fake.rpm_after = ["openssh-server.aarch64 9.9p1-16", "amazon-ssm-agent.aarch64 3.3.5700.0-1",
                               "fail2ban-server.noarch 1.1.0-1"]
        self.fake.active = {"sshd", "microk8s-management-firewall", "fail2ban"}   # the SSM agent wasn't running
        self.fake.restart = 0
        self.assertEqual(up.do_run(cfg(**dict(self.AL, after=rules)), now=NIGHT), 0)
        ran = [c for c in self.fake.calls if c[0] in ("/usr/sbin/sshd", "/usr/bin/fail2ban-client")
               or c[:2] in (("systemctl", "restart"), ("systemctl", "reload-or-restart"))]
        self.assertEqual(ran, [("/usr/sbin/sshd", "-t"), ("systemctl", "restart", "sshd"),
                               ("systemctl", "reload-or-restart", "microk8s-management-firewall")])
        self.assertEqual(up.load_state()["dnf"]["after"], ["restart sshd", "reload-or-restart microk8s-management-firewall"])
        self.assertEqual(up.verdict(cfg(**dict(self.AL, after=rules)))[0], 0)

    def test_a_failing_test_leaves_the_unit_as_it_is_and_fails_the_night(self):
        rules = [{"packages": ["openssh-server"], "test": ["/usr/sbin/sshd", "-t"], "unit": "sshd"}]
        self.fake.rpm, self.fake.rpm_after = ["openssh-server.aarch64 9.9p1-15"], ["openssh-server.aarch64 9.9p1-16"]
        self.fake.active, self.fake.tests, self.fake.restart = {"sshd"}, {"/usr/sbin/sshd": 255}, 0
        self.assertEqual(up.do_run(cfg(**dict(self.AL, after=rules)), now=NIGHT), 2)
        self.assertFalse(self.fake.did("systemctl", "restart", "sshd"))
        rc, line = up.verdict(cfg(**dict(self.AL, after=rules)))
        self.assertEqual(rc, 2)
        self.assertIn("sshd: /usr/sbin/sshd -t failed (error in /etc/ssh/sshd_config line 9), not restarted", line)

    def test_reboot_never_waits_for_a_person(self):
        self.fake.restart = 1                                  # needs-restarting: a reboot is needed
        self.assertEqual(up.do_run(cfg(**self.AL), now=NIGHT), 0)
        self.assertFalse(self.fake.did("systemctl", "reboot"))
        rc, line = up.verdict(cfg(**self.AL))
        self.assertEqual(rc, 0)
        self.assertIn("reboot waiting, for you (upgrade.reboot = never)", line)
        st = up.load_state()
        st["reboot"]["needed_since"] -= 8 * 86400
        up.save_state(st)
        self.assertEqual(up.verdict(cfg(**self.AL))[0], 1)    # a week later: the check warns

    SSHD = [{"packages": ["openssh-server"], "test": ["/usr/sbin/sshd", "-t"], "unit": "sshd"}]

    def broken_sshd(self):
        self.fake.rpm, self.fake.rpm_after = ["openssh-server.aarch64 9.9p1-15"], ["openssh-server.aarch64 9.9p1-16"]
        self.fake.active, self.fake.tests = {"sshd"}, {"/usr/sbin/sshd": 255}

    def test_no_reboot_while_a_validation_failed(self):
        # an idle-reboot box: sshd's new config fails sshd -t, and a reboot is needed. Rebooting would
        # start the broken sshd; the running one must stay, and the night must say it failed.
        self.broken_sshd()
        self.fake.restart = 1
        c = cfg(**dict(self.AL, reboot="idle", after=self.SSHD))
        self.assertEqual(up.do_run(c, now=NIGHT), 2)
        self.assertFalse(self.fake.did("systemctl", "reboot"))
        self.assertFalse(self.fake.did("systemctl", "restart", "sshd"))

    def test_no_reboot_or_refresh_after_a_failed_transaction(self):
        self.fake.dnf_rc, self.fake.restart = 1, 1
        self.assertEqual(up.do_run(cfg(), now=NIGHT), 2)
        self.assertFalse(self.fake.did("systemctl", "reboot"))
        self.assertFalse(self.fake.did("snap", "refresh", "microk8s"))

    def test_a_failed_after_step_stays_until_it_works(self):
        self.broken_sshd()
        self.fake.restart = 0
        c = cfg(**dict(self.AL, after=self.SSHD))
        self.assertEqual(up.do_run(c, now=NIGHT), 2)
        self.assertIn("sshd", up.load_state()["after_pending"])
        self.assertEqual(up.do_run(c, now=NIGHT), 2)             # 30 minutes later: tried again, still broken
        self.assertFalse(self.fake.did("systemctl", "restart", "sshd"))
        st = up.load_state()                                      # the next night: openssh doesn't change again
        st["night"] = "earlier"
        up.save_state(st)
        self.fake.rpm = self.fake.rpm_after
        self.fake.tests = {"/usr/sbin/sshd": 0}                   # someone fixed the config
        self.assertEqual(up.do_run(c, now=NIGHT), 0)
        self.assertTrue(self.fake.did("systemctl", "restart", "sshd"))
        self.assertNotIn("after_pending", up.load_state())
        self.assertEqual(up.verdict(c)[0], 0)

    def test_forget_a_step_taken_care_of(self):
        self.broken_sshd()
        self.fake.restart = 0
        c = cfg(**dict(self.AL, after=self.SSHD))
        up.do_run(c, now=NIGHT)
        self.assertEqual(up.verdict(c)[0], 2)
        self.assertEqual(up.do_forget("fail2ban"), 1)
        self.assertEqual(up.do_forget("sshd"), 0)
        self.assertEqual(up.verdict(c)[0], 0)

    def test_a_pinned_release_of_another_major_is_refused(self):
        c = cfg(**dict(self.AL, release="2025.0.20270301"))
        self.assertEqual(up.do_run(c, now=NIGHT), 2)
        self.assertEqual(self.upgrade_call(), (None, None))
        self.assertIn("pinned release 2025.0.20270301 is another major version than 2023.12.20261102", up.verdict(c)[1])

    def test_a_transaction_that_never_finished_shows(self):
        up.save_state({"dnf_started": int(time.time()) - 4 * 3600})
        rc, line = up.verdict(cfg(**self.AL))
        self.assertEqual(rc, 1)
        self.assertIn("hasn't finished: still running, or stopped halfway", line)

    def interrupted(self, test_rc=0):
        """openssh-server got installed, then the run died before its after steps were saved."""
        self.fake.rpm = self.fake.rpm_after = ["openssh-server.aarch64 9.9p1-16"]   # already the new one
        self.fake.active, self.fake.tests, self.fake.restart = {"sshd"}, {"/usr/sbin/sshd": test_rc}, 0
        up.save_state({"night": "earlier", "dnf_started": {
            "at": int(time.time()) - 6 * 3600, "before": {"openssh-server.aarch64": ["9.9p1-15"]},
            "was_active": {"sshd": True}}})
        return cfg(**dict(self.AL, after=self.SSHD))

    def test_an_interrupted_transaction_still_gets_its_after_steps(self):
        c = self.interrupted()
        self.assertEqual(up.do_run(c, now=NIGHT), 0)
        self.assertTrue(self.fake.did("/usr/sbin/sshd", "-t"))
        self.assertTrue(self.fake.did("systemctl", "restart", "sshd"))
        self.assertTrue(self.fake.did("dnf", "check"))
        st = up.load_state()
        self.assertNotIn("dnf_started", st)
        self.assertNotIn("unfinished", st)
        self.assertEqual(up.verdict(c)[0], 0)

    def test_an_interrupted_transaction_whose_test_fails_stays_pending(self):
        c = self.interrupted(test_rc=255)
        self.assertEqual(up.do_run(c, now=NIGHT), 2)
        self.assertFalse(self.fake.did("systemctl", "restart", "sshd"))
        self.assertIn("sshd", up.load_state()["after_pending"])

    def test_a_broken_package_database_stays_failed_until_clean(self):
        c = self.interrupted()
        self.fake.check_rc, self.fake.restart = 1, 1           # dnf check finds a duplicate; a reboot is due
        c["upgrade"]["reboot"] = "idle"
        self.assertEqual(up.do_run(c, now=NIGHT), 2)
        self.assertFalse(self.fake.did("systemctl", "reboot"))
        rc, line = up.verdict(c)
        self.assertEqual(rc, 2)
        self.assertIn("stopped halfway; dnf check: glibc-2.34-1.x86_64 is a duplicate", line)
        self.fake.check_rc, self.fake.restart = 0, 0           # someone cleaned it up
        self.assertEqual(up.do_run(c, now=NIGHT), 0)
        self.assertEqual(up.verdict(c)[0], 0)

    def test_forget_dnf(self):
        c = self.interrupted()
        self.fake.check_rc = 1
        up.do_run(c, now=NIGHT)
        self.assertEqual(up.do_forget("dnf"), 0)
        self.assertEqual(up.do_forget("dnf"), 1)
        self.assertNotIn("unfinished", up.load_state())

    def test_the_unit_has_no_deadline_either(self):
        with open(os.path.join(REPO, "units", "hb-upgrade.service")) as f:
            self.assertIn("TimeoutStartSec=infinity\n", f.read())

    def test_settings_that_cant_be_used(self):
        for over, text in ((dict(release="2023.x"), "upgrade.release"),
                           (dict(reboot="sometimes"), "upgrade.reboot"),
                           (dict(repos=["amazon linux"]), "upgrade.repos"),
                           (dict(after=[{"unit": "sshd", "test": ["sshd", "-t"]}]), "test starts with a full path"),
                           (dict(after=[{"unit": "sshd", "when": ["x"]}]), "a table of"),
                           (dict(after=[{"unit": "sshd", "action": "stop"}]), "action is one of"),
                           (dict(refresh_snaps="false"), "upgrade.refresh_snaps: true or false"),
                           (dict(security_only=1), "upgrade.security_only: true or false"),
                           (dict(enabled="false"), "upgrade.enabled: true or false"),
                           (dict(repos="amazonlinux"), "upgrade.repos: a list"),
                           (dict(after={"unit": "sshd"}), "upgrade.after: a list"),
                           (dict(snaps="microk8s"), "upgrade.snaps: a list"),
                           (dict(snapshot_days="0"), "upgrade.snapshot_days: a whole number"),
                           (dict(window_end="7am"), "upgrade.window_end"),
                           (dict(after=[{"unit": "sshd", "test": ["/usr/sbin/sshd", "-t"], "packages": ["openssh-server"]},
                                        {"unit": "sshd"}]), "more than one rule for sshd")):
            c = cfg(**dict(self.AL, **over))
            rc, line = up.verdict(c)
            self.assertEqual(rc, 2, over)
            self.assertIn(text, line)
            self.fake.calls = []
            self.assertEqual(up.do_run(c, now=NIGHT), 2)
            self.assertFalse(self.fake.did("dnf"), over)


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
