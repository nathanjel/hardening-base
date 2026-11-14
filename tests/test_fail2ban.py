"""hb-fail2ban: the jail and action files, the failed-code exception, recent logins, bans, the
items and verdicts (system commands answered by a fake box), and the root-run tree."""
import configparser
import contextlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from tools import load_tool, temp_state, util  # noqa: E402

fb = load_tool("fail2ban")
notify = load_tool("notify")
KNOWN = f"{util.HB} fail2ban known <ip>"


def cfg(**over):
    c = {"fail2ban": {"enabled": True, "maxretry": 5, "findtime_minutes": 10, "bantime_minutes": 60,
                      "mode": "aggressive", "known_days": 1, "notify_days": 30, "ignoreip": []}}
    c["fail2ban"].update(over)
    return c


KEY_THEN_CODE = "port 22\nauthenticationmethods publickey,keyboard-interactive:pam\n"
# sshd -T without a connection: where it listens (always printed with the port), its PAM service
PLAIN = "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\npamservicename sshd\n"
ROUTES = {"192.0.2.1": "192.0.2.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0",
          "2001:db8::1": "2001:db8::1 from :: via fe80::1 dev eth0 src 2001:db8:5::5 metric 1024 pref medium"}
FACTS = {"ports": ["22"], "key_first": True, "code_only": True, "skip_codes": True}
# /etc/pam.d/sshd as hb ssh leaves it with ssh.codes (the stock file with the code check in place
# of "auth substack password-auth"), and postlogin, which has no auth lines.
PAM_SSHD = """#%PAM-1.0
# hb-ssh: the code from hb totp decides (requisite); pam_permit only lets sshd's pam_setcred succeed
auth       requisite    pam_exec.so quiet expose_authtok /opt/hb/tools/hb-totp verify
auth       required     pam_permit.so
auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
session    required     pam_selinux.so close
session    include      password-auth
session    include      postlogin
"""
PAM_POSTLOGIN = "#%PAM-1.0\nsession optional pam_umask.so silent\nsession optional pam_lastlog.so silent noupdate\n"
PAM_PASSWORD_AUTH = "auth required pam_env.so\nauth sufficient pam_unix.so try_first_pass nullok\nauth required pam_deny.so\n"

# What fail2ban's sshd filter matches against: sshd's lines without their prefix (13 Nov, a box).
CODE_LINES = ["Failed keyboard-interactive/pam for ec2-user from 203.0.113.9 port 60941 ssh2"]
OTHER_LINES = ["Failed keyboard-interactive/pam for invalid user admin from 203.0.113.9 port 1 ssh2",
               "Failed publickey for root from 203.0.113.9 port 1 ssh2",
               "Failed password for ec2-user from 203.0.113.9 port 1 ssh2",
               "maximum authentication attempts exceeded for ec2-user from 203.0.113.9 port 60941 ssh2 [preauth]",
               "Invalid user admin from 203.0.113.9 port 1",
               # Fable review: without PAM (no /pam) it isn't hb totp's code
               "Failed keyboard-interactive for ec2-user from 203.0.113.9 port 1 ssh2"]


def f2b_list(head, items, prefix=""):
    """fail2ban-client's way of printing a list (client/beautifier.py)."""
    return head + "\n" + "\n".join(("|- " if i < len(items) - 1 else "`- ") + prefix.format(i) + x
                                   for i, x in enumerate(items))


class Box:
    """run() for a box with fail2ban: what each command answers, and what it was asked."""

    def __init__(self):
        self.calls, self.sshd, self.journal, self.banned = [], {}, [], []
        self.plain, self.routes, self.ip_rc = PLAIN, dict(ROUTES), 0
        self.installed, self.active, self.enabled, self.test_rc = set(fb.PACKAGES), True, True, 0
        self.jail_running, self.reload_rc, self.reload_sshd_rc, self.jail_after_start = True, 0, 0, True
        self.dnf_rc, self.unban_rc, self.systemd_run_rc, self.pings_unanswered = 0, 0, 0, 0
        self.journal_raw, self.grep = [], True          # lines that aren't JSON; journalctl has --grep
        self.on_reload = None                            # a function run at a reload (to raise in it)
        self.reload_adds_actions, self.restart_rc = False, 0   # fail2ban up to 1.1.1: a reload drops a new action
        self.db, self.on_restart = True, None            # fail2ban's database (dbfile); a function run at a restart
        self.unit = "sshd.service"                       # the unit sshd's journal lines come from
        # the running sshd jail, as hb.toml (cfg()) wants it
        self.live = {"maxretry": "5", "findtime": "600", "bantime": "3600", "ignorecommand": KNOWN,
                     "ignoreregex": [fb.CODE_FAILED], "actions": ["hb-notify", "nftables"],
                     "ignoreip": ["127.0.0.0/8", "::1"]}
        self.after_reload = None                         # what a reload changes in the running jail

    def get(self, key):
        v = self.live[key]
        if key == "ignoreregex":
            return f2b_list("The following regular expression are defined:", v, "[{}]: ") if v else \
                "No regular expression is defined"
        if key == "actions":
            return "The jail sshd has the following actions:\n" + ", ".join(v) if v else "No actions for jail sshd"
        if key == "ignoreip":
            return f2b_list("These IP addresses/networks are ignored:", v) if v else "No IP address/network is ignored"
        return v

    def run(self, *cmd, **kw):
        self.calls.append(cmd)
        if cmd[0] == "sshd":
            if "-C" not in cmd:
                return 0, self.plain, ""
            spec = dict(kv.split("=", 1) for kv in cmd[cmd.index("-C") + 1].split(","))
            if "lport" not in spec:                      # as with a Match LocalPort block in the config
                return 255, "", "'Match LocalPort' in configuration but 'lport' not in connection test specification.\n"
            return 0, self.sshd.get((spec["addr"], spec["lport"]), self.sshd.get(spec["addr"], KEY_THEN_CODE)), ""
        if cmd[:4] == ("ip", "-o", "route", "get"):
            if self.ip_rc:
                return self.ip_rc, "", "Error: something else\n"
            route = self.routes.get(cmd[4])
            return (0, route + "\n", "") if route else (2, "", "RTNETLINK answers: Network is unreachable\n")
        if cmd[0] == "rpm":
            return (0 if cmd[-1] in self.installed else 1), "", ""
        if cmd[:3] == ("dnf", "install", "-y"):
            if self.dnf_rc:
                return self.dnf_rc, "", "Error: Unable to find a match: fail2ban-systemd\n"
            self.installed |= set(cmd[3:])
            return 0, "", ""
        if cmd[:2] == ("systemctl", "is-active"):
            return (0 if self.active else 3), "", ""
        if cmd[:2] == ("systemctl", "is-enabled"):
            return (0 if self.enabled else 1), "", ""
        if cmd[:3] == ("systemctl", "enable", "--now"):
            self.active = self.enabled = True
            self.jail_running = self.jail_after_start
            return 0, "", ""
        if cmd[0] == "systemd-run":
            return self.systemd_run_rc, "", "Failed to start transient service unit: Access denied\n" if self.systemd_run_rc else ""
        if cmd[0] == "fail2ban-client":
            if "fail2ban-server" not in self.installed:
                return 127, "", "fail2ban-client: not found"
            a = cmd[1:]
            if a == ("-t",):
                return self.test_rc, "OK: configuration test is successful\n" if not self.test_rc else "", \
                    "" if not self.test_rc else "ERROR  Failed during configuration: No section: 'Definition'"
            if not self.active and a[:1] in (("get",), ("status",), ("set",), ("reload",), ("restart",)):
                return 255, "", "Failed to access socket path: /var/run/fail2ban/fail2ban.sock. Is fail2ban running?\n"
            if a == ("ping",):
                if self.pings_unanswered:
                    self.pings_unanswered -= 1
                    return 255, "", "Failed to access socket path: /var/run/fail2ban/fail2ban.sock\n"
                return 0, "Server replied: pong\n", ""
            if a[:1] == ("reload",):
                if self.on_reload:
                    self.on_reload()
                if self.reload_rc or (a == ("reload", "sshd") and (self.reload_sshd_rc or not self.jail_running)):
                    return self.reload_rc or self.reload_sshd_rc or 255, "", "ERROR  NOK: ('sshd',)"
                if self.after_reload is not None:
                    new = dict(self.after_reload)
                    if "actions" in new and self.jail_running and not self.reload_adds_actions:
                        # the end of the reload removes an action it added (actions.py, Actions.reload)
                        new["actions"] = [x for x in new["actions"] if x in self.live["actions"]]
                    self.live.update(new)
                self.jail_running = True
                return 0, "OK\n", ""
            if a == ("restart", "sshd"):
                if self.on_restart:
                    self.on_restart()
                if not self.jail_running:
                    return 255, "", "Sorry but the jail 'sshd' does not exist\n"
                if self.restart_rc:
                    self.jail_running = False                # stopped, and its start failed
                    return self.restart_rc, "", "ERROR  Failed to start jail 'sshd' action 'hb-notify'"
                if self.after_reload is not None:
                    self.live.update(self.after_reload)
                if not self.db:
                    self.banned = []                         # nothing to restore them from
                return 0, "OK\n", ""
            if a == ("get", "dbfile"):
                return 0, ("Current database file is:\n`- /var/lib/fail2ban/fail2ban.sqlite3\n" if self.db
                           else "Database currently disabled\n"), ""
            if a[:2] == ("get", "sshd"):
                if not self.jail_running:
                    return 255, "", "Sorry but the jail 'sshd' does not exist\n"
                return 0, self.get(a[2]) + "\n", ""
            if a == ("status",):
                return 0, "Status\n|- Number of jail:\t2\n`- Jail list:\tnginx-http-auth, sshd\n", ""
            if a == ("status", "sshd"):
                return 0, f"Status for the jail: sshd\n`- Actions\n   `- Banned IP list:\t{' '.join(self.banned)}\n", ""
            if a[:3] == ("set", "sshd", "unbanip"):
                if self.unban_rc:
                    return self.unban_rc, "", "Sorry but the jail 'sshd' does not exist\n"
                return 0, ("1" if a[3] in self.banned else "0") + "\n", ""
        if cmd[0] == "journalctl":
            mine = f"_SYSTEMD_UNIT={self.unit}" in cmd   # another unit's lines aren't sshd's
            since = int(cmd[cmd.index("--since") + 1].lstrip("@"))
            pattern = cmd[cmd.index("--grep") + 1] if "--grep" in cmd else None
            if pattern and not self.grep:
                return 1, "", "Compiled without pattern matching support\n"
            def text(m):                                 # journalctl matches a message's bytes
                return m if isinstance(m, str) else bytes(m).decode("latin-1") if isinstance(m, list) else ""
            lines = [json.dumps({"MESSAGE": m, "__REALTIME_TIMESTAMP": str(int(t * 1e6))}) + "\n"
                     for t, m in self.journal if mine and t >= since and (pattern is None or re.search(pattern, text(m)))]
            lines += [raw + "\n" for raw in self.journal_raw if mine]
            return (1 if pattern and not lines else 0), "".join(lines), ""
        return 0, "", ""

    def did(self, *prefix):
        return [c for c in self.calls if c[:len(prefix)] == prefix]


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


class FakeBoxTest(unittest.TestCase):
    def setUp(self):
        temp_state(self)
        self.box = Box()
        d = tempfile.mkdtemp()
        saved = {n: getattr(fb, n) for n in ("JAIL_FILE", "ACTION_FILE", "PAM_DIR", "unsafe_tree")}
        self.addCleanup(lambda: [setattr(fb, n, v) for n, v in saved.items()])
        fb.JAIL_FILE = os.path.join(d, "jail.d", "95-hb-sshd.local")
        fb.ACTION_FILE = os.path.join(d, "action.d", "hb-notify.conf")
        fb.PAM_DIR = os.path.join(d, "pam.d")
        write(os.path.join(fb.PAM_DIR, "sshd"), PAM_SSHD)
        write(os.path.join(fb.PAM_DIR, "postlogin"), PAM_POSTLOGIN)
        write(os.path.join(fb.PAM_DIR, "password-auth"), PAM_PASSWORD_AUTH)
        fb.unsafe_tree = lambda: None
        self.enterContext(mock.patch.object(fb.util, "run", self.box.run))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def written(self, c=None):
        for p, text in fb.wanted(c or cfg(), FACTS).items():
            write(p, text)


class FilesTest(unittest.TestCase):
    def parsed(self, text):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_string(text)
        return cp

    def test_the_jail_file(self):
        text = fb.jail_text(cfg(), FACTS)
        sshd = self.parsed(text)["sshd"]
        for key, want in (("enabled", "true"), ("backend", "systemd"), ("filter", "sshd[mode=aggressive]"),
                          ("port", "22"), ("usedns", "no"), ("maxretry", "5"), ("findtime", "10m"), ("bantime", "60m"),
                          ("banaction", "nftables[type=multiport]"), ("ignoreself", "true"),
                          ("ignoreip", "127.0.0.1/8 ::1"), ("ignorecommand", KNOWN),
                          # Fable review: fail2ban keeps a "no" as long, so a short one
                          ("ignorecache", 'key="<ip>", max-count=1000, max-time=1m'),
                          ("ignoreregex", fb.CODE_FAILED), ("bantime.increment", "false")):
            self.assertEqual(sshd[key], want, key)
        self.assertEqual(sshd["action"].split("\n"), ["%(action_)s", "hb-notify"])   # two actions, as fail2ban reads it
        self.assertTrue(text.startswith("# Managed by hb-fail2ban"))

    def test_the_jail_file_without_the_extras(self):
        c = cfg(known_days=0, notify_days=0, ignoreip=["203.0.113.0/24", "2001:db8::5"], mode="normal")
        sshd = self.parsed(fb.jail_text(c, {**FACTS, "ports": ["22", "2222"], "skip_codes": False}))["sshd"]
        self.assertEqual(sshd["ignorecommand"], "")
        self.assertNotIn("ignorecache", sshd)
        self.assertEqual(sshd["ignoreregex"], "")                         # failed answers count here
        self.assertEqual(sshd["action"], "%(action_)s")
        self.assertEqual(sshd["port"], "22,2222")
        self.assertEqual(sshd["filter"], "sshd[mode=normal]")
        self.assertEqual(sshd["ignoreip"], "127.0.0.1/8 ::1 203.0.113.0/24 2001:db8::5/128")

    def test_the_code_exception_takes_failed_codes_only(self):
        rx = re.compile(fb.CODE_FAILED)
        for line in CODE_LINES:
            self.assertTrue(rx.search(line), line)
        for line in OTHER_LINES:
            self.assertFalse(rx.search(line), line)

    def test_the_action_file(self):
        d = self.parsed(fb.action_text())["Definition"]
        self.assertEqual(d["actionban"], f"{util.HB} fail2ban banned <ip>")
        self.assertEqual(d["actionunban"], "")
        self.assertEqual(d["norestored"], "1")            # a ban restored after a restart doesn't text again


class SshdTest(FakeBoxTest):
    def specs(self):
        return sorted(c[c.index("-C") + 1] for c in self.box.did("sshd", "-T") if "-C" in c)

    def test_a_key_before_the_code(self):
        self.assertEqual(fb.sshd_facts(), (FACTS, None))
        # Fable review: laddr and lport as a connection has them (a Match LocalPort block makes
        # sshd refuse a spec without lport, which the fake box does always)
        self.assertEqual(self.specs(), ["user=hb-fail2ban,host=hb-fail2ban,addr=192.0.2.1,laddr=10.0.0.5,lport=22",
                                        "user=hb-fail2ban,host=hb-fail2ban,addr=2001:db8::1,laddr=2001:db8:5::5,lport=22"])

    def test_where_a_code_may_come_first(self):
        self.box.plain = PLAIN + "listenaddress 0.0.0.0:2222\n"
        for methods in ("any", "publickey,keyboard-interactive:pam keyboard-interactive", "password"):
            self.box.sshd = {"192.0.2.1": f"authenticationmethods {methods}\n"}
            facts, err = fb.sshd_facts()
            self.assertFalse(facts["skip_codes"], methods)
        self.assertEqual(facts["ports"], ["22", "2222"])
        self.box.sshd = {"2001:db8::1": "authenticationmethods any\n"}       # one family only
        self.assertFalse(fb.sshd_facts()[0]["skip_codes"])
        self.box.sshd = {("192.0.2.1", "2222"): "authenticationmethods keyboard-interactive\n"}   # one port only
        self.assertFalse(fb.sshd_facts()[0]["skip_codes"])
        self.box.sshd = {"192.0.2.1": "authenticationmethods publickey\n"}
        self.assertTrue(fb.sshd_facts()[0]["skip_codes"])

    def test_the_ports_sshd_listens_on(self):
        # Fable review: with ListenAddress 0.0.0.0:2200, sshd -T still says "port 22"
        for plain, ports in (("port 22\nlistenaddress 0.0.0.0:2200\n", ["2200"]),
                             ("port 22\nport 2222\nlistenaddress [::]:22\nlistenaddress [::]:2222\n"
                              "listenaddress 0.0.0.0:22 rdomain x\n", ["22", "2222"]),
                             ("port 2022\n", ["2022"]), ("", ["22"])):
            self.box.plain = plain
            self.assertEqual(fb.sshd_facts()[0]["ports"], ports, plain)
            self.assertEqual({spec.rsplit("lport=", 1)[1] for spec in self.specs()}, set(ports), plain)
            self.box.calls.clear()

    def test_a_family_without_a_route_isnt_asked(self):
        self.box.routes["2001:db8::1"] = None             # no IPv6 here: no stranger comes that way
        self.box.sshd = {"2001:db8::1": "authenticationmethods any\n"}
        self.assertTrue(fb.sshd_facts()[0]["skip_codes"])
        self.assertEqual(len(self.specs()), 1)
        self.box.routes["192.0.2.1"] = None               # no route at all: hb can't tell
        self.assertFalse(fb.sshd_facts()[0]["key_first"])
        self.box.routes, self.box.sshd = dict(ROUTES), {}
        self.box.ip_rc = 1                                # ip can't say: asked without laddr
        self.box.calls.clear()
        self.assertTrue(fb.sshd_facts()[0]["skip_codes"])
        self.assertEqual(self.specs(), ["user=hb-fail2ban,host=hb-fail2ban,addr=192.0.2.1,lport=22",
                                        "user=hb-fail2ban,host=hb-fail2ban,addr=2001:db8::1,lport=22"])

    def test_a_password_anywhere_in_pam_turns_the_exception_off(self):
        # Codex review: a Match User override can let an account in without a key, which the probe
        # (a made-up user) doesn't see. Failures there may only go uncounted if PAM asks for
        # nothing but the code, so they are code guesses, which hb totp limits.
        pam = os.path.join(fb.PAM_DIR, "sshd")
        stock = PAM_SSHD.replace("auth       requisite    pam_exec.so quiet expose_authtok /opt/hb/tools/hb-totp verify\n"
                                 "auth       required     pam_permit.so\n", "auth       substack     password-auth\n")
        early = "#%PAM-1.0\n"
        for name, text, more in (
                ("the stock file", stock, {}),
                ("a password module after the code", PAM_SSHD.replace("auth       include      postlogin",
                                                                      "auth       sufficient   pam_unix.so"), {}),
                ("one in an included file", PAM_SSHD, {"postlogin": PAM_POSTLOGIN + "auth sufficient pam_sss.so\n"}),
                ("an included file that isn't there", PAM_SSHD.replace("include      postlogin",
                                                                        "include      gone"), {}),
                ("no code line at all", "auth required pam_permit.so\n", {}),
                # Fable review: what libpam reads as auth lines too
                ("the type in capitals", PAM_SSHD.replace(early, early + "AUTH sufficient pam_unix.so\n"), {}),
                ("the type in brackets", PAM_SSHD.replace(early, early + "[auth]sufficient pam_unix.so\n"), {}),
                ("a line continued", PAM_SSHD.replace(early, early + "-auth\\\n  sufficient pam_unix.so\n"), {}),
                ("Debian's @include", PAM_SSHD.replace(early, early + "@include common-auth\n"), {}),
                ("a file that includes itself", PAM_SSHD.replace("include      postlogin", "include      sshd"), {}),
                ("an include of a folder", PAM_SSHD.replace("include      postlogin", "include      .."), {})):
            write(pam, text)
            for n, t in more.items():
                write(os.path.join(fb.PAM_DIR, n), t)
            facts, _ = fb.sshd_facts()
            self.assertEqual((facts["key_first"], facts["code_only"], facts["skip_codes"]), (True, False, False), name)
            self.assertIn("(sshd's PAM stack may ask for more than hb totp's code)", fb.summary(cfg(), facts))
            write(os.path.join(fb.PAM_DIR, "postlogin"), PAM_POSTLOGIN)
        write(pam, PAM_SSHD.replace("auth       required     pam_permit.so", "-auth      optional     pam_faildelay.so"))
        self.assertTrue(fb.sshd_facts()[0]["skip_codes"])                  # harmless modules are fine
        with open(pam, "wb") as f:                                        # a Latin-1 comment, trailing ones
            f.write(b"# \xe9t\xe9\n" + PAM_SSHD.replace("auth       required     pam_permit.so",
                                                        "auth       required     pam_permit.so  # a \\").replace(
                "hb-totp verify", "hb-totp verify   # the code").encode())
        self.assertTrue(fb.sshd_facts()[0]["skip_codes"])

    def test_the_pam_service_sshd_names(self):
        # Fable review: PAMServiceName
        write(os.path.join(fb.PAM_DIR, "sshd-hb"), PAM_SSHD.replace("pam_permit.so", "pam_unix.so"))
        self.box.plain = PLAIN.replace("pamservicename sshd", "pamservicename sshd-hb")
        self.assertFalse(fb.sshd_facts()[0]["code_only"])
        self.box.plain = PLAIN.replace("pamservicename sshd\n", "")    # sshd before 9.8 doesn't print it
        self.assertTrue(fb.sshd_facts()[0]["code_only"])

    def test_sshd_that_cant_say(self):
        with mock.patch.object(fb.util, "run", lambda *c, **k: (255, "", "/etc/ssh/sshd_config: line 3: Bad\n")):
            self.assertEqual(fb.sshd_facts(), (None, "sshd -T: /etc/ssh/sshd_config: line 3: Bad"))


class ItemsTest(FakeBoxTest):
    def test_apply_on_a_box_without_fail2ban(self):
        self.box.installed, self.box.active, self.box.enabled = set(), False, False
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 0)
        self.assertEqual(self.box.did("dnf", "install", "-y"), [("dnf", "install", "-y", *fb.PACKAGES)])
        for path in (fb.JAIL_FILE, fb.ACTION_FILE):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        order = [c[:3] for c in self.box.calls if c[0] in ("dnf", "fail2ban-client") or c[:2] == ("systemctl", "enable")]
        self.assertEqual(order[:3], [("dnf", "install", "-y"), ("fail2ban-client", "-t"),
                                     ("systemctl", "enable", "--now")])
        self.assertEqual(self.box.did("fail2ban-client", "reload"), [])   # it wasn't running: started after
        self.assertEqual(fb.verdict(cfg())[0], 0)

    def test_a_new_setting_reloads_the_jail_keeping_its_bans(self):
        self.box.live["maxretry"] = "3"
        self.box.after_reload = {"maxretry": "5"}
        self.assertEqual(fb.chk_jail(cfg())[0], 1)
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 0)
        self.assertEqual(self.box.did("fail2ban-client", "reload"), [("fail2ban-client", "reload", "sshd")])
        # the files already match, but the running jail doesn't: a reload again
        self.box.live["maxretry"] = "3"
        rc, line = fb.chk_jail(cfg())
        self.assertEqual(rc, 1)
        self.assertIn("maxretry '3', not '5': will reload", line)

    def test_each_part_of_the_running_jail_is_compared(self):
        # Codex review: an apply whose reload failed looked done when only these differed
        self.written()
        self.assertEqual(fb.chk_jail(cfg())[0], 0)
        for key, value, says in (("findtime", "300", "findtime '300', not '600'"),
                                 ("ignoreregex", [], "ignoreregex 'none', not 'the code exception'"),
                                 ("actions", ["nftables"], "actions 'no hb-notify', not 'hb-notify'"),
                                 ("ignoreip", ["127.0.0.0/8"], "ignoreip '127.0.0.0/8', not '127.0.0.0/8 ::1/128'"),
                                 ("ignorecommand", "None", "ignorecommand '', not")):
            before = self.box.live[key]
            self.box.live[key] = value
            rc, line = fb.chk_jail(cfg())
            self.assertEqual(rc, 1, key)
            self.assertIn(says, line, key)
            self.box.live[key] = before
        self.box.live["ignoreip"] = ["127.0.0.1/8", "::1"]                  # the same networks, written another way
        self.assertEqual(fb.chk_jail(cfg())[0], 0)
        self.written(cfg(ignoreip=["203.0.113.0/24"]))
        rc, line = fb.chk_jail(cfg(ignoreip=["203.0.113.0/24"]))
        self.assertEqual(rc, 1)
        self.assertIn("203.0.113.0/24", line)

    def test_a_failed_reload_puts_the_old_files_back(self):
        # Codex review: the new files stayed and the next check said ok
        self.box.live["ignoreregex"] = []
        self.box.reload_rc = 1
        err = fb.fix_jail(cfg())
        self.assertIn("fail2ban-client reload: ERROR  NOK", err)
        self.assertIn("the previous files are back, and reloading them failed too", err)
        self.assertFalse(os.path.exists(fb.JAIL_FILE))
        self.assertFalse(os.path.exists(fb.ACTION_FILE))
        self.assertEqual(fb.chk_jail(cfg())[0], 1)                          # still to do
        self.assertNotEqual(fb.verdict(cfg())[0], 0)
        self.box.reload_rc = 0
        self.box.after_reload = {"ignoreregex": [fb.CODE_FAILED]}
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 0)        # the next apply does it

    def test_a_jail_that_wasnt_running_reloads_whole(self):
        # reload sshd answers NOK for a jail fail2ban doesn't run yet; a full reload starts it
        self.box.live["maxretry"] = "3"
        self.box.after_reload = {"maxretry": "5"}
        self.box.jail_running = False
        self.assertIsNone(fb.fix_jail(cfg()))
        self.assertEqual(self.box.did("fail2ban-client", "reload"),
                         [("fail2ban-client", "reload", "sshd"), ("fail2ban-client", "reload")])
        self.assertEqual(self.box.did("fail2ban-client", "restart"), [])     # a jail fail2ban doesn't run

    def test_an_interrupted_apply_puts_the_old_files_back(self):
        # Fable review: Ctrl-C in the reload, or a write that fails, left files never tested or loaded
        write(fb.JAIL_FILE, "[sshd]\nmaxretry = 3\n")

        def interrupt():
            raise KeyboardInterrupt
        self.box.on_reload = interrupt
        with self.assertRaises(KeyboardInterrupt):
            fb.fix_jail(cfg())
        with open(fb.JAIL_FILE) as f:
            self.assertEqual(f.read(), "[sshd]\nmaxretry = 3\n")
        self.assertFalse(os.path.exists(fb.ACTION_FILE))
        self.box.on_reload = None
        real = fb.util.write_atomic
        with mock.patch.object(fb.util, "write_atomic", side_effect=lambda p, *a, **k: (
                (_ for _ in ()).throw(OSError(28, "No space left on device")) if p == fb.ACTION_FILE else real(p, *a, **k))):
            with self.assertRaises(OSError):
                fb.fix_jail(cfg())
        with open(fb.JAIL_FILE) as f:
            self.assertEqual(f.read(), "[sshd]\nmaxretry = 3\n")
        self.assertEqual(self.box.did("fail2ban-client", "-t"), [("fail2ban-client", "-t")])   # the first time only

    def test_apply_looks_at_the_jail_once_fail2ban_runs(self):
        # Fable review: the jail item wrote the files before fail2ban ran; nothing looked after the start
        self.box.active, self.box.enabled, self.box.jail_after_start = False, False, False
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 2)
        self.assertIn("after apply, jail: fail2ban runs without the sshd jail", sys.stdout.getvalue())

    def test_a_failed_item_stops_apply(self):
        self.box.installed, self.box.active, self.box.enabled, self.box.dnf_rc = set(), False, False, 1
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 2)
        self.assertIn("failed: dnf install: Error: Unable to find a match", sys.stdout.getvalue())
        self.assertFalse(os.path.exists(fb.JAIL_FILE))
        self.assertEqual(self.box.did("systemctl", "enable"), [])

    def test_a_started_fail2ban_is_waited_for(self):
        self.box.active, self.box.enabled, self.box.pings_unanswered = False, False, 2
        self.assertIsNone(fb.fix_service(cfg()))
        self.assertEqual(len(self.box.did("fail2ban-client", "ping")), 3)
        self.box.pings_unanswered = 1000
        with mock.patch.object(fb, "WAIT_PING", 0.2):
            self.assertIn("didn't answer fail2ban-client ping within", fb.fix_service(cfg()))

    def test_selinux_enforcing_is_noted(self):
        flag = os.path.join(tempfile.mkdtemp(), "enforce")
        self.box.installed = set()
        for value, noted in (("1", True), ("0", False)):
            write(flag, value)
            out = io.StringIO()
            with mock.patch.object(fb, "SELINUX_ENFORCE", flag), contextlib.redirect_stdout(out):
                fb.do_plan(cfg())
            self.assertEqual("SELinux is enforcing" in out.getvalue(), noted, value)

    def test_fail2ban_without_the_sshd_jail_is_broken(self):
        self.written()
        self.box.jail_running = False
        rc, line = fb.chk_jail(cfg())
        self.assertEqual(rc, 2)
        self.assertIn("fail2ban runs without the sshd jail", line)

    def test_a_file_read_after_ours_is_named(self):
        self.box.after_reload = {"bantime": "600"}
        self.box.live["maxretry"] = "3"
        self.box.after_reload["maxretry"] = "5"
        err = fb.fix_jail(cfg())
        self.assertIn("after the reload the jail runs bantime '600', not '3600'", err)
        self.assertIn(": fail2ban's log may say why", err)               # no file is read after hb's
        jail_d = os.path.dirname(fb.JAIL_FILE)
        for name in ("99-late.conf", "10-early.local", "99-late.local", "zz.local"):
            write(os.path.join(jail_d, name), "[sshd]\nbantime = 10m\n")
        err = fb.fix_jail(cfg())
        # *.conf in jail.d is read before every *.local; *.local in name order
        self.assertIn(": 99-late.local, zz.local in jail.d, read after 95-hb-sshd.local, may set them", err)
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 2)

    def test_a_new_action_restarts_the_jail(self):
        # 13 Nov, on the box: fail2ban 1.1.0's reload dropped hb-notify, which only a restart loads
        self.box.live["actions"] = ["nftables"]
        self.box.after_reload = {"actions": ["nftables", "hb-notify"]}
        line = fb.chk_jail(cfg())[1]                                         # the first apply
        self.assertIn("will write", line)
        self.assertIn("; the jail then restarts (a new action loads only then; its bans come back from "
                      "fail2ban's database)", line)
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 0)
        self.assertEqual(self.box.did("fail2ban-client", "restart"), [("fail2ban-client", "restart", "sshd")])
        self.assertEqual(self.box.did("fail2ban-client", "reload"), [])
        # the box's state after an apply that only reloaded: the files are there, the action isn't
        self.box.calls, self.box.live["actions"] = [], ["nftables"]
        rc, line = fb.chk_jail(cfg())
        self.assertEqual(rc, 1)
        self.assertIn("actions 'no hb-notify', not 'hb-notify': will restart the jail (a new action loads "
                      "only then; its bans come back from fail2ban's database)", line)
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 0)
        self.assertEqual(self.box.did("fail2ban-client", "restart"), [("fail2ban-client", "restart", "sshd")])
        self.assertEqual(self.box.did("fail2ban-client", "reload"), [])
        self.assertEqual(self.box.live["actions"], ["nftables", "hb-notify"])
        self.assertEqual(fb.verdict(cfg())[0], 0)
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 0)        # nothing to do: no second restart
        self.assertEqual(len(self.box.did("fail2ban-client", "restart")), 1)

    def test_a_reload_alone_wouldnt_load_the_action(self):
        # what the box did before: the fake drops the new action as fail2ban 1.1.0 does
        self.box.live["actions"] = ["nftables"]
        self.box.after_reload = {"actions": ["nftables", "hb-notify"]}
        self.assertEqual(fb.reload()[0], 0)
        self.assertEqual(self.box.live["actions"], ["nftables"])
        self.box.reload_adds_actions = True                                  # fail2ban after 1.1.1
        self.assertEqual(fb.reload()[0], 0)
        self.assertEqual(self.box.live["actions"], ["nftables", "hb-notify"])

    def test_what_a_restart_does_to_the_bans_is_said(self):
        # Codex review (round 3): without fail2ban's database a restart lifts the jail's bans
        self.box.live["actions"], self.box.banned = ["nftables"], ["203.0.113.5", "203.0.113.6"]
        self.box.after_reload = {"actions": ["nftables", "hb-notify"]}
        self.box.db = False
        self.assertIn("(dbfile in fail2ban.conf))", fb.chk_jail(cfg())[1])  # said at the first apply too
        self.box.db = True
        self.written()
        self.assertIn("will restart the jail (a new action loads only then; its bans come back from "
                      "fail2ban's database)", fb.chk_jail(cfg())[1])
        self.box.db = False
        rc, line = fb.chk_jail(cfg())
        self.assertEqual(rc, 1)
        self.assertIn("will restart the jail (a new action loads only then; its 2 bans are lifted: fail2ban "
                      "keeps no database (dbfile in fail2ban.conf))", line)
        with mock.patch.object(fb, "banned_now", lambda: None):          # fail2ban can't say
            self.assertIn("any bans it has are lifted: fail2ban keeps no database", fb.chk_jail(cfg())[1])
        # apply asks first; a yes restarts it, and the bans are gone
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 0)
        self.assertEqual(self.box.did("fail2ban-client", "restart"), [("fail2ban-client", "restart", "sshd")])
        self.assertEqual(self.box.banned, [])
        self.box.live["actions"] = ["nftables"]
        self.assertIn("it has no bans to lose)", fb.chk_jail(cfg())[1])

    def test_an_interrupted_restart_starts_the_jail_again(self):
        # Codex review (round 3): Ctrl-C after the restart stopped the jail left it stopped
        self.written()
        old = {p: fb.read(p) for p in (fb.JAIL_FILE, fb.ACTION_FILE)}
        self.box.live["actions"] = ["nftables"]
        self.box.after_reload = {"actions": ["nftables", "hb-notify"]}

        def interrupt():
            self.box.jail_running = False                 # stopped, not started again yet
            raise KeyboardInterrupt
        self.box.on_restart = interrupt
        with self.assertRaises(KeyboardInterrupt):
            fb.fix_jail(cfg())
        self.assertEqual({p: fb.read(p) for p in old}, old)
        self.assertEqual(self.box.did("fail2ban-client", "reload"), [("fail2ban-client", "reload", "sshd"),
                                                                    ("fail2ban-client", "reload")])
        self.assertTrue(self.box.jail_running)
        self.assertNotEqual(fb.chk_jail(cfg())[0], 2)
        # interrupted before the restart began (a write that fails): nothing to start again
        self.box.calls, self.box.on_restart = [], None
        real, writes = fb.util.write_atomic, []

        def full_once(p, *a, **k):                         # the first write fails, putting back works
            writes.append(p)
            if len(writes) == 1:
                raise OSError(28, "No space left on device")
            return real(p, *a, **k)
        with mock.patch.object(fb.util, "write_atomic", full_once):
            with self.assertRaises(OSError):
                fb.fix_jail(cfg())
        self.assertEqual(len(writes), 3)                    # the failed one, then both put back
        self.assertEqual({p: fb.read(p) for p in old}, old)
        self.assertEqual(self.box.did("fail2ban-client"), [])   # neither -t nor a reload: nothing to start again

    def test_a_failed_restart_puts_the_old_files_back(self):
        self.box.live["actions"] = ["nftables"]
        self.box.after_reload = {"actions": ["nftables", "hb-notify"]}
        self.box.restart_rc = 255
        err = fb.fix_jail(cfg())
        self.assertIn("fail2ban-client restart: ERROR  Failed to start jail 'sshd' action 'hb-notify'; "
                      "the previous files are back", err)
        self.assertNotIn("failed too", err)
        self.assertFalse(os.path.exists(fb.JAIL_FILE))
        self.assertFalse(os.path.exists(fb.ACTION_FILE))
        # the restart left the jail stopped: a whole reload starts it again
        self.assertEqual(self.box.did("fail2ban-client", "reload"), [("fail2ban-client", "reload", "sshd"),
                                                                    ("fail2ban-client", "reload")])
        self.assertTrue(self.box.jail_running)

    def test_taking_the_action_out_only_reloads(self):
        # a reload removes an action fine (notify_days 0: no texts)
        self.box.after_reload = {"actions": ["nftables"]}
        rc, line = fb.chk_jail(cfg(notify_days=0))
        self.assertEqual(rc, 1)
        self.assertIn("will write", line)
        self.assertNotIn("restarts", line)
        self.written(cfg(notify_days=0))
        rc, line = fb.chk_jail(cfg(notify_days=0))
        self.assertIn("actions 'hb-notify', not 'no hb-notify': will reload the jail", line)
        self.assertIsNone(fb.fix_jail(cfg(notify_days=0)))
        self.assertEqual(self.box.did("fail2ban-client", "restart"), [])
        self.assertEqual(self.box.live["actions"], ["nftables"])
        # without texts, a jail without hb-notify is as wanted: another setting only reloads it
        self.box.live["maxretry"], self.box.after_reload = "3", {"maxretry": "5"}
        self.assertIn("will reload the jail", fb.chk_jail(cfg(notify_days=0))[1])
        self.assertIsNone(fb.fix_jail(cfg(notify_days=0)))
        self.assertEqual(self.box.did("fail2ban-client", "restart"), [])

    def test_refused_settings_put_the_old_files_back(self):
        write(fb.JAIL_FILE, "[sshd]\nmaxretry = 3\n")
        self.box.test_rc = 1
        err = fb.fix_jail(cfg())
        self.assertIn("fail2ban-client -t refused them (ERROR  Failed during configuration", err)
        self.assertIn("the previous files are back", err)
        with open(fb.JAIL_FILE) as f:
            self.assertEqual(f.read(), "[sshd]\nmaxretry = 3\n")
        self.assertFalse(os.path.exists(fb.ACTION_FILE))                  # it wasn't there before
        self.assertEqual(self.box.did("fail2ban-client", "reload"), [])

    def test_hb_run_from_a_checkout_is_refused(self):
        fb.unsafe_tree = lambda: "/home/you is you's"
        self.box.installed, self.box.active, self.box.enabled = set(), False, False
        rc, line = fb.chk_jail(cfg())
        self.assertEqual(rc, 2)
        self.assertIn(f"fail2ban would run hb from {fb.util.HB_ROOT} as root, but /home/you is you's: use the copy", line)
        self.assertEqual(fb.do_plan(cfg(), apply=True, yes=True), 2)
        self.assertEqual(self.box.did("systemctl", "enable"), [])         # nothing after the refusal

    def test_plan_changes_nothing(self):
        self.box.installed, self.box.active, self.box.enabled = set(), False, False
        self.assertEqual(fb.do_plan(cfg()), 1)
        self.assertEqual([c for c in self.box.calls if c[0] == "dnf" or c[1:2] in (("-t",), ("enable",))], [])
        self.assertFalse(os.path.exists(fb.JAIL_FILE))

    def test_a_declined_item_stops_there(self):
        self.box.installed = set()
        with mock.patch.object(fb.util, "ask", lambda q: False):
            self.assertEqual(fb.do_plan(cfg(), apply=True), 1)
        self.assertEqual(self.box.did("dnf"), [])
        self.assertFalse(os.path.exists(fb.JAIL_FILE))


class TreeTest(unittest.TestCase):
    """What fail2ban runs as root must be root's alone: hb's tree and hb.toml, as sudocheck judges
    them (tests/test_sudocheck.py)."""

    def test_its_own_tree_and_host_file(self):
        # Codex review: the hooks run without HB_CONFIG, so the file it names isn't the one to judge
        with mock.patch.object(fb.sudocheck, "hb_problems", return_value=["a", "b"]) as hb, \
             mock.patch.dict(os.environ, HB_CONFIG="/srv/safe.toml"):
            self.assertEqual(fb.unsafe_tree(), "a")
        hb.assert_called_once_with(fb.util.HB_ROOT, ["/etc/hb/hb.toml"])
        with mock.patch.object(fb.sudocheck, "hb_problems", return_value=[]):
            self.assertIsNone(fb.unsafe_tree())


class LoginsTest(FakeBoxTest):
    def setUp(self):
        super().setUp()
        now = time.time()
        self.box.journal = [
            (now - 3600, "Accepted keyboard-interactive/pam for alice from 203.0.113.9 port 5 ssh2"),
            (now - 7200, "Accepted publickey for ec2-user from 203.0.113.9 port 6 ssh2"),
            (now - 2 * 86400, "Accepted publickey for rescue from 2001:db8::7 port 6 ssh2"),
            (now - 2 * 86400, "Accepted keyboard-interactive/pam for administrator from "
                              "2001:db8:1234:5678:abcd:ef01:2345:6789 port 6 ssh2"),
            (now - 600, "Partial publickey for alice from 198.51.100.4 port 7 ssh2: ED25519 SHA256:x"),
            (now - 600, "Failed keyboard-interactive/pam for alice from 198.51.100.5 port 8 ssh2"),
            (now - 40 * 86400, "Accepted publickey for alice from 198.51.100.6 port 9 ssh2"),
        ]

    def test_logins(self):
        self.box.journal += [(time.time() - 60, list(b"Accepted publickey for \xe9 from 198.51.100.9 port 1")),
                             (time.time() - 60, None)]                  # journalctl prints bytes as a list
        self.box.journal_raw = ["not json {"]
        day = fb.logins(1)
        self.assertEqual(set(day), {fb.address("203.0.113.9")})
        self.assertEqual(day[fb.address("203.0.113.9")][0], "alice")    # the newest of its two
        self.assertEqual(set(fb.logins(30)), {fb.address("203.0.113.9"), fb.address("2001:db8::7"),
                                              fb.address("2001:db8:1234:5678:abcd:ef01:2345:6789")})
        # Fable review: journalctl picks the lines (a 30-day read was 5 to 25 s and 47 MB)
        reads = self.box.did("journalctl")
        self.assertTrue(all(c[-2:] == ("--grep", "^Accepted ") for c in reads), reads)
        self.box.grep = False                             # a journalctl without pattern matching
        self.assertEqual(set(fb.logins(1)), {fb.address("203.0.113.9")})
        self.assertEqual(self.box.did("journalctl")[-1][-1], "-q")
        self.box.grep, self.box.journal, self.box.journal_raw = True, [], []   # --grep finds nothing: exit 1, silent
        self.assertEqual(fb.logins(30), {})

    def test_logins_where_the_unit_is_ssh(self):
        # Debian and Ubuntu name sshd's unit ssh.service (sshd.service is an alias, not in the journal)
        self.box.unit = "ssh.service"
        self.assertEqual(set(fb.logins(1)), {fb.address("203.0.113.9")})
        self.box.unit = "session-4.scope"                 # a user's process writing "Accepted" lines
        self.assertEqual(fb.logins(30), {})

    def test_known(self):
        self.assertEqual(fb.do_known(cfg(), "203.0.113.9"), 0)
        self.assertEqual(fb.do_known(cfg(), "2001:db8::7"), 1)              # two days ago
        self.assertEqual(fb.do_known(cfg(known_days=3), "2001:0db8:0::7"), 0)
        for stranger in ("198.51.100.4", "198.51.100.5", "198.51.100.6"):  # a key half-way, a failure, too old
            self.assertEqual(fb.do_known(cfg(known_days=3), stranger), 1, stranger)
        self.assertEqual(fb.do_known(cfg(known_days=0), "203.0.113.9"), 1)
        for bad in ("host.example", "203.0.113.9; rm -rf /", ""):
            self.assertEqual(fb.do_known(cfg(), bad), 2, bad)
        with mock.patch.object(fb.util, "run", lambda *c, **k: (1, "", "No journal files were found.")):
            self.assertEqual(fb.do_known(cfg(), "203.0.113.9"), 2)          # fail2ban then bans as usual

    def test_a_ban_of_an_address_that_logged_in_texts(self):
        self.assertEqual(fb.do_banned(cfg(), "2001:db8::7"), 0)
        sent = self.box.did("systemd-run")
        self.assertEqual(len(sent), 1)
        cmd = sent[0]
        self.assertIn("--no-block", cmd)                   # the ban doesn't wait for the SMS
        self.assertEqual(cmd[-7:-1], (util.HB, "notify", "send", "--every-time", "fail", "fail2ban.ban"))
        self.assertTrue(cmd[-1].startswith("sudo hb fail2ban unban 2001:db8::7 lifts a 60 min ban"))
        self.assertIn("rescue logged in from it", cmd[-1])

    def test_the_sms_keeps_the_whole_command(self):
        # Codex review: a full IPv6 address cut the command off
        ip = "2001:db8:1234:5678:abcd:ef01:2345:6789"
        self.assertEqual(fb.do_banned(cfg(), ip), 0)
        msg = self.box.did("systemd-run")[-1][-1]
        sms = notify.sms_text("fail", "fail2ban.ban", msg, "a-long-box-name.internal.example.org")
        self.assertIn(f"sudo hb fail2ban unban {ip} ", sms)

    def test_an_sms_that_wasnt_handed_over_is_an_error(self):
        # Fable review: exit 0 and nothing in fail2ban's log
        self.box.systemd_run_rc = 1
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(fb.do_banned(cfg(), "2001:db8::7"), 2)
        self.assertIn("the SMS for 2001:db8::7 wasn't sent: systemd-run: Failed to start", err.getvalue())

    def test_a_stranger_banned_texts_nobody(self):
        for who, c in (("198.51.100.4", cfg()), ("198.51.100.6", cfg()), ("2001:db8::7", cfg(notify_days=0))):
            self.assertEqual(fb.do_banned(c, who), 0)
        self.assertEqual(fb.do_banned(cfg(), "nonsense"), 2)
        self.assertEqual(self.box.did("systemd-run"), [])

    def test_unban(self):
        self.box.banned = ["203.0.113.9"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(fb.do_unban(cfg(), "203.0.113.9"), 0)
            self.assertEqual(fb.do_unban(cfg(), "198.51.100.4"), 0)
        self.assertIn("lifted the sshd jail's ban of 203.0.113.9", out.getvalue())
        self.assertIn("198.51.100.4 wasn't banned", out.getvalue())
        calls = len(self.box.calls)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(fb.do_unban(cfg(), "203.0.113.9."), 2)
        self.assertEqual(len(self.box.calls), calls)                       # nothing passed to fail2ban
        self.box.unban_rc = 255
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(fb.do_unban(cfg(), "203.0.113.9"), 2)
        self.assertIn("fail2ban-client: Sorry but the jail 'sshd' does not exist", err.getvalue())

    def test_status(self):
        self.written()
        self.box.journal = [(time.time() - 3600, "Accepted publickey for alice from 203.0.113.9 port 5 ssh2")]
        self.box.banned = ["198.51.100.4", "203.0.113.9"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(fb.do_status(cfg()), 0)
        text = out.getvalue()
        for want in ("ok    package", "ok    jail     sshd jail: 5 failures in 10 min ban for 60 min",
                     "ok    service", "jails: nginx-http-auth, sshd", "sshd jail has banned 2:",
                     "        198.51.100.4\n", "203.0.113.9   alice logged in from it"):
            self.assertIn(want, text)


class VerdictTest(FakeBoxTest):
    def test_not_managed(self):
        self.assertEqual(fb.verdict(cfg(enabled=False)), (0, "ok: not managed (fail2ban.enabled is false)"))

    def test_turned_off_takes_hbs_files_out(self):
        # Fable review: they stayed in force, running hb as root, while check said "not managed"
        self.written()
        rc, line = fb.verdict(cfg(enabled=False))
        self.assertEqual(rc, 1)
        self.assertIn(f"warn: fail2ban.enabled is false, but {fb.JAIL_FILE} and {fb.ACTION_FILE} still set", line)
        fb.unsafe_tree = lambda: "/home/you is you's"
        rc, line = fb.verdict(cfg(enabled=False))
        self.assertEqual(rc, 2)
        self.assertIn(f"runs hb from {fb.util.HB_ROOT} as root, and /home/you is you's: sudo hb fail2ban apply", line)
        fb.unsafe_tree = lambda: None
        self.assertEqual(fb.do_remove(apply=False), 1)
        self.assertTrue(os.path.exists(fb.JAIL_FILE))
        self.box.test_rc = 1                              # the files without hb's don't pass -t: hb's come back
        self.assertEqual(fb.do_remove(apply=True, yes=True), 2)
        self.assertTrue(os.path.exists(fb.JAIL_FILE) and os.path.exists(fb.ACTION_FILE))
        self.box.test_rc = 0
        self.assertEqual(fb.do_remove(apply=True, yes=True), 0)
        self.assertEqual(fb.left_behind(), [])
        self.assertEqual(self.box.did("fail2ban-client", "reload"), [("fail2ban-client", "reload", "sshd")])
        self.assertEqual(fb.verdict(cfg(enabled=False))[0], 0)
        self.assertEqual(fb.do_remove(apply=True, yes=True), 0)            # nothing left: nothing to do
        self.written()                                    # fail2ban gone (dnf remove), hb's files left
        self.box.installed, self.box.calls = set(), []
        self.assertEqual(fb.do_remove(apply=True, yes=True), 0)
        self.assertEqual(fb.left_behind(), [])
        self.assertEqual(self.box.did("fail2ban-client"), [])

    def test_settings_that_cant_be(self):
        rc, line = fb.verdict(cfg(maxretry=0, known_days=True, mode="loud", ignoreip=["nope", "10.0.0.0/8"]))
        self.assertEqual(rc, 2)
        for want in ("fail2ban.maxretry must be", "fail2ban.known_days must be", "fail2ban.mode must be",
                     "fail2ban.ignoreip: 'nope'"):
            self.assertIn(want, line)
        self.assertNotIn("10.0.0.0/8", line)

    def test_a_banned_address_that_logged_in_is_named(self):
        self.written()
        now = time.time()
        self.box.journal = [(now - 3 * 86400, "Accepted publickey for alice from 203.0.113.9 port 5 ssh2")]
        self.box.banned = ["198.51.100.4", "203.0.113.9"]
        rc, line = fb.verdict(cfg())
        self.assertEqual(rc, 1)
        self.assertIn("warn: the sshd jail has banned 203.0.113.9 (alice logged in from it", line)
        self.assertNotIn("198.51.100.4", line)
        self.box.banned = ["198.51.100.4"]
        self.assertEqual(fb.verdict(cfg()), (0, "ok: sshd jail on, 5 failures in 10 min ban for 60 min; 1 banned now"))

    def test_fail2ban_that_doesnt_answer(self):
        self.written()
        real = self.box.run
        self.box.run = lambda *c, **k: (255, "", "") if c[1:] == ("status", "sshd") else real(*c, **k)
        with mock.patch.object(fb.util, "run", self.box.run):
            self.assertEqual(fb.verdict(cfg())[0], 2)

    def test_an_item_to_do_is_a_warning(self):
        self.box.active = False
        rc, line = fb.verdict(cfg())
        self.assertEqual(rc, 1)
        self.assertIn("jail: will write", line)
        self.assertIn("service: will start fail2ban.service", line)


class MainTest(unittest.TestCase):
    def test_root_only(self):
        with mock.patch.object(fb.os, "geteuid", return_value=1000), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(fb.main(["hb-fail2ban", "known", "203.0.113.9"]), 2)

    def test_the_address_verbs(self):
        with mock.patch.object(fb.os, "geteuid", return_value=0), \
                mock.patch.object(fb.config, "load", return_value=cfg()), \
                mock.patch.object(fb, "do_known", lambda c, a: 0 if a == "203.0.113.9" else 1), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(fb.main(["hb-fail2ban", "known", "203.0.113.9"]), 0)
            self.assertEqual(fb.main(["hb-fail2ban", "known"]), 2)
            self.assertEqual(fb.main(["hb-fail2ban", "unban", "a", "b"]), 2)
            self.assertEqual(fb.main(["hb-fail2ban", "nonsense"]), 2)

    def test_settings_that_cant_be_change_nothing(self):
        box = Box()
        with mock.patch.object(fb.os, "geteuid", return_value=0), \
                mock.patch.object(fb.config, "load", return_value=cfg(maxretry=0)), \
                mock.patch.object(fb.util, "run", box.run), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(fb.main(["hb-fail2ban", "apply", "--yes"]), 2)
        self.assertIn("fail2ban.maxretry must be", out.getvalue())
        self.assertEqual(box.calls, [])


if __name__ == "__main__":
    unittest.main()
