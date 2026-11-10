"""hb-k8s's restart, linger and metadata items, as (namespace) root with systemctl, loginctl and nft
faked (and nft for real, in a network namespace); the other items not managed."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

# systemctl show answers what systemd would have loaded: snapd's defaults, or hb's drop-in once it's there
FAKE_SYSTEMCTL = """#!/bin/sh
echo "$*" >> {log}
if [ "$1" = show ]; then
  if [ -f "{units}/$2.d/10-hb-keep-restarting.conf" ]; then
    printf 'RestartUSec=10s\\nStartLimitIntervalUSec=0\\n'
  else
    printf 'RestartUSec=100ms\\nStartLimitIntervalUSec=10s\\n'
  fi
fi
exit 0
"""


def can_fake_root():
    return shutil.which("unshare") is not None and subprocess.run(
        ["unshare", "-r", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
@unittest.skipUnless(os.path.exists("/snap/bin/microk8s"), "hb-k8s exits early without microk8s")
class KeepRestartingTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.units, self.bin, self.log = f"{d}/units", f"{d}/bin", f"{d}/systemctl.log"
        os.makedirs(self.units)
        os.makedirs(self.bin)
        with open(f"{self.bin}/systemctl", "w") as f:
            f.write(FAKE_SYSTEMCTL.format(log=self.log, units=self.units))
        os.chmod(f"{self.bin}/systemctl", 0o755)
        self.toml = f"{d}/hb.toml"
        self.config('["kubelite", "k8s-dqlite"]')

    def config(self, daemons):
        with open(self.toml, "w") as f:
            f.write(f"[k8s]\nkeep_restarting = {daemons}\n")

    def tool(self, *args):
        env = {**os.environ, "HB_CONFIG": self.toml, "HB_SYSTEMD_DIR": self.units, "HB_STATE": f"{self.d}/state",
               "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-k8s"), *args], env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              start_new_session=True)

    def dropin(self, daemon):
        return f"{self.units}/snap.microk8s.daemon-{daemon}.service.d/10-hb-keep-restarting.conf"

    def test_pending_then_applied(self):
        r = self.tool("status")
        line = next(l for l in r.stdout.splitlines() if " restart " in f" {l} ")
        self.assertIn("kubelite: no drop-in; k8s-dqlite: no drop-in", line)
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for daemon in ("kubelite", "k8s-dqlite"):
            with open(self.dropin(daemon)) as f:
                text = f.read()
            self.assertIn("[Unit]\nStartLimitIntervalSec=0\n[Service]\nRestartSec=10s\n", text)
            self.assertEqual(os.stat(self.dropin(daemon)).st_mode & 0o777, 0o644)
            self.assertEqual(os.stat(os.path.dirname(self.dropin(daemon))).st_mode & 0o777, 0o755)
        with open(self.log) as f:
            self.assertIn("daemon-reload", f.read())
        r = self.tool("status")
        self.assertIn("kubelite k8s-dqlite: retry every 10 s, no limit", r.stdout)
        self.assertEqual(self.tool("check").returncode, 0)

    def test_an_edited_dropin_is_pending_again(self):
        self.tool("apply", "--yes")
        with open(self.dropin("kubelite"), "a") as f:
            f.write("RestartSec=1h\n")
        self.assertEqual(self.tool("check").returncode, 1)

    def test_not_managed_by_default_and_names_checked(self):
        self.config("[]")
        self.assertIn("not managed", next(l for l in self.tool("status").stdout.splitlines() if "restart" in l))
        self.config('["../../evil"]')
        self.assertEqual(self.tool("check").returncode, 2)
        self.assertEqual(os.listdir(self.units), [])


# root's user manager runs while root lingers (and nobody stopped it); systemd-oomd as the test sets it
LINGER_SYSTEMCTL = """#!/bin/sh
echo "systemctl $*" >> {log}
case "$1 $2" in
  "is-active user@0.service")
    if [ -e "{linger}/root" ] && [ ! -e "{d}/stopped" ]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
  "is-active systemd-oomd.service")
    if [ -e "{d}/oomd" ]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
  "show user@0.service")
    if [ -e "{d}/oomd-kill" ]; then echo kill; else echo auto; fi ;;
  "start --no-block")
    if [ "$3" = user@0.service ]; then rm -f "{d}/stopped"; fi ;;
esac
exit 0
"""
# as logind 252: enabling linger starts the manager only for a user it hasn't started yet, so a
# manager stopped while a root session pins root's record (the "stopped" flag) stays stopped
LINGER_LOGINCTL = """#!/bin/sh
echo "loginctl $*" >> {log}
if [ "$1 $2" = "enable-linger root" ]; then mkdir -p "{linger}" && touch "{linger}/root"; fi
exit 0
"""


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
@unittest.skipUnless(os.path.exists("/snap/bin/microk8s"), "hb-k8s exits early without microk8s")
class LingerTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.bin, self.log, self.linger = f"{d}/bin", f"{d}/calls.log", f"{d}/linger"
        os.makedirs(self.bin)
        for name, text in (("systemctl", LINGER_SYSTEMCTL), ("loginctl", LINGER_LOGINCTL)):
            with open(f"{self.bin}/{name}", "w") as f:
                f.write(text.format(log=self.log, linger=self.linger, d=d))
            os.chmod(f"{self.bin}/{name}", 0o755)
        self.toml = f"{d}/hb.toml"
        self.config("linger_root = true")

    def config(self, line):
        with open(self.toml, "w") as f:
            f.write(f"[k8s]\n{line}\n")

    def flag(self, name):
        open(f"{self.d}/{name}", "w").close()

    def tool(self, *args):
        env = {**os.environ, "HB_CONFIG": self.toml, "HB_LINGER_DIR": self.linger, "HB_SYSTEMD_DIR": f"{self.d}/units",
               "HB_STATE": f"{self.d}/state", "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-k8s"), *args], env=env,
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              start_new_session=True)

    def line(self):
        return next(l for l in self.tool("status").stdout.splitlines() if l.split()[1:2] == ["linger"])

    def calls(self, prog):
        try:
            with open(self.log) as f:
                return [l.strip() for l in f if l.startswith(prog + " ")]
        except OSError:
            return []

    def enabled(self):
        return self.calls("loginctl").count("loginctl enable-linger root")

    def test_pending_then_applied(self):
        self.assertIn("root's user manager stops after each root session", self.line())
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.enabled(), 1)
        self.assertTrue(os.path.exists(f"{self.linger}/root"))
        self.assertIn("ok    linger         root lingers: its user manager runs from boot", self.line())
        self.assertEqual(self.tool("check").returncode, 0)
        self.tool("apply", "--yes")
        self.assertEqual(self.enabled(), 1)                    # nothing to do

    def test_a_stopped_manager_is_started_again(self):
        self.tool("apply", "--yes")
        self.flag("stopped")                                   # systemctl stop user@0, or terminate-user root
        self.assertIn("root lingers, but its user manager isn't running", self.line())
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(self.enabled(), 2)
        self.assertIn("systemctl start --no-block user@0.service", self.calls("systemctl"))
        self.assertEqual(self.tool("check").returncode, 0, r.stdout + r.stderr)

    def test_refused_where_systemd_oomd_watches_user_managers(self):
        self.flag("oomd")                                      # oomd runs, but leaves user@ alone: fine
        self.assertEqual(self.tool("check").returncode, 1)
        self.flag("oomd-kill")                                 # Fedora's systemd-oomd-defaults
        self.assertIn("systemd-oomd ends processes in root's user manager", self.line())
        self.assertEqual(self.tool("check").returncode, 2)
        self.tool("apply", "--yes")
        self.assertEqual(self.enabled(), 0)
        self.assertFalse(os.path.exists(f"{self.linger}/root"))

    def test_not_managed_by_default_and_never_undone(self):
        self.config("")
        self.assertIn("not managed", self.line())
        os.makedirs(self.linger)
        self.flag("linger/root")                               # root lingers, set by someone else
        self.assertEqual(self.tool("check").returncode, 0)
        self.tool("apply", "--yes")
        self.assertEqual(self.calls("loginctl"), [])           # neither enabled nor disabled
        self.assertTrue(os.path.exists(f"{self.linger}/root"))



# nft as hb uses it. In the test's own network namespace: -c and -f with hb's file, list, delete;
# the table kept in a folder, listed the way real nft lists it (the drops 3 each); rules hb inserts
# and deletes by handle (-a shows handles), each counting the packets the fake curl recorded. With the "stale" flag the cgroup
# shows as an id, as when it was made again; with "reject" nft takes nothing. In any other network
# namespace (hb's scratch check of nftables.service's file) a ruleset of tables: -f /dev/stdin
# seeds it, -f FILE follows FILE's includes, empties it on `flush ruleset` and adds what `table`
# names, and list ruleset prints it.
MD_NFT = """#!/bin/sh
echo "nft $*" >> {log}
if [ "$(readlink /proc/self/ns/net)" != "$(cat {d}/mainns)" ]; then
  S={d}/scratch-$(readlink /proc/self/ns/net | tr -dc 0-9); touch "$S"
  case "$1 $2" in
    "-f /dev/stdin") grep -E '^add table ' | sed 's/^add //' > "$S" ;;     # each check starts afresh
    "list ruleset") sort -u "$S" ;;
    -f*) text=$(cat "$2"); for f in $(printf '%s\\n' "$text" | sed -nE 's/^include "(.*)"$/\\1/p'); do text="$text
$(cat "$f")"; done
         case "$text" in *"flush ruleset"*) : > "$S" ;; esac
         printf '%s\\n' "$text" | grep -v '^include' | grep -oE 'table [a-z0-9]+ [A-Za-z0-9_-]+' >> "$S" ;;
  esac
  exit 0
fi
S={d}/nftstate
a=""; [ "$1" = -a ] && {{ a=1; shift; }}
case "$1" in
  -c) [ -e {d}/reject ] && exit 1; exit 0 ;;
  -f) [ -e {d}/reject ] && exit 1
      rm -rf "$S" {d}/stale; mkdir -p "$S"; : > "$S/temp"
      for c in forward output; do
        sed -n "/chain $c/,/}}/p" "$2" | grep -E '^[[:space:]]+ip6? daddr' | sed 's/^[[:space:]]*//' > "$S/$c"
      done ;;
  insert) [ -d "$S" ] || exit 1; shift 5
      h=$(( $(cat "$S/handle" 2>/dev/null || echo 100) + 1 )); echo $h > "$S/handle"
      echo "$h|$*" >> "$S/temp" ;;
  list)
    if [ "$2" = tables ]; then [ -d "$S" ] && echo "table inet hb_metadata"; cat {d}/othertables 2>/dev/null; exit 0; fi
    [ -d "$S" ] || exit 1
    printf 'table inet hb_metadata {{\\n\\tchain forward {{\\n\\t\\ttype filter hook forward priority filter - 10; policy accept;\\n'
    # a rule hb put in counts the packets (in the "packets" file) from its source address and port
    while IFS='|' read -r h r; do
      src=$(echo "$r" | sed -nE 's/.*saddr ([0-9.]+).*/\\1/p'); port=$(echo "$r" | sed -nE 's/.*sport ([0-9]+).*/\\1/p')
      n=$(grep -cx "$src $port" {d}/packets 2>/dev/null)
      printf '\\t\\t%s%s\\n' "$(echo "$r" | sed "s/counter /counter packets $n bytes 60 /")" "${{a:+ # handle $h}}"
    done < "$S/temp"
    sed "s/counter drop/counter packets 3 bytes 180 drop/; s/^/\\t\\t/" "$S/forward"
    printf '\\t}}\\n\\n\\tchain output {{\\n\\t\\ttype filter hook output priority filter - 10; policy accept;\\n'
    if [ -e {d}/stale ]; then sed 's/level 1 "[^"]*"/level 1 4242/' "$S/output"; else cat "$S/output"; fi \\
      | sed 's/counter drop/counter packets 3 bytes 180 drop/; s/^/\\t\\t/'
    printf '\\t}}\\n}}\\n' ;;
  delete) if [ "$2" = rule ]; then grep -v "^$7|" "$S/temp" > "$S/temp.new"; mv "$S/temp.new" "$S/temp"; else rm -rf "$S"; fi ;;
esac
exit 0
"""
# systemd for hb's units: enable remembers, restart runs the unit's own ExecStart lines, a
# unit's drop-ins count as loaded once they are there and daemon-reload ran after them;
# nftables.service is installed unless the "no-nftables" flag is there
MD_SYSTEMCTL = """#!/bin/sh
echo "systemctl $*" >> {log}
case "$1" in
  daemon-reload) find {units} -name '*.conf' > {d}/reloaded 2>/dev/null ;;
  is-enabled) [ -e "{d}/enabled-$2" ] && {{ echo enabled; exit 0; }}; echo disabled; exit 1 ;;
  enable) touch "{d}/enabled-$2" ;;
  restart)
    grep '^ExecStart=' "{units}/$2" | sed 's/^ExecStart=//; s#^/usr/sbin/nft#nft#' | while read -r c; do
      sh -c "$c" || exit 1
    done ;;
  show)
    case "$2 $4" in
      "nftables.service LoadState") [ -e {d}/no-nftables ] && echo not-found || echo loaded ;;
      "nftables.service FragmentPath") echo {d}/nftables.service ;;
      *)  base={units}/$2; [ "$2" = nftables.service ] && base={d}/nftables.service
          files=""; [ -f "$base" ] && files="$base"
          for f in $(ls {units}/$2.d/*.conf 2>/dev/null | LC_ALL=C sort); do grep -qxF "$f" {d}/reloaded 2>/dev/null && files="$files $f"; done
          [ -n "$files" ] && awk -v p="$4" -f {bin}/effective.awk $files ;;
    esac ;;
esac
exit 0
"""
# what systemctl show prints for a setting, from a unit file and its drop-ins in order: an empty
# assignment resets a command list, the -+!@: prefixes and quotes go; After= and Wants= add up
EFFECTIVE_AWK = r"""
index($0, p "=") == 1 {
  v = substr($0, length(p) + 2)
  if (p == "After" || p == "Wants") { w = w " " v; next }
  if (v == "") { n = 0; next }
  pre = v; sub(/[^-+!@:].*$/, "", pre); v = substr(v, length(pre) + 1); gsub(/["\047]/, "", v)
  split(v, x, " "); path[++n] = x[1]; ign[n] = (index(pre, "-") ? "yes" : "no")
  args[n] = (index(pre, "@") ? substr(v, length(x[1]) + 2) : v)
}
END {
  if (p == "After" || p == "Wants") { sub(/^ /, "", w); print w; exit }
  for (i = 1; i <= n; i++) printf "{ path=%s ; argv[]=%s ; ignore_errors=%s ; start_time=[n/a] }\n", path[i], args[i], ign[i]
}
"""
# busctl for systemd's commands: LoadUnit, then get-property of an Exec setting as systemd serves it
# (a(sasbttttuii): path, argv, ignore_errors, ...), from the unit file and its loaded drop-ins in
# name order, each command split into its arguments the way systemd's own quoting does
FAKE_BUSCTL = r"""#!/usr/bin/env python3
import json, os, shlex, sys
units = os.environ["HB_SYSTEMD_DIR"]; d = os.path.dirname(units); args = sys.argv[1:]
flag = lambda name: os.path.exists(os.path.join(d, name))
if "call" in args:
    if flag("busctl-loadunit-fails"):
        sys.exit(1)
    print(json.dumps({"type": "o", "data": ["/fake/" + args[-1]]})); sys.exit()
unit, prop = args[args.index("get-property") + 2].split("/fake/", 1)[1], args[-1]
if flag("busctl-fails-" + prop):                 # this property's read fails
    sys.exit(1)
if flag("busctl-garbage"):
    print("Failed to get property"); sys.exit()
if flag("busctl-wrong-type"):
    print(json.dumps({"type": "as", "data": []})); sys.exit()
base = os.path.join(d, "nftables.service") if unit == "nftables.service" else os.path.join(units, unit)
try:
    loaded = set(open(os.path.join(d, "reloaded")).read().split())
except OSError:
    loaded = set()
drop = os.path.join(units, unit + ".d")
files = ([base] if os.path.isfile(base) else []) + sorted(
    os.path.join(drop, f) for f in (os.listdir(drop) if os.path.isdir(drop) else [])
    if f.endswith(".conf") and os.path.join(drop, f) in loaded)
cmds = []
for f in files:
    for line in open(f):
        line = line.rstrip("\n")
        if not line.startswith(prop + "="):
            continue
        v = line[len(prop) + 1:]
        if not v:
            cmds = []
            continue
        pre = ""
        while v and v[0] in "-+!@:":
            pre, v = pre + v[0], v[1:]
        words = shlex.split(v)
        path, argv = (words[0], words[1:]) if "@" in pre else (words[0], words)
        cmds.append([path, argv, "-" in pre, 0, 0, 0, 0, 0, 0, 0])
print(json.dumps({"type": "a(sasbttttuii)", "data": cmds}))
"""
# the probe from a pod's network: nsenter runs what follows -- (or fails, with "nsenter-fails");
# curl answers what the "probe" file says (000 = no answer, exit 28; with "refused", exit 7), takes
# 2 s with "slow", logs the proxy setting it sees, and a request hb's rule drops ("inpath") counts
MD_NSENTER = """#!/bin/sh
echo "nsenter $*" >> {log}
case "$*" in *curl*) [ -e {d}/nsenter-fails ] && exit 1 ;; esac
while [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done; shift
exec "$@"
"""
# curl from the pod (10.1.0.5): a request hb's chain sees ("inpath") is recorded as "SOURCE PORT";
# with "otherpacket" another namespace's packet from the same port is too
MD_CURL = """#!/bin/sh
echo "curl $* proxy=${{http_proxy:-none}}" >> {log}
[ -e {d}/slow ] && sleep 2
port=$(echo "$*" | sed -nE 's/.*--local-port ([0-9]+).*/\\1/p')
code=$(cat {d}/probe 2>/dev/null || echo 000)
[ "$code" = 000 ] && [ -e {d}/inpath ] && echo "10.1.0.5 $port" >> {d}/packets
[ -e {d}/otherpacket ] && echo "10.1.9.9 $port" >> {d}/packets
printf '%s' "$code"
[ "$code" = 000 ] && {{ [ -e {d}/refused ] && exit 7; exit 28; }}
exit 0
"""
MD_IP = """#!/bin/sh
[ -e {d}/noroute ] && exit 2
echo "169.254.169.254 via 10.1.0.1 dev eth0 src 10.1.0.5 uid 0"
"""


def real_nft_works():
    return (shutil.which("nft") is not None and os.path.isdir("/sys/fs/cgroup/kubepods") and
            subprocess.run(["unshare", "-rn", "nft", "list", "ruleset"], capture_output=True).returncode == 0)


@unittest.skipUnless(can_fake_root(), "needs unprivileged user namespaces (unshare -r)")
class MetadataTest(unittest.TestCase):
    def setUp(self):
        d = self.d = tempfile.mkdtemp()
        self.bin, self.log, self.units, self.nft = f"{d}/bin", f"{d}/calls.log", f"{d}/units", f"{d}/nftables"
        self.cgroup, self.proc = f"{d}/cgroup", f"{d}/proc"
        for folder in (self.bin, f"{self.cgroup}/kubepods/besteffort/pod1/c1", f"{self.cgroup}/kubepods/burstable/pod2/c2"):
            os.makedirs(folder)
        open(f"{self.cgroup}/cgroup.controllers", "w").close()
        self.write(f"{self.cgroup}/kubepods/besteffort/pod1/c1/cgroup.procs", "101\n")    # a pod with its own network
        self.write(f"{self.cgroup}/kubepods/burstable/pod2/c2/cgroup.procs", "102\n")     # a host-network pod
        for pid, ns in (("1", "4026531840"), ("101", "4026532001"), ("102", "4026531840")):
            os.makedirs(f"{self.proc}/{pid}/ns")
            os.symlink(f"net:[{ns}]", f"{self.proc}/{pid}/ns/net")
        open(f"{d}/inpath", "w").close()
        self.write(f"{d}/mainns", os.readlink("/proc/self/ns/net") + "\n")
        self.write(f"{d}/nftables.conf", '#include "/etc/nftables/main.nft"\n')
        self.write(f"{d}/nftables.service", f"[Service]\nExecStart=/sbin/nft -f {d}/nftables.conf\n"
                   f"ExecReload=/sbin/nft 'flush ruleset; include \"{d}/nftables.conf\";'\nExecStop=/sbin/nft flush ruleset\n")
        os.makedirs(self.units)
        for daemon in ("containerd", "kubelite"):
            self.write(f"{self.units}/snap.microk8s.daemon-{daemon}.service",
                       f"[Unit]\nAfter=network-online.target\n[Service]\nExecStart=/usr/bin/snap run microk8s.daemon-{daemon}\n")
        self.write(f"{self.bin}/effective.awk", EFFECTIVE_AWK)
        self.write(f"{self.bin}/busctl", FAKE_BUSCTL)
        os.chmod(f"{self.bin}/busctl", 0o755)
        for name, text in (("nft", MD_NFT), ("systemctl", MD_SYSTEMCTL), ("nsenter", MD_NSENTER), ("curl", MD_CURL),
                           ("ip", MD_IP), ("microk8s", "#!/bin/sh\nexit 0\n")):
            with open(f"{self.bin}/{name}", "w") as f:
                f.write(text.format(log=self.log, d=d, units=self.units, bin=self.bin))
            os.chmod(f"{self.bin}/{name}", 0o755)
        self.toml = f"{d}/hb.toml"
        self.config("block_metadata = true")

    def config(self, line):
        self.write(self.toml, f"[k8s]\n{line}\n")

    def write(self, path, text):
        with open(path, "w") as f:
            f.write(text)

    def env(self):
        return {**os.environ, "HB_CONFIG": self.toml, "HB_SYSTEMD_DIR": self.units, "HB_NFT_DIR": self.nft,
                "HB_CGROUP_ROOT": self.cgroup, "HB_PROC": self.proc, "HB_MICROK8S": f"{self.bin}/microk8s",
                "HB_MD_WAIT": "2", "HB_STATE": f"{self.d}/state", "PATH": self.bin + os.pathsep + os.environ["PATH"],
                "http_proxy": "http://127.0.0.1:3128"}

    def tool(self, *args):
        return subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-k8s"), *args], env=self.env(),
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              start_new_session=True)

    def line(self, item="metadata"):
        return next(l for l in self.tool("status").stdout.splitlines() if l.split()[1:2] == [item])

    def calls(self, prog):
        try:
            with open(self.log) as f:
                return [l.strip() for l in f if l.startswith(prog + " ")]
        except OSError:
            return []

    def read(self, path):
        with open(path) as f:
            return f.read()

    def gate(self, daemon):
        return f"{self.units}/snap.microk8s.daemon-{daemon}.service.d/10-hb-metadata.conf"

    def test_pending_then_applied(self):
        self.assertIn("pods can reach the instance metadata service, and with it the instance role", self.line())
        self.assertEqual(self.tool("check").returncode, 1)
        r = self.tool("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        unit = self.read(f"{self.units}/hb-metadata-block.service")
        for want in ("Before=snap.microk8s.daemon-containerd.service snap.microk8s.daemon-kubelite.service",
                     "PartOf=nftables.service snap.microk8s.daemon-kubelite.service",
                     f"ExecStart=/usr/bin/mkdir -p {self.cgroup}/kubepods\nExecStart=/usr/sbin/nft -f {self.nft}/hb-metadata.nft\n",
                     "WantedBy=multi-user.target\n"):
            self.assertIn(want, unit)
        self.assertNotIn("ExecStop", unit)
        rules = self.read(f"{self.nft}/hb-metadata.nft")
        self.assertIn('ip daddr 169.254.169.254 socket cgroupv2 level 1 "kubepods" counter drop', rules)
        self.assertIn("ip6 daddr fd00:ec2::254 counter drop", rules)
        for daemon in ("containerd", "kubelite"):                # fails closed
            gate = self.read(self.gate(daemon))
            self.assertIn("Wants=hb-metadata-block.service\nAfter=hb-metadata-block.service\n", gate)
            self.assertIn("ExecStartPre=/bin/sh -c '/usr/sbin/nft list chain inet hb_metadata output >/dev/null'", gate)
        self.assertIn(f'include "{self.d}/nftables.conf"\ninclude "{self.nft}/hb-metadata.nft"\n',
                      self.read(f"{self.nft}/hb-nftables-service.nft"))
        self.assertIn(f"[Service]\nExecStartPre=/usr/bin/mkdir -p {self.cgroup}/kubepods\n"
                      f"ExecStart=\nExecStart=/usr/sbin/nft -f {self.nft}/hb-nftables-service.nft\n"
                      f"ExecReload=\nExecReload=/usr/sbin/nft -f {self.nft}/hb-nftables-service.nft\nExecStop=\n",
                      self.read(f"{self.units}/nftables.service.d/10-hb-keep-tables.conf"))
        for path in (f"{self.units}/hb-metadata-block.service", f"{self.nft}/hb-metadata.nft", self.gate("kubelite")):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o644, path)
        self.assertEqual(sorted(os.listdir(self.nft)), ["hb-metadata.nft", "hb-nftables-service.nft"])
        self.assertTrue(any(c.startswith(f"nft -c -f {self.nft}/.hb-metadata.") for c in self.calls("nft")))
        sc = self.calls("systemctl")
        for want in ("systemctl daemon-reload", "systemctl enable hb-metadata-block.service",
                     "systemctl restart hb-metadata-block.service"):
            self.assertIn(want, sc)
        self.assertRegex(self.line(), r"containerd and kubelite start only with that in place \(\d+ packets dropped since it was loaded\)")
        self.assertIn("ok    metadata_live  a pod's request to the instance metadata service was just dropped by hb's rule",
                      self.line("metadata_live"))
        self.assertTrue(all(f"--net={self.proc}/101/ns/net" in c for c in self.calls("nsenter")))   # never the host's
        self.assertEqual(self.tool("check").returncode, 0)
        self.tool("apply", "--yes")
        self.assertEqual(self.calls("systemctl").count("systemctl restart hb-metadata-block.service"), 1)

    def test_a_pod_that_reaches_it_fails(self):
        self.tool("apply", "--yes")
        self.write(f"{self.d}/probe", "401")                     # IMDSv2 answering a request without a token
        self.assertIn("a pod reached the instance metadata service (answered HTTP 401", self.line("metadata_live"))
        self.assertEqual(self.tool("check").returncode, 2)

    def test_a_request_stopped_before_hbs_rule_isnt_proof(self):
        self.tool("apply", "--yes")
        os.remove(f"{self.d}/inpath")                            # a network policy, say
        self.assertIn("not confirmed: 1 pods tried", self.line("metadata_live"))   # every pod, the host-network one not
        self.assertEqual(self.tool("check").returncode, 1)
        self.assertFalse([c for c in self.calls("nsenter") if "/102/" in c])

    def test_no_pod_to_try_from(self):
        self.tool("apply", "--yes")
        os.remove(f"{self.cgroup}/kubepods/besteffort/pod1/c1/cgroup.procs")
        self.assertIn("no pod runs here to try from", self.line("metadata_live"))

    def test_nftables_services_file_must_change_nothing(self):
        for text in ("table inet harmless {}; flush ruleset\n",                            # inline
                     f'include "{self.d}/more.nft"\n',                                     # included
                     "table inet own {\n\tchain input { type filter hook input priority 0; accept; }\n}\n"):  # a table of its own
            self.write(f"{self.d}/more.nft", "flush ruleset\n")
            self.write(f"{self.d}/nftables.conf", text)
            self.assertIn("nftables.service's file", self.line())
            self.assertEqual(self.tool("check").returncode, 2, text)
        self.assertFalse(os.path.exists(self.nft))

    def reload(self):
        subprocess.run(["sh", "-c", f"find {self.units} -name '*.conf' > {self.d}/reloaded"])

    def test_what_systemd_will_run_is_checked(self):
        self.tool("apply", "--yes")
        os.remove(f"{self.d}/reloaded")                          # written, but systemd hasn't read them
        self.assertIn("containerd may start without it; kubelite may start without it; nftables.service may flush", self.line())
        self.tool("apply", "--yes")
        self.assertEqual(self.tool("check").returncode, 0)
        # a later drop-in of someone else's puts the flushes back, or takes the gate away
        self.write(f"{self.units}/nftables.service.d/90-local.conf",
                   "[Service]\nExecStop=/sbin/nft flush ruleset\nExecReload=\nExecReload=/sbin/nft flush ruleset\n")
        os.makedirs(f"{self.units}/snap.microk8s.daemon-kubelite.service.d", exist_ok=True)
        self.write(f"{self.units}/snap.microk8s.daemon-kubelite.service.d/90-local.conf", "[Service]\nExecStartPre=\n")
        self.reload()
        self.assertIn("kubelite may start without it; nftables.service may flush every table", self.line())
        self.assertEqual(self.tool("check").returncode, 1)
        # the gate again, but allowed to fail (-): systemd would start kubelite all the same
        self.write(f"{self.units}/snap.microk8s.daemon-kubelite.service.d/90-local.conf",
                   "[Service]\nExecStartPre=\nExecStartPre=-/bin/sh -c '/usr/sbin/nft list chain inet hb_metadata output >/dev/null'\n")
        self.reload()
        self.assertIn("kubelite may start without it", self.line())
        # or quoted wrongly: the same words, but sh runs a bare `nft`, which fails, so kubelite never starts
        self.write(f"{self.units}/snap.microk8s.daemon-kubelite.service.d/90-local.conf",
                   "[Service]\nExecStartPre=\nExecStartPre=/bin/sh -c /usr/sbin/nft list chain inet hb_metadata output >/dev/null\n")
        self.reload()
        self.assertIn("kubelite may start without it", self.line())
        # or run by another program under the same name (@): /bin/true always succeeds
        self.write(f"{self.units}/snap.microk8s.daemon-kubelite.service.d/90-local.conf",
                   "[Service]\nExecStartPre=\nExecStartPre=@/bin/true /bin/sh -c '/usr/sbin/nft list chain inet hb_metadata output >/dev/null'\n")
        self.reload()
        self.assertIn("kubelite may start without it", self.line())
        for name in ("nftables.service.d", "snap.microk8s.daemon-kubelite.service.d"):
            os.remove(f"{self.units}/{name}/90-local.conf")
        os.makedirs(f"{self.units}/hb-metadata-block.service.d")
        self.write(f"{self.units}/hb-metadata-block.service.d/90-local.conf", "[Service]\nExecStartPost=/sbin/nft flush ruleset\n")
        self.reload()
        self.assertIn("hb-metadata-block.service", self.line())

    def test_a_failed_read_is_never_none(self):
        """A flushing ExecStop that systemd has loaded stays a problem when reading it fails: a
        failed or garbled read, or one of the wrong type, is not an empty command list."""
        self.tool("apply", "--yes")
        self.write(f"{self.units}/nftables.service.d/90-local.conf", "[Service]\nExecStop=/usr/sbin/nft flush ruleset\n")
        self.reload()
        self.assertIn("nftables.service may flush every table", self.line())
        for flag in ("busctl-fails-ExecStop", "busctl-loadunit-fails", "busctl-garbage", "busctl-wrong-type"):
            open(f"{self.d}/{flag}", "w").close()
            self.assertIn("nftables.service may flush every table", self.line(), flag)
            self.assertEqual(self.tool("check").returncode, 1, flag)
            os.remove(f"{self.d}/{flag}")
        os.remove(f"{self.units}/nftables.service.d/90-local.conf")
        self.reload()
        self.assertEqual(self.tool("check").returncode, 0)
        open(f"{self.d}/busctl-fails-ExecStartPre", "w").close()    # the gate can't be read: not known to be there
        self.assertIn("containerd may start without it", self.line())
        os.remove(f"{self.d}/busctl-fails-ExecStartPre")
        # the helper itself: any failed step is a failure, never an empty list of commands
        k8s = os.path.join(REPO, "tools", "hb-k8s")
        read = (f'eval "$(sed -n "/^effective_cmds() {{/,/^}}/p" {k8s})"; '
                'effective_cmds nftables.service ExecStop; echo "rc=$?"')
        for flag, rc in (("", "rc=0"), ("busctl-loadunit-fails", "rc=1"), ("busctl-fails-ExecStop", "rc=1"),
                         ("busctl-garbage", "rc=1"), ("busctl-wrong-type", "rc=1")):
            if flag:
                open(f"{self.d}/{flag}", "w").close()
            out = subprocess.run(["bash", "-c", read], env=self.env(), capture_output=True, text=True).stdout
            self.assertEqual(out.strip().splitlines()[-1], rc, (flag, out))
            if flag:
                os.remove(f"{self.d}/{flag}")

    def test_the_probe_ignores_proxies_and_curlrc(self):
        self.tool("apply", "--yes")
        c = self.calls("curl")[-1]
        self.assertTrue(c.startswith("curl -q --noproxy * "), c)
        self.assertRegex(c, r"--local-port 61\d\d\d ")
        self.assertTrue(c.endswith("proxy=none"), c)          # the host's http_proxy left behind

    def test_a_probe_that_couldnt_run_isnt_proof(self):
        self.tool("apply", "--yes")
        open(f"{self.d}/nsenter-fails", "w").close()
        open(f"{self.d}/otherpacket", "w").close()               # another namespace's packet, meanwhile
        self.assertIn("not confirmed: 1 pods tried, none dropped by hb's rule (last: (couldn't try: exit 1))",
                      self.line("metadata_live"))
        os.remove(f"{self.d}/nsenter-fails")
        os.remove(f"{self.d}/otherpacket")
        open(f"{self.d}/noroute", "w").close()
        self.assertIn("no route to it from there", self.line("metadata_live"))
        os.remove(f"{self.d}/noroute")
        open(f"{self.d}/refused", "w").close()                   # a reset from something else
        self.assertIn("refused by something else", self.line("metadata_live"))
        self.assertEqual(self.tool("check").returncode, 1)

    def test_only_this_tries_packets_count(self):
        """The try dropped before hb's chain (another table, say) while another namespace's packet
        from the same port reaches it: that isn't this try's, so nothing is proven."""
        self.tool("apply", "--yes")
        os.remove(f"{self.d}/inpath")
        open(f"{self.d}/otherpacket", "w").close()
        self.assertIn("no answer, but hb's rule didn't see it", self.line("metadata_live"))
        self.assertEqual(self.tool("check").returncode, 1)

    def test_each_tries_counter_is_taken_out(self):
        self.tool("apply", "--yes")
        for _ in range(2):
            self.assertIn("ok    metadata_live", self.line("metadata_live"))
        self.assertEqual(self.read(f"{self.d}/nftstate/temp"), "")
        inserts = [c for c in self.calls("nft") if c.startswith("nft insert rule inet hb_metadata forward ip saddr 10.1.0.5 ")]
        self.assertGreaterEqual(len(inserts), 3)
        self.assertGreater(len({c.split(" sport ")[1].split()[0] for c in inserts}), 1)   # a port picked for each try

    def test_tries_never_overlap(self):
        self.tool("apply", "--yes")
        open(f"{self.d}/slow", "w").close()                      # each try takes 2 s
        start = time.monotonic()
        runs = [subprocess.Popen(["unshare", "-r", os.path.join(REPO, "tools", "hb-k8s"), "status"], env=self.env(),
                                 stdout=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL, start_new_session=True)
                for _ in range(2)]
        outs = [r.communicate(timeout=120)[0] for r in runs]
        self.assertGreaterEqual(time.monotonic() - start, 4)      # one after the other, under the lock
        for out in outs:
            self.assertIn("ok    metadata_live  a pod's request to the instance metadata service was just dropped", out)
        self.assertEqual(self.read(f"{self.d}/nftstate/temp"), "")

    def test_the_wait_is_a_deadline(self):
        self.tool("apply", "--yes")
        os.remove(f"{self.d}/inpath")
        open(f"{self.d}/slow", "w").close()
        env = {**self.env(), "HB_MD_WAIT": "5"}
        start = time.monotonic()
        subprocess.run(["unshare", "-r", os.path.join(REPO, "tools", "hb-k8s"), "apply", "--yes"], env=env,
                       capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL, start_new_session=True)
        took = time.monotonic() - start
        self.assertLess(took, 5 + 6, took)                     # the wait, and status before and after it

    def test_without_nftables_service(self):
        open(f"{self.d}/no-nftables", "w").close()
        self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(f"{self.units}/nftables.service.d"))
        self.assertEqual(self.tool("check").returncode, 0)

    def test_the_pods_cgroup_is_made_when_the_kubelet_hasnt(self):
        shutil.rmtree(f"{self.cgroup}/kubepods")               # kubelite not started yet
        self.assertIn("pods can reach the instance metadata service", self.line())
        self.tool("apply", "--yes")
        self.assertTrue(os.path.isdir(f"{self.cgroup}/kubepods"))
        self.assertIn("ok    metadata", self.line())

    def test_a_flushed_table_is_noticed_and_loaded_again(self):
        self.tool("apply", "--yes")
        shutil.rmtree(f"{self.d}/nftstate")                    # nft flush ruleset, by hand
        self.assertIn("pods can reach the instance metadata service", self.line())
        self.assertEqual(self.tool("check").returncode, 1)
        self.tool("apply", "--yes")
        self.assertEqual(self.tool("check").returncode, 0)

    def test_rules_for_a_cgroup_made_again_are_noticed(self):
        self.tool("apply", "--yes")
        open(f"{self.d}/stale", "w").close()                   # the rules now name the old cgroup's id
        self.assertIn("the loaded rules don't block it all", self.line())
        self.assertEqual(self.tool("check").returncode, 1)
        self.tool("apply", "--yes")
        self.assertEqual(self.tool("check").returncode, 0)

    def test_an_edited_unit_and_a_disabled_one_are_pending(self):
        self.tool("apply", "--yes")
        os.remove(f"{self.d}/enabled-hb-metadata-block.service")
        self.assertIn("not loaded at boot", self.line())
        self.tool("apply", "--yes")
        with open(f"{self.units}/hb-metadata-block.service", "a") as f:
            f.write("ExecStop=/usr/sbin/nft delete table inet hb_metadata\n")
        self.assertIn("hb-metadata-block.service", self.line())
        self.assertEqual(self.tool("check").returncode, 1)

    def test_rules_nft_rejects_never_replace_the_loaded_ones(self):
        self.tool("apply", "--yes")
        with open(f"{self.nft}/hb-metadata.nft", "a") as f:
            f.write("# edited\n")
        open(f"{self.d}/reject", "w").close()
        self.tool("apply", "--yes")
        self.assertIn("# edited", self.read(f"{self.nft}/hb-metadata.nft"))
        self.assertEqual(self.calls("systemctl").count("systemctl restart hb-metadata-block.service"), 1)
        self.assertTrue(os.path.exists(f"{self.d}/nftstate/output"))           # still loaded

    def test_the_systemd_cgroup_driver_is_refused(self):
        os.rename(f"{self.cgroup}/kubepods", f"{self.cgroup}/kubepods.slice")
        self.assertIn("systemd cgroup driver", self.line())
        self.assertEqual(self.tool("check").returncode, 2)
        self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(self.nft))

    def test_refused_without_cgroup_v2(self):
        os.remove(f"{self.cgroup}/cgroup.controllers")
        self.assertIn("needs cgroup v2", self.line())
        self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(self.nft))
        self.assertNotIn("systemctl daemon-reload", self.calls("systemctl"))

    def test_not_managed_by_default(self):
        self.config("")
        self.assertIn("not managed", self.line())
        self.assertIn("not managed", self.line("metadata_live"))
        self.tool("apply", "--yes")
        self.assertFalse(os.path.exists(self.nft))
        self.assertEqual(self.calls("nft"), [])

    @unittest.skipUnless(real_nft_works(), "needs nft in a user and network namespace, and /sys/fs/cgroup/kubepods")
    def test_with_real_nft(self):
        """The real nft, in a network namespace of its own: hb's file loaded as the unit would, a
        file nft rejects leaving the loaded rules as they were, a flush noticed, nftables.service's
        file checked in a scratch namespace (inline and included flushes, a table of its own), and
        nftables.service's load keeping hb's table even when its file flushes the ruleset."""
        for name in ("nft", "nsenter", "curl"):
            os.remove(f"{self.bin}/{name}")
        shutil.rmtree(self.proc)                               # no pods to try from here
        self.cgroup = "/sys/fs/cgroup"                         # nft finds the cgroup there itself
        k8s, d, conf = os.path.join(REPO, "tools", "hb-k8s"), self.d, f"{self.d}/nftables.conf"
        state = f"{k8s} status | grep -E '^(ok|todo|FAIL) +metadata ' | cut -c1-5"
        script = f"""
            {k8s} apply --yes >/dev/null 2>&1; echo applied=$({state})
            sed 's/"kubepods"/"no-such-cgroup"/' {self.nft}/hb-metadata.nft > {d}/bad.nft
            nft -f {d}/bad.nft 2>/dev/null; echo rejected=$? kept=$({state})
            nft delete table inet hb_metadata; echo flushed=$({state}); {k8s} apply --yes >/dev/null 2>&1
            nft add table ip filter; nft add chain ip filter KUBE
            printf 'table inet harmless {{}}; flush ruleset\\n' > {conf}; echo inline=$({state})
            printf 'flush ruleset\\n' > {d}/more.nft; printf 'include "{d}/more.nft"\\n' > {conf}; echo included=$({state})
            printf 'table inet own {{ chain c {{ type filter hook input priority 0; accept; }} }}\\n' > {conf}; echo own=$({state})
            nft list table ip filter >/dev/null 2>&1 && echo "kube table still there"
            printf 'flush ruleset\\n' > {conf}; nft -f {self.nft}/hb-nftables-service.nft
            nft list tables; {k8s} status | grep metadata_live
        """
        r = subprocess.run(["unshare", "-rn", "sh", "-c", script], env=self.env(), capture_output=True, text=True,
                           timeout=180, stdin=subprocess.DEVNULL, start_new_session=True)
        out = r.stdout
        for want in ("applied=ok", "rejected=1 kept=ok", "flushed=todo", "inline=FAIL", "included=FAIL", "own=FAIL",
                     "kube table still there", "todo  metadata_live  no pod runs here"):
            self.assertIn(want, out, out + r.stderr)
        tables = [l for l in out.splitlines() if l.startswith("table ")]
        self.assertEqual(tables, ["table inet hb_metadata"], out)   # the service's flush, and hb's table again with it

    @unittest.skipUnless(real_nft_works() and all(shutil.which(t) for t in ("ip", "nsenter", "curl", "python3")),
                         "needs nft, ip, nsenter, curl and python3 in user and network namespaces")
    def test_the_probe_end_to_end(self):
        """No fakes on the path: a pod's network (10.1.0.5) routed through this namespace to one
        that answers HTTP as 169.254.169.254, real nft, hb's probe and its own counter. Dropped by
        hb: ok. hb's drop taken out: the pod gets an answer, FAIL. Dropped by an earlier chain
        instead: hb's counter for the try stays at 0, so not proven."""
        for name in ("nft", "nsenter", "curl", "ip"):
            os.remove(f"{self.bin}/{name}")
        self.cgroup = "/sys/fs/cgroup"
        pods, fake_proc = f"{self.d}/pods", f"{self.d}/fproc"
        os.makedirs(pods)
        k8s = os.path.join(REPO, "tools", "hb-k8s")
        live = f"{k8s} status | grep -E '^(ok|todo|FAIL) +metadata_live'"
        script = f"""
            unshare -n sleep 120 & POD=$!; unshare -n sleep 120 & IMDS=$!; sleep 0.5
            trap 'kill $POD $IMDS $SRV 2>/dev/null' EXIT
            ip link set lo up; echo 1 > /proc/sys/net/ipv4/ip_forward
            ip link add vpod type veth peer name ceth netns $POD; ip addr add 10.1.0.1/24 dev vpod; ip link set vpod up
            ip link add vimds type veth peer name ieth netns $IMDS; ip addr add 169.254.0.1/16 dev vimds; ip link set vimds up
            nsenter -t $POD -n sh -c 'ip link set lo up; ip addr add 10.1.0.5/24 dev ceth; ip link set ceth up; ip route add default via 10.1.0.1'
            nsenter -t $IMDS -n sh -c 'ip link set lo up; ip addr add 169.254.169.254/16 dev ieth; ip link set ieth up; ip route add 10.1.0.0/24 via 169.254.0.1'
            nsenter -t $IMDS -n python3 -m http.server --bind 169.254.169.254 80 >/dev/null 2>&1 & SRV=$!; sleep 1
            mkdir -p {fake_proc}/1/ns {fake_proc}/$POD/ns; ln -s /proc/$$/ns/net {fake_proc}/1/ns/net; ln -s /proc/$POD/ns/net {fake_proc}/$POD/ns/net
            echo $POD > {pods}/cgroup.procs
            {k8s} apply --yes >/dev/null 2>&1; echo "dropped: $({live})"
            nft list chain inet hb_metadata forward | grep -c 'hb probe' | sed 's/^/left behind: /'
            h=$(nft -a list chain inet hb_metadata forward | grep 'ip daddr 169.254.169.254 counter' | sed -nE 's/.*# handle ([0-9]+)$/\\1/p')
            nft delete rule inet hb_metadata forward handle $h; echo "open: $({live})"
            {k8s} apply --yes >/dev/null 2>&1
            nft add table inet early; nft add chain inet early f '{{ type filter hook forward priority -20; }}'
            nft add rule inet early f ip saddr 10.1.0.5 drop; echo "earlier: $({live})"
        """
        env = {**self.env(), "HB_PROC": fake_proc, "HB_POD_CGROUPS": pods, "HB_MD_WAIT": "8"}
        r = subprocess.run(["unshare", "-rn", "bash", "-c", script], env=env, capture_output=True, text=True,
                           timeout=180, stdin=subprocess.DEVNULL, start_new_session=True)
        out = r.stdout
        for want in ("dropped: ok    metadata_live  a pod's request to the instance metadata service was just dropped by hb's rule",
                     "left behind: 0",
                     "open: FAIL  metadata_live  a pod reached the instance metadata service (answered HTTP 404",
                     "earlier: todo  metadata_live  not confirmed: 1 pods tried, none dropped by hb's rule (last: (no answer, but hb's rule didn't see it))"):
            self.assertIn(want, out, out + r.stderr)

if __name__ == "__main__":
    unittest.main()
