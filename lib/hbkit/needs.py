"""What hb runs on a box: each program, the package it comes in, and whether this box needs it.

  python3 -IB needs.py check   one line, for hb install's needs item: exit 0 when everything hb
                               needs here is installed, 2 when something is missing
  python3 -IB needs.py list    all of it (hb install needs)

Each program is one of three kinds:
  mandatory  hb itself runs it: every tool, hb install, the timers
  needed     a tool runs it once that tool is in use here: set up in hb.toml, or the box has what
             it looks after (a btrfs root, microk8s). Until then it is "needed later", never a
             failure, so a box without WireGuard isn't asked for wireguard-tools
  optional   a tool does something more with it, and works without it
A needed program that the tool's own apply installs (hb wg apply installs wireguard-tools) is
reported as such, not as a failure.

Programs are looked up on a fixed PATH ($HB_NEEDS_PATH, else /usr/local/sbin, /usr/local/bin,
/usr/sbin, /usr/bin, /snap/bin), never the caller's. Package names are dnf's: Fedora's, or Amazon
Linux's where they differ. The settings come from hb's usual hb.toml, or $HB_CONFIG (hb install
passes the checkout's, the one it is about to install).

This file runs on Python 3.9 too: Amazon Linux's /usr/bin/python3 is 3.9, and hb's 3.11 being
missing is one of the things it has to be able to say.
"""
import glob
import os
import re
import sys
import textwrap

NEED_PY = (3, 11)
PATH = os.environ.get("HB_NEEDS_PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin")
ROOT = os.environ.get("HB_NEEDS_ROOT", "")      # tests: a folder standing in for / (os-release, mounts, files)
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
PREFIX = "/opt/hb"                              # where hb install puts hb (and what hb.toml names)
PAM_DIRS = ("/usr/lib64/security", "/usr/lib/security", "/lib64/security", "/lib/security",
            "/usr/lib/x86_64-linux-gnu/security", "/usr/lib/aarch64-linux-gnu/security")


def newest_python(pattern="/usr/bin/python3.*"):
    """The newest executable python3.N with N >= NEED_PY's minor, or None."""
    best = None
    for path in glob.glob(pattern):
        m = re.fullmatch(r"python3\.([0-9]+)", os.path.basename(path))
        if m and int(m.group(1)) >= NEED_PY[1] and os.access(path, os.X_OK):
            if best is None or int(m.group(1)) > best[0]:
                best = (int(m.group(1)), path)
    return best[1] if best else None


def running_python():
    v = os.environ.get("HB_NEEDS_PYTHON")           # tests: the version this pretends to run on
    return tuple(int(x) for x in v.split(".")[:2]) if v else sys.version_info[:2]


# --- the box ------------------------------------------------------------------------

def read(path):
    try:
        with open(ROOT + path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def os_release():
    """(ID, a name to show) from /etc/os-release."""
    text = read("/etc/os-release")
    ident = re.search(r'^ID="?([A-Za-z0-9._-]+)"?\s*$', text, re.M)
    name = re.search(r'^PRETTY_NAME="?([^"\n]+)"?\s*$', text, re.M)
    return (ident.group(1) if ident else ""), (name.group(1) if name else "an unknown system")


def root_fstype():
    kind = ""
    for line in read("/proc/self/mounts").splitlines():
        parts = line.split()
        if len(parts) > 2 and parts[1] == "/":
            kind = parts[2]                         # the last one mounted there is what / is
    return kind


def program(name):
    for d in PATH.split(":"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def pam_module(name):
    for d in PAM_DIRS:
        if os.path.isfile(ROOT + d + "/" + name):
            return d + "/" + name
    return None


def needs_restarting(_name):
    """dnf's needs-restarting: a plugin of dnf5 (Fedora 41 on) or of dnf 4 (Amazon Linux)."""
    for pattern in ("/usr/lib64/dnf5/plugins/needs_restarting*.so", "/usr/lib/dnf5/plugins/needs_restarting*.so",
                    "/usr/lib/python3*/site-packages/dnf-plugins/needs_restarting.py"):
        hits = glob.glob(ROOT + pattern)
        if hits:
            return hits[0][len(ROOT):]
    return None


def python_found(_name):
    """As hbkit.start finds it: the tools start /usr/bin/python3 and go on with the newest
    /usr/bin/python3.N that is 3.11 or newer, never another one on PATH."""
    return newest_python(ROOT + "/usr/bin/python3.*")


# --- when a tool is in use ----------------------------------------------------------

def always(_cfg, _box):
    return ""


def setting(*keys):
    """In use when any of these settings is set (not empty, not false): says which."""
    def when(cfg, _box):
        if cfg is None:
            return None
        for key in keys:
            section, _, name = key.partition(".")
            table = cfg.get(section)
            if isinstance(table, dict) and table.get(name) not in (None, "", [], {}, False):
                return key
        return None
    return when


def both(a, b):
    def when(cfg, box):
        x, y = a(cfg, box), b(cfg, box)
        return None if x is None or y is None else " and ".join(t for t in (x, y) if t)
    return when


def either(*whens):
    def when(cfg, box):
        for w in whens:
            r = w(cfg, box)
            if r is not None:
                return r
        return None
    return when


def btrfs_root(_cfg, box):
    return "/ is btrfs" if box["fstype"] == "btrfs" else None


def has_microk8s(_cfg, box):
    return "microk8s is installed" if box["microk8s"] else None


def md_arrays(_cfg, box):
    return "/etc/mdadm.conf lists arrays" if box["mdadm_conf"] else None


def git_checkout(_cfg, box):
    return "installing from a git checkout" if box["git"] else None


K8S = setting("k8s.nodeport_addresses", "k8s.token_off_namespaces", "k8s.freeze_certs", "k8s.cluster_agent_bind",
              "k8s.keep_restarting", "k8s.linger_root", "k8s.memory_reserved", "k8s.memory_evict_below",
              "k8s.block_metadata")


# --- the table ----------------------------------------------------------------------

MANDATORY, NEEDED, OPTIONAL = "mandatory", "needed", "optional"


class Use:
    def __init__(self, tool, when, kind=NEEDED, why=""):
        self.tool, self.when, self.kind, self.why = tool, when, kind, why


class Need:
    """Programs (or files) that come together, the package that brings them, and who uses them.

    pkg: a dnf package name, or {os id: name, "": the rest}; None where there is no package to name.
    instead: what to do in place of, or besides, installing the package.
    installs: which hb apply installs it, when one does (missing then is no failure).
    Each of the three may also be a function of (settings, os id)."""

    def __init__(self, names, pkg, uses, find=program, label=None, instead=None, installs=None):
        self.names, self.pkg, self.uses, self.find = tuple(names), pkg, uses, find
        self.label, self.instead, self.installs = label, instead, installs


def hb(why):
    return [Use("hb", always, MANDATORY, why)]


COREUTILS = ("base32 basename cat chgrp chmod chown cp cut date df dirname du env fold head id install ln mkdir mktemp mv paste "
             "readlink realpath rm seq sha256sum sleep sort stat tail tee timeout touch tr uname wc").split()

TABLE = [
    Need(["python 3.11+"], {"fedora": "python3", "amzn": "python3.13", "": "python3"}, find=python_found,
         uses=hb("every Python tool; hb runs the newest /usr/bin/python3.N that is 3.11 or newer")),
    Need(["python3"], "python3", hb("the shell tools start their Python helpers with it (hb picks 3.11+ itself)")),
    Need(["bash"], "bash", hb("the shell tools")),
    Need(COREUTILS, "coreutils", hb("everywhere"), label="coreutils"),
    Need(["cmp", "diff"], "diffutils", hb("comparing what is with what should be")),
    Need(["find", "xargs"], "findutils", hb("finding files")),
    Need(["grep"], "grep", hb("everywhere")),
    Need(["sed"], "sed", hb("everywhere")),
    Need(["awk"], "gawk", hb("everywhere")),
    Need(["tar"], "tar", hb("hb install copies the code; backups of what hb removes")),
    Need(["runuser", "flock", "unshare", "findmnt", "lsblk", "nsenter", "mount"], "util-linux",
         hb("hb install (runuser), locks (flock), backups (unshare, findmnt, mount), hb k8s (nsenter)")),
    Need(["pgrep"], "procps-ng", hb("processes")),
    Need(["systemctl", "journalctl", "systemd-run", "systemd-analyze", "loginctl", "busctl", "timedatectl"], "systemd",
         hb("units and timers, revert timers (systemd-run), the journal")),
    Need(["ip", "ss"], "iproute", hb("addresses, routes, listening ports")),
    Need(["getent"], "glibc-common", hb("accounts and groups")),
    Need(["sudo", "visudo"], "sudo", hb("hb runs as root by sudo; hb harden reads and writes sudo's rules")),
    Need(["rpm", "dnf"], {"fedora": "dnf5", "": "dnf"}, hb("hb is for dnf systems: upgrades, health, inventory")),
    Need(["useradd", "usermod", "userdel", "groupadd", "groupdel", "gpasswd", "chpasswd"], "shadow-utils", [
        Use("harden", setting("harden.admins", "harden.remove_accounts"), why="admin accounts, removing accounts"),
        Use("ssh", setting("ssh.keys"), why="the hb-ssh group"),
        Use("breakglass", setting("breakglass.user"), why="the rescue account"),
        Use("rebuild", setting("backup.repo"), why="accounts on a rebuilt box")]),
    Need(["hostname"], "hostname", [Use("backup", setting("backup.repo"), why="the host name the backups go under")]),
    Need(["passwd"], "passwd", [Use("breakglass", setting("breakglass.user"), why="locks the rescue account's password")]),
    Need(["curl"], "curl", [
        Use("install", setting("backup.restic_version"), why="downloads restic's release"),
        Use("k8s", setting("k8s.block_metadata"), why="tries the metadata service from a pod")]),
    Need(["git"], "git-core", [
        Use("install", git_checkout, why="copies the checkout's git-tracked files"),
        Use("clean", setting("clean.project_roots"), why="looks at idle projects")]),
    Need(["openssl"], "openssl", [Use("k8s", setting("k8s.freeze_certs"), why="the frozen certificate's end date")]),
    Need(["sshd"], "openssh-server", [
        Use("ssh", setting("ssh.keys"), why="checks what sshd would do (sshd -T)"),
        Use("fail2ban", setting("fail2ban.enabled"), why="the jail's ports, and whether a key comes before the code"),
        Use("harden", setting("harden.permit_root_login", "harden.x11_forwarding"), why="sshd's settings"),
        Use("breakglass", setting("breakglass.user"), why="the rescue login")]),
    Need(["ssh-keygen"], "openssh", [
        Use("breakglass", setting("breakglass.user"), why="the kit's key"),
        Use("inventory", setting("backup.repo"), why="the authorized keys' fingerprints in the state dump before "
                                                       "each backup; without it they read \"(no keys)\"")]),
    Need(["pam_exec.so"], "pam", find=pam_module, uses=[
        Use("harden", setting("harden.admins"), why="sudo asks for the admins' code"),
        Use("ssh", setting("ssh.codes"), why="the code at login")]),
    Need(["pam_succeed_if.so"], "pam", find=pam_module, uses=[
        Use("harden", setting("harden.admins"), why="the code is asked of the admins only")]),
    Need(["firewall-cmd"], "firewalld", [
        Use("fw", setting("fw.zones"), why="the zones"),
        Use("share", setting("share.user"), why="where the share is open"),
        Use("webshell", setting("webshell.user"), why="where the web shell is open")]),
    Need(["wg", "wg-quick"], "wireguard-tools", [Use("wg", setting("wg.address"), why="the tunnel")],
         installs="hb wg apply"),
    Need(["restic"], lambda cfg, os_id: restic_how(cfg, os_id)[0], installs=lambda cfg, _o: restic_how(cfg, "")[2], uses=[
        Use("backup", setting("backup.repo"), why="the backups"),
        Use("restore", setting("backup.repo"), why="restore drills"),
        Use("breakglass", both(setting("breakglass.user"), setting("backup.repo")), why="the kit's restic key")],
         instead=lambda cfg, os_id: restic_how(cfg, os_id)[1]),
    Need(["btrfs"], "btrfs-progs", [
        Use("backup", both(setting("backup.repo"), btrfs_root), why="backs up from a snapshot of /"),
        Use("snapshot", btrfs_root, why="snapshots of / before risky changes"),
        Use("upgrade", both(setting("upgrade.enabled"), btrfs_root), why="a snapshot before each upgrade"),
        Use("health", btrfs_root, OPTIONAL, why="the filesystem's error counters")]),
    Need(["fail2ban-client"], "fail2ban-server", [Use("fail2ban", setting("fail2ban.enabled"), why="the sshd jail")],
         installs="hb fail2ban apply"),
    Need(["nft"], "nftables", [Use("k8s", setting("k8s.block_metadata"), why="keeps pods off the metadata service")]),
    Need(["iptables-save"], "iptables-nft", [Use("k8s", setting("k8s.nodeport_addresses"), why="NodePort rules")]),
    Need(["smartctl"], "smartmontools", [
        Use("alerts", setting("alerts.smartd"), why="disk alerts"),
        Use("health", always, OPTIONAL, why="disk and NVMe health")], installs="hb alerts apply"),
    # hb runs no mdadm itself: hb alerts points the mdmonitor service, which comes with it, at its hook
    Need(["mdadm"], "mdadm", [Use("alerts", both(setting("alerts.mdadm"), md_arrays), why="RAID alerts (mdmonitor)")]),
    Need(["grubby"], "grubby", [
        Use("upgrade", setting("upgrade.enabled"), why="which kernel boots next"),
        Use("health", always, why="whether a reboot is due; without it, a warning on every run")]),
    Need(["dnf needs-restarting"], {"fedora": "dnf5-plugins", "": "dnf-plugins-core"}, find=needs_restarting, uses=[
        Use("upgrade", setting("upgrade.enabled"), why="whether a reboot is needed"),
        Use("health", always, why="whether a reboot is needed; without it, a warning on every run")]),
    Need(["docker"], {"fedora": "moby-engine", "": "docker"}, [
        Use("health", setting("health.containers", "health.asterisk_container"), why="the containers"),
        Use("clean", setting("clean.docker"), why="old images and containers")]),
    Need(["snap"], {"amzn": None, "": "snapd"}, [
        Use("k8s", has_microk8s, why="restarts microk8s's services"),
        Use("upgrade", setting("upgrade.snaps"), why="holds and refreshes snaps")],
         instead={"amzn": "not in Amazon Linux's repositories: install snapd as its project describes", "": ""}),
    Need(["microk8s"], None, find=lambda _n: hb_file("/snap/bin/microk8s"), uses=[
        Use("k8s", K8S, why="the cluster's settings"),
        Use("dump", setting("backup.dumps"), why="database dumps from pods"),
        Use("webshell", setting("webshell.host"), why="the web shell's ingress")],
         instead="snap install microk8s --classic"),
    Need(["testparm", "pdbedit", "smbpasswd"], "samba", [Use("share", setting("share.user"), why="the shares")],
         installs="hb share apply"),
    Need(["tmux"], "tmux", [Use("webshell", setting("webshell.user"), why="the shell's session")]),
    Need(["qrencode"], "qrencode", [Use("totp", always, OPTIONAL, why="a QR code at enrol, besides the key")]),
    Need(["make"], "make", [Use("clean", setting("clean.project_roots"), OPTIONAL, why="make clean in idle projects")]),
]


def restic_how(cfg, os_id):
    """(the package, or None; what to do instead; which hb apply installs it, or None)."""
    backup = (cfg or {}).get("backup")
    v = backup.get("restic_version") if isinstance(backup, dict) else None
    if v:
        return None, f"restic {v} to /usr/local/bin (backup.restic_version)", "hb install apply"
    if os_id == "amzn":
        return None, ("not in Amazon Linux's repositories: set backup.restic_version, and hb install apply "
                      "fetches restic's own release"), None
    return "restic", "", None


def hb_file(name):
    """A program by its path; one under /opt/hb may be in the copy about to be installed instead."""
    for p in [ROOT + name] + ([REPO + name[len(PREFIX):]] if name.startswith(PREFIX + "/") else []):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def sms_needs(cfg):
    """The SMS commands in hb.toml: whatever they run has to be there."""
    out = []
    for key in ("sms_command", "sms_fallback"):
        notify = (cfg or {}).get("notify")
        cmd = notify.get(key) if isinstance(notify, dict) else None
        if isinstance(cmd, list) and cmd:
            name = str(cmd[0])
            find = hb_file if name.startswith("/") else program
            out.append(Need([name], None, [Use("notify", setting("notify." + key), why="texts the owner")],
                            find=find, label=f"notify.{key}: {name}", instead="the SMS command in hb.toml"))
    return out


# --- assessing ----------------------------------------------------------------------

def pick(value, os_id, cfg):
    if callable(value):
        return value(cfg, os_id)
    if isinstance(value, dict):
        return value.get(os_id, value.get(""))
    return value


class Row:
    def __init__(self, need, found, missing, kind, uses, pkg, instead, installs):
        self.need, self.found, self.missing, self.kind = need, found, missing, kind
        self.uses, self.pkg, self.instead, self.installs = uses, pkg, instead, installs

    def failing(self):
        """Missing, needed here, and nothing in hb will install it."""
        return bool(self.missing) and self.kind in (MANDATORY, NEEDED) and not self.installs

    def what(self):
        if self.need.label and len(self.need.names) == 1:
            return self.need.label
        if self.need.label and not self.missing:
            return f"{self.need.label} ({len(self.need.names)} programs)"
        if self.need.label:
            return f"{self.need.label}: {' '.join(self.missing)}"
        return " ".join(self.need.names)

    def tools(self):
        """mandatory, or the tools that need it here."""
        if self.kind == MANDATORY:
            return MANDATORY
        return ", ".join(dict.fromkeys(f"hb {u.tool}" for u, _ in self.uses))

    def missing_text(self):
        return self.what() if self.need.label else " ".join(self.missing)

    def why(self):
        return "; ".join(f"hb {u.tool}" + (f" ({r})" if r else "") + (f": {u.why}" if u.why else "")
                         for u, r in self.uses)


def assess(cfg, box):
    rows = []
    for need in TABLE + sms_needs(cfg):
        found = {n: need.find(n) for n in need.names}
        missing = [n for n in need.names if not found[n]]
        on = [(u, u.when(cfg, box)) for u in need.uses]
        on_needed = [(u, r) for u, r in on if r is not None and u.kind in (MANDATORY, NEEDED)]
        on_optional = [(u, r) for u, r in on if r is not None and u.kind == OPTIONAL]
        if any(u.kind == MANDATORY for u in need.uses):
            kind = MANDATORY
        elif on_needed:
            kind = NEEDED
        elif on_optional:       # what a tool here does more with it says more than a tool not set up
            kind = OPTIONAL
        elif any(u.kind == NEEDED for u in need.uses):
            kind = "later"
        else:
            kind = OPTIONAL
        if kind in (MANDATORY, NEEDED):
            shown = on_needed
        elif kind == "later":
            shown = [(u, None) for u in need.uses if u.kind == NEEDED]
        else:
            shown = on_optional or [(u, None) for u in need.uses]
        # which apply installs it is said only where that tool needs it (now or once set up)
        installs = pick(need.installs, box["os"], cfg) if kind in (NEEDED, "later") else None
        rows.append(Row(need, found, missing, kind, shown, pick(need.pkg, box["os"], cfg),
                        pick(need.instead, box["os"], cfg), installs))
    return rows


def install_line(rows):
    pkgs = sorted({r.pkg for r in rows if r.pkg})
    other = [f"{r.what()}: {r.instead}" for r in rows if not r.pkg and r.instead]
    out = [f"dnf install -y {' '.join(pkgs)}"] if pkgs else []
    return "; ".join(out + other)


def load_box():
    os_id, os_name = os_release()
    return {"os": os_id, "os_name": os_name, "fstype": root_fstype(),
            "microk8s": hb_file("/snap/bin/microk8s") is not None, "git": os.environ.get("HB_NEEDS_GIT") == "1",
            "mdadm_conf": bool(re.search(r"^\s*ARRAY\b", read("/etc/mdadm.conf"), re.M))}


def load_settings():
    """(the settings, where from, None) or (None, None, why they can't be read)."""
    if running_python() < NEED_PY:
        return None, None, f"hb.toml unread: that takes Python {NEED_PY[0]}.{NEED_PY[1]}"
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    try:
        from hbkit import config
        return config.load(), config.path() or "defaults only, no hb.toml", None
    except Exception as e:   # noqa: BLE001 - a broken hb.toml is hb config's to report; the list still shows
        return None, None, f"hb.toml unread ({type(e).__name__}: {e})"


def installs_text(rows):
    return ", ".join(f"{r.missing_text()} ({r.installs})" for r in rows)


def do_check(rows, note):
    bad = [r for r in rows if r.failing()]
    soon = [r for r in rows if r.missing and r.kind == NEEDED and r.installs]
    opt = [r for r in rows if r.missing and r.kind == OPTIONAL]
    tail = (f"; hb installs when applied: {installs_text(soon)}" if soon else "") \
        + (f"; {note}" if note else "") + "; the whole list: hb install needs"
    if bad:
        what = "; ".join(f"{r.missing_text()} ({r.tools()})" for r in bad)
        print(f"missing: {what}. Install: {install_line(bad)}{tail}")
        return 2
    n = sum(len(r.need.names) for r in rows if r.kind in (MANDATORY, NEEDED))
    out = f"everything hb needs here is installed ({n} programs)"
    if opt:
        out += "; optional, not installed: " + ", ".join(f"{r.missing_text()} ({r.pkg or r.instead})" for r in opt)
    print(out + tail)
    return 0


SECTIONS = ((MANDATORY, "mandatory: hb itself"),
            (NEEDED, "needed: by what hb does here"),
            ("later", "needed later: once the tool named is set up (nothing here uses them yet)"),
            (OPTIONAL, "optional: a tool does more with them"))


def do_list(rows, box, source, note):
    print(f"What hb runs on {box['os_name']}, and the dnf package each comes in.")
    print(f"Settings: {source or note}")
    for kind, title in SECTIONS:
        mine = [r for r in rows if r.kind == kind]
        if not mine:
            continue
        print(f"\n{title}")
        for r in mine:
            print(f"  {'MISSING' if r.missing else 'ok':<8} {r.pkg or '-':<17} {r.what()}")
            if kind != MANDATORY or r.missing:
                why = "; ".join(x for x in (r.uses[0][0].why if kind == MANDATORY else r.why(), r.instead,
                                             f"{r.installs} installs it" if r.installs else "") if x)
                for line in textwrap.wrap(why, 72):
                    print(f"{'':29}{line}")
    bad = [r for r in rows if r.failing()]
    soon = [r for r in rows if r.missing and r.kind == NEEDED and r.installs]
    later = [r for r in rows if r.missing and r.kind == "later"]
    opt = [r for r in rows if r.missing and r.kind == OPTIONAL]
    print(f"\nmissing, needed here: {install_line(bad) if bad else 'nothing'}")
    if soon:
        print(f"hb installs these itself when you apply the tool: {installs_text(soon)}")
    if later:
        print(f"for later, when you set those tools up: {install_line(later)}")
    if opt:
        print(f"optional: {install_line(opt)}")
    return 2 if bad else 0


def main(argv):
    if len(argv) != 2 or argv[1] not in ("check", "list"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cfg, source, note = load_settings()
    box = load_box()
    rows = assess(cfg, box)
    return do_check(rows, note) if argv[1] == "check" else do_list(rows, box, source, note)


if __name__ == "__main__":
    if sys.version_info < NEED_PY and not os.environ.get("HB_NEEDS_PYTHON"):
        _py = newest_python()
        if _py:     # as hbkit.start does, but without one this still runs, to say so
            os.execv(_py, [_py, "-I", "-B", os.path.abspath(sys.argv[0])] + sys.argv[1:])
    try:
        sys.exit(main(sys.argv))
    except Exception as e:  # noqa: BLE001 - one line for hb install's status, never a traceback
        print(f"needs.py failed: {type(e).__name__}: {e}")
        sys.exit(2)
