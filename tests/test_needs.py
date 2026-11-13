"""lib/hbkit/needs.py: what hb runs, the package each comes in, and what this box needs."""
import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from tools import REPO  # noqa: E402

sys.path.insert(0, os.path.join(REPO, "lib"))
from hbkit import needs  # noqa: E402

NEEDS = os.path.join(REPO, "lib", "hbkit", "needs.py")
AMZN = 'NAME="Amazon Linux"\nID="amzn"\nPRETTY_NAME="Amazon Linux 2023.9"\n'
FEDORA = 'NAME="Fedora Linux"\nID=fedora\nPRETTY_NAME="Fedora Linux 44"\n'


def write(path, text="", mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


class NeedsTest(unittest.TestCase):
    """A stand-in / (os-release, mounts, PAM modules, dnf's plugin) and every program, as stubs."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.root, self.bin, self.cfg = f"{self.d}/root", f"{self.d}/bin", f"{self.d}/hb.toml"
        write(f"{self.root}/etc/os-release", AMZN)
        self.fs("xfs")
        for m in ("pam_exec.so", "pam_succeed_if.so"):
            write(f"{self.root}/usr/lib64/security/{m}")
        write(f"{self.root}/usr/lib/python3.9/site-packages/dnf-plugins/needs_restarting.py")
        write(f"{self.root}/usr/bin/python3.13", "#!/bin/sh\n", 0o755)
        write(f"{self.root}/snap/bin/microk8s", "#!/bin/sh\n", 0o755)
        for need in needs.TABLE:
            if need.find is needs.program:
                for name in need.names:
                    write(f"{self.bin}/{name}", "#!/bin/sh\n", 0o755)
        self.settings("")

    def fs(self, kind):
        # what is mounted on / last is what / is (an early rootfs line comes first on some systems)
        write(f"{self.root}/proc/self/mounts", f"rootfs / rootfs rw 0 0\nproc /proc proc rw 0 0\n/dev/nvme0n1p1 / {kind} rw 0 0\n")

    def settings(self, text):
        write(self.cfg, text)

    def gone(self, *names):
        for n in names:
            os.unlink(f"{self.bin}/{n}")

    def run_needs(self, verb, **env):
        e = {k: v for k, v in os.environ.items() if not k.startswith("HB_")}
        e.update(HB_NEEDS_ROOT=self.root, HB_NEEDS_PATH=self.bin, HB_CONFIG=self.cfg, **env)
        p = subprocess.run([sys.executable, "-IB", NEEDS, verb], env=e, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.stderr, "")
        return p.returncode, p.stdout

    def section(self, out, title):
        """The lines of the list's section that starts with title."""
        m = re.search(rf"^{re.escape(title)}.*?\n(.*?)(?:\n\n|\Z)", out, re.M | re.S)
        self.assertIsNotNone(m, out)
        return m.group(1)

    def test_everything_there_is_ok(self):
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"^everything hb needs here is installed \(\d+ programs\); the whole list: hb install needs")

    def test_a_mandatory_program_missing_fails(self):
        self.gone("visudo")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: visudo (mandatory). Install: dnf install -y sudo", out)
        rc, out = self.run_needs("list")
        self.assertEqual(rc, 2)
        self.assertIn("  MISSING  sudo              sudo visudo", self.section(out, "mandatory"))
        self.assertIn("missing, needed here: dnf install -y sudo", out)

    def test_coreutils_are_named_one_by_one(self):
        self.gone("seq", "base32")
        rc, out = self.run_needs("check")
        self.assertIn("missing: coreutils: base32 seq (mandatory)", out)

    def test_a_tool_not_set_up_is_needed_later_not_a_failure(self):
        self.gone("wg", "wg-quick")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 0, out)
        rc, out = self.run_needs("list")
        self.assertEqual(rc, 0)
        later = self.section(out, "needed later")
        self.assertIn("  MISSING  wireguard-tools   wg wg-quick", later)
        self.assertIn("hb wg: the tunnel; hb wg apply installs it", later)
        self.assertIn("for later, when you set those tools up: dnf install -y wireguard-tools", out)
        self.assertIn("missing, needed here: nothing", out)

    def test_a_tool_set_up_needs_it(self):
        self.settings('[fw.zones.public]\nservices = ["ssh"]\n')
        self.gone("firewall-cmd")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: firewall-cmd (hb fw). Install: dnf install -y firewalld", out)
        rc, out = self.run_needs("list")
        self.assertIn("  MISSING  firewalld         firewall-cmd", self.section(out, "needed: by what hb does here"))

    def test_what_hb_installs_itself_is_said_not_failed(self):
        # Fable review 1: hb install apply, then hb wg apply (which installs wireguard-tools), is the
        # usual order; the first must not end "broken: needs"
        self.settings('[wg]\naddress = "10.0.0.1/24"\n[backup]\nrepo = "s3:x"\nrestic_version = "0.19.1"\n')
        self.gone("wg", "wg-quick", "restic")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 0, out)
        self.assertIn("; hb installs when applied: wg wg-quick (hb wg apply), restic (hb install apply);", out)
        rc, out = self.run_needs("list")
        self.assertIn("  MISSING  wireguard-tools   wg wg-quick", self.section(out, "needed: by what hb does here"))
        self.assertIn("missing, needed here: nothing", out)
        self.assertIn("hb installs these itself when you apply the tool: wg wg-quick (hb wg apply), restic "
                      "(hb install apply)", out)
        self.gone("visudo")                          # with something else missing, they're still not counted
        rc, out = self.run_needs("check")
        self.assertIn("missing: visudo (mandatory). Install: dnf install -y sudo; hb installs when applied: wg", out)

    def test_hb_share_is_set_up_by_its_user(self):
        # Fable review 5: hb share is managed once share.user is set, and never makes the account
        self.settings('[share]\nuser = "alice"\n')
        self.gone("firewall-cmd", "testparm", "useradd")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: firewall-cmd (hb share). Install: dnf install -y firewalld; "
                      "hb installs when applied: testparm (hb share apply)", out)
        self.assertNotIn("useradd", out)

    def test_optional_missing_is_said_not_failed(self):
        self.gone("qrencode")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 0, out)
        self.assertIn("; optional, not installed: qrencode (qrencode);", out)
        rc, out = self.run_needs("list")
        self.assertIn("  MISSING  qrencode          qrencode", self.section(out, "optional"))
        self.assertIn("optional: dnf install -y qrencode", out)

    def test_packages_are_named_as_each_system_names_them(self):
        self.settings('[health]\ncontainers = ["db"]\n[backup]\nrepo = "s3:x"\n')
        self.gone("docker", "restic")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2)
        self.assertIn("Install: dnf install -y docker; restic: not in Amazon Linux's repositories: set "
                      "backup.restic_version, and hb install apply fetches restic's own release", out)
        write(f"{self.root}/etc/os-release", FEDORA)
        rc, out = self.run_needs("check")
        self.assertIn("Install: dnf install -y moby-engine restic;", out)
        self.settings('[health]\ncontainers = ["db"]\n[backup]\nrepo = "s3:x"\nrestic_version = "0.19.1"\n')
        rc, out = self.run_needs("check")              # a first install: hb install's restic item fetches it
        self.assertIn("missing: docker (hb health). Install: dnf install -y moby-engine; hb installs when applied: "
                      "restic (hb install apply);", out)

    def test_the_code_gate_needs_its_pam_modules(self):
        os.unlink(f"{self.root}/usr/lib64/security/pam_succeed_if.so")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 0, out)                 # no admins: needed later
        self.settings('[harden]\nadmins = ["alice"]\n')
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: pam_succeed_if.so (hb harden). Install: dnf install -y pam", out)
        write(f"{self.root}/lib/security/pam_succeed_if.so")     # another system's folder counts too
        self.assertEqual(self.run_needs("check")[0], 0)

    def test_btrfs_only_on_a_btrfs_root(self):
        self.gone("btrfs")
        self.assertEqual(self.run_needs("check")[0], 0)
        self.fs("btrfs")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: btrfs (hb snapshot). Install: dnf install -y btrfs-progs", out)   # Fable review 8
        self.settings('[backup]\nrepo = "s3:x"\n')
        self.assertIn("missing: btrfs (hb backup, hb snapshot)", self.run_needs("check")[1])

    def test_dnf_needs_restarting_as_dnf4_or_dnf5_has_it(self):
        self.settings("[upgrade]\nenabled = true\n")
        self.assertEqual(self.run_needs("check")[0], 0)
        os.unlink(f"{self.root}/usr/lib/python3.9/site-packages/dnf-plugins/needs_restarting.py")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: dnf needs-restarting (hb upgrade, hb health). Install: dnf install -y dnf-plugins-core",
                      out)
        write(f"{self.root}/etc/os-release", FEDORA)
        self.assertIn("dnf install -y dnf5-plugins", self.run_needs("check")[1])
        write(f"{self.root}/usr/lib64/dnf5/plugins/needs_restarting_cmd_plugin.so")
        self.assertEqual(self.run_needs("check")[0], 0)

    def test_the_sms_command_has_to_be_there(self):
        self.settings('[notify]\nsms_command = ["/opt/sms/send", "--to", "me"]\nsms_fallback = ["sms-backup"]\n')
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: notify.sms_command: /opt/sms/send (hb notify); notify.sms_fallback: sms-backup "
                      "(hb notify)", out)
        write(f"{self.root}/opt/sms/send", "#!/bin/sh\n", 0o755)
        write(f"{self.bin}/sms-backup", "#!/bin/sh\n", 0o755)
        self.assertEqual(self.run_needs("check")[0], 0)
        # hb's own hook, before hb install has put it in /opt/hb: the copy about to be installed has it
        self.settings('[notify]\nsms_command = ["/opt/hb/hooks/sms-supervoip", "--to", "me"]\n')
        self.assertEqual(self.run_needs("check")[0], 0)
        self.settings('[notify]\nsms_command = ["/opt/hb/hooks/no-such-hook"]\n')
        self.assertEqual(self.run_needs("check")[0], 2)

    def test_without_python_311_it_still_says_so(self):
        # Amazon Linux's python3 is 3.9: this file runs there, reads no hb.toml, and names the package
        self.settings('[fw.zones.public]\nservices = ["ssh"]\n')
        self.gone("firewall-cmd")
        os.unlink(f"{self.root}/usr/bin/python3.13")
        rc, out = self.run_needs("check", HB_NEEDS_PYTHON="3.9")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: python 3.11+ (mandatory). Install: dnf install -y python3.13; "
                      "hb.toml unread: that takes Python 3.11;", out)
        self.assertNotIn("firewall", out)            # settings unread: no tool counts as set up
        write(f"{self.root}/usr/bin/python3.13", "#!/bin/sh\n", 0o755)
        rc, out = self.run_needs("check", HB_NEEDS_PYTHON="3.9")
        self.assertNotIn("python", out)

    def test_python_is_what_the_tools_start(self):
        # Fable review 12: the tools start /usr/bin/python3 and go on only to /usr/bin/python3.N; the
        # interpreter running this check (here 3.11 or newer, from anywhere) proves nothing
        os.unlink(f"{self.root}/usr/bin/python3.13")
        write(f"{self.root}/usr/bin/python3.10", "#!/bin/sh\n", 0o755)
        rc, out = self.run_needs("check")
        self.assertIn("missing: python 3.11+ (mandatory)", out)

    def test_microk8s_where_the_tools_run_it(self):
        # Fable review 12: every tool runs /snap/bin/microk8s, not one found on PATH
        self.settings('[k8s]\nmemory_reserved = "2Gi"\n')
        os.unlink(f"{self.root}/snap/bin/microk8s")
        write(f"{self.bin}/microk8s", "#!/bin/sh\n", 0o755)
        self.assertIn("missing: microk8s (hb k8s)", self.run_needs("check")[1])

    def test_the_inventory_needs_ssh_keygen_before_backups(self):
        # Codex review 2: without it the state dump says "(no keys)" for every authorized_keys file
        self.gone("ssh-keygen")
        self.assertEqual(self.run_needs("check")[0], 0)
        self.settings('[backup]\nrepo = "s3:x"\n')
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: ssh-keygen (hb inventory). Install: dnf install -y openssh", out)

    def test_an_optional_use_here_beats_a_tool_not_set_up(self):
        # Codex review 2: smartctl without alerts.smartd is hb health's (optional), not "needed later",
        # and hb alerts apply installs nothing then
        self.gone("smartctl")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 0, out)
        self.assertIn("; optional, not installed: smartctl (smartmontools);", out)
        rc, out = self.run_needs("list")
        opt = self.section(out, "optional")
        self.assertIn("  MISSING  smartmontools     smartctl", opt)
        self.assertIn("hb health: disk and NVMe health", opt)
        self.assertNotIn("installs it", opt)
        self.settings("[alerts]\nsmartd = true\n")
        self.assertIn("hb installs when applied: smartctl (hb alerts apply)", self.run_needs("check")[1])

    def test_health_warns_without_grubby(self):
        # Fable review 11: hb health's reboot check warns on every run without it
        self.gone("grubby")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: grubby (hb health). Install: dnf install -y grubby", out)

    def test_mdadm_only_with_arrays(self):
        # Fable review 7: hb alerts runs no mdadm; mdmonitor (from the package) matters once there are arrays
        self.settings("[alerts]\nmdadm = true\n")
        self.gone("mdadm")
        self.assertEqual(self.run_needs("check")[0], 0)
        write(f"{self.root}/etc/mdadm.conf", "MAILADDR root\nARRAY /dev/md0 metadata=1.2 UUID=x\n")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: mdadm (hb alerts). Install: dnf install -y mdadm", out)

    def test_odd_settings_or_a_crash_give_one_line(self):
        # Fable review 9: never a traceback (hb install would show it as "todo")
        self.settings("notify = 3\nbackup = 4\n")
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 0, out)
        rc, out = self.run_needs("check", HB_NEEDS_PYTHON="x")
        self.assertEqual((rc, out.strip()), (2, "needs.py failed: ValueError: invalid literal for int() with base 10: 'x'"))

    def test_a_broken_hb_toml_still_gets_the_list(self):
        self.settings("[wg\n")
        rc, out = self.run_needs("list")
        self.assertEqual(rc, 0, out)
        self.assertIn("Settings: hb.toml unread (TOMLDecodeError", out)
        self.assertIn("  ok       sudo              sudo visudo", out)

    def test_git_when_installing_from_a_git_checkout(self):
        self.gone("git")
        self.assertEqual(self.run_needs("check")[0], 0)
        rc, out = self.run_needs("check", HB_NEEDS_GIT="1")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: git (hb install). Install: dnf install -y git-core", out)

    def test_microk8s_is_needed_once_hb_k8s_is_set_up(self):
        os.unlink(f"{self.root}/snap/bin/microk8s")
        self.gone("snap")
        self.assertEqual(self.run_needs("check")[0], 0)
        self.settings('[k8s]\nmemory_reserved = "2Gi"\n')
        rc, out = self.run_needs("check")
        self.assertEqual(rc, 2, out)
        self.assertIn("missing: microk8s (hb k8s). Install: microk8s: snap install microk8s --classic", out)
        rc, out = self.run_needs("list")
        self.assertIn("hb k8s (k8s.memory_reserved): the cluster's settings", out)

    def test_usage(self):
        p = subprocess.run([sys.executable, "-IB", NEEDS], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("needs.py check", p.stderr)


# Words the scan below finds in command position that aren't programs hb runs: hb's own
# commands, and arguments that happen to be programs' names (dnf's needs-restarting subcommand).
NOT_PROGRAMS = {"hb", "needs-restarting"}
# bash's own commands, which are never looked up on PATH
SHELL = set("""if then else elif fi for while until do done case esac in function return local export declare
readonly set unset shift break continue exit eval exec source trap wait read echo printf cd pwd test true false
command type hash mapfile readarray shopt umask kill builtin time let""".split())
# A program that runs the next word: the pattern takes the wrapper and its options.
WRAPPERS = {
    "timeout": r"timeout(?:\s+-\S+)*\s+\S+", "runuser": r"runuser\s+-u\s+\S+\s+--",
    "nsenter": r"nsenter(?:\s+-\S+)*\s+--", "unshare": r"unshare(?:\s+-\S+)*\s+--", "xargs": r"xargs(?:\s+-\S+)*",
    "setsid": r"setsid", "nice": r"nice(?:\s+-n\s*\S+)?", "ionice": r"ionice(?:\s+-c\s*\S+)*",
    "env": r"env(?:\s+-\S+)*(?:\s+\w+=\S*)*", "sudo": r"sudo(?:\s+-[A-Za-z]+(?:\s+[^-\s]\S*)?)*",
    "command": r"command\s+-v", "exec": r"exec", "time": r"time", "nohup": r"nohup"}
START = re.compile(r"(?:^|[|;&(`{!]|\$\(|\b(?:then|do|else|elif|if|while|until)\b)")
WORD = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_.+-]*)")
VALUE = re.compile(r"\+?=(?:\(\S*\)|\$\([^)]*\)|\S*)")
ARRAY = re.compile(r"(\b[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=)\(([^()]*)\)")   # X=(a b c), on one line or more: data
ARRAY_HEAD = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=\(\s*([^\s()\"'$]+)")          # X=(prog ...): the program
ARRAY_WORDS = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\[[@*]\]\}")                 # ${X[@]}: X's words
ARRAY_RUN = re.compile(r"\s*\"?\s*@([A-Za-z_][A-Za-z0-9_]*)\b")                       # code_only's mark for it
# Python calls that run a program, and what a program's name looks like.
HELPERS = {"run", "run_read", "sh", "stream", "Popen", "call", "check_call", "check_output", "run_in",
           "execv", "execvp", "execvpe"}
PROGRAM = re.compile(r"[a-z][a-z0-9_.+-]*|/(?:usr/)?s?bin/[a-z][a-z0-9_.+-]*|/snap/bin/[a-z0-9]+")
PY_PATH = re.compile(r"\"(/(?:usr/)?s?bin/[a-z][a-z0-9_.+-]*|/snap/bin/[a-z0-9]+)\"")


def on_path():
    names = set()
    for d in os.get_exec_path():
        try:
            names |= set(os.listdir(d))
        except OSError:
            pass
    return names


def blank(text):
    return re.sub(r"[^\n]", " ", text)


def array_mark(m):
    """${X[@]} as " @X" and spaces, as long: no "{" to read as a group, blanks where its text was."""
    return (" @" + m.group(1)).ljust(len(m.group()))


def code_only(text):
    """A bash file with what doesn't run blanked out, newlines kept: comments, heredocs, text in
    quotes. What does run stays: $(...) inside double quotes, and the body of bash -c '...'."""
    lines, kept, end = text.split("\n"), [], None
    for line in lines:                               # heredoc bodies are text
        if end is not None:
            kept.append("")
            end = None if line.strip() == end else end
            continue
        m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", line)
        end = m.group(1) if m and not line.lstrip().startswith("#") else None
        kept.append(line)
    text, out, i, stack = "\n".join(kept), [], 0, [["code", 0]]
    while i < len(text):
        c, mode = text[i], stack[-1]
        if mode[0] == "dq":
            if c == "\\":
                out.append("  "[: len(text[i:i + 2])]); i += 2; continue
            if c == '"':
                stack.pop(); out.append('"')
            elif text.startswith("$(", i):
                stack.append(["code", 0]); out.append("$("); i += 2; continue
            elif ARRAY_WORDS.match(text, i):         # "${X[@]}": X's words, maybe a command
                out.append(array_mark(ARRAY_WORDS.match(text, i))); i += len(out[-1]); continue
            else:
                out.append(blank(c))
            i += 1
            continue
        if c == "\\":
            out.append(text[i:i + 2]); i += 2; continue
        if ARRAY_WORDS.match(text, i):
            out.append(array_mark(ARRAY_WORDS.match(text, i))); i += len(out[-1]); continue
        if c == "#" and (i == 0 or text[i - 1] in " \t\n;") and not text.startswith("#!", i) or \
                (c == "#" and text.startswith("#!", i) and i == 0):
            j = text.find("\n", i)
            j = len(text) if j < 0 else j
            out.append(blank(text[i:j])); i = j; continue
        if c == "'":
            j = text.find("'", i + 1)
            j = len(text) if j < 0 else j
            body = text[i + 1:j]
            runs = re.search(r"\b(?:bash|sh)\s+-c\s*$", text[max(0, i - 40):i])
            # the quotes stay, so a quoted command ("$X" sub) still stands where a command would
            out.append(" " + code_only(body) + " " if runs else "'" + blank(body) + "'"); i = j + 1; continue
        if c == '"':
            stack.append(["dq", 0]); out.append('"'); i += 1; continue
        if len(stack) > 1:                           # inside "$(...)": its parentheses
            if c == "(":
                mode[1] += 1
            elif c == ")":
                if mode[1] == 0:
                    stack.pop(); out.append(")"); i += 1; continue
                mode[1] -= 1
        out.append(c)
        i += 1
    return "".join(out)


def shell_code(text):
    """Code lines, with case labels and array values (X=(a b c), on one line or several) taken out."""
    code = ARRAY.sub(lambda m: m.group(1) + "(" + re.sub(r"[^\n]", "", m.group(2)) + ")", code_only(text))
    return [re.sub(r"^\s*[^\s()]+\)(?=\s|$)", "", line) for line in code.split("\n")]


def shell_arrays(text):
    """{array: the programs it starts with}, for an array run as "${X[@]}"."""
    arrays = {}
    for m in ARRAY_HEAD.finditer(code_only(text)):
        arrays.setdefault(m.group(1), set()).add(os.path.basename(m.group(2)))
    return arrays


def shell_commands(line, arrays=None):
    found = []
    for m in START.finditer(line):
        i = m.end()
        while True:
            a = ARRAY_RUN.match(line, i)
            if a:                                    # "${X[@]}" runs the program X starts with
                found.extend(sorted((arrays or {}).get(a.group(1), ())))
                break
            w = WORD.match(line, i)
            if not w:
                break
            word, j = w.group(1), w.end()
            if line.startswith("[", j):              # name[key]=value
                k = line.find("]", j)
                j = k + 1 if k > 0 else j
            if line.startswith("=", j) or line.startswith("+=", j):    # VAR=value: a command may follow
                i = VALUE.match(line, j).end()
                continue
            found.append(word)
            wrap = WRAPPERS.get(word) and re.compile(WRAPPERS[word]).match(line, w.start(1))
            if not wrap:
                break
            i = wrap.end()
    return found


def python_programs(text):
    """The programs a Python file runs: in a call of a run helper (not restic's, whose words are its
    own subcommands), the first argument that is a string or a list, or *X, X or X[0] for one
    assigned to X. run_in(repo, uid, "make") skips the two before; run(*cfg["x"]) is hb.toml's."""
    tree = ast.parse(text)
    assigned = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tg in node.targets:
                if isinstance(tg, ast.Name):
                    assigned.setdefault(tg.id, []).append(node.value)

    def heads(node, depth=0):
        """The programs node names as a command's first word: None when it isn't a string or list."""
        if depth > 5:
            return None
        if isinstance(node, ast.Constant):
            return {node.value} if isinstance(node.value, str) else None
        if isinstance(node, (ast.List, ast.Tuple)):
            return heads(node.elts[0], depth + 1) if node.elts else None
        if isinstance(node, ast.Starred):
            return heads(node.value, depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return heads(node.left, depth + 1)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            return heads(node.value, depth + 1)
        if isinstance(node, ast.Name) and node.id in assigned:
            found = [heads(v, depth + 1) for v in assigned[node.id]]
            found = [f for f in found if f is not None]
            return set().union(*found) if found else None
        return None

    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name):
            helper = f.id
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id != "restic":
            helper = f.attr                          # restic.run("ls") is restic's ls
        else:
            continue
        if helper not in HELPERS:
            continue
        for arg in node.args:
            found = heads(arg)
            if found is not None:
                names |= {os.path.basename(n) for n in found if PROGRAM.fullmatch(n)}
                break
            if isinstance(arg, ast.Starred):         # run(*cfg["command"]): whatever hb.toml says
                break
    names |= {os.path.basename(p) for p in PY_PATH.findall(text)}
    return names


def scan():
    """{program: the files that run it}, as far as a scan of the source can tell."""
    found = {}
    files = [os.path.join(REPO, "tools", f) for f in os.listdir(os.path.join(REPO, "tools"))]
    files += [os.path.join(REPO, d, f) for d in ("busy.d", "hooks") for f in os.listdir(os.path.join(REPO, d))]
    files += [os.path.join(REPO, "lib", "hb.sh"), os.path.join(REPO, "hb")]
    # not needs.py (its table names every program) nor config.py (data: process names, a shell)
    files += [os.path.join(REPO, "lib", "hbkit", f) for f in os.listdir(os.path.join(REPO, "lib", "hbkit"))
              if f.endswith(".py") and f not in ("needs.py", "config.py")]
    with open(os.path.join(REPO, "lib", "hb.sh")) as f:
        shared = set(re.findall(r"^\s*([a-z_][a-z0-9_]*)\(\)", f.read(), re.M))
    for path in files:
        if not os.path.isfile(path):
            continue
        with open(path, errors="replace") as f:
            text = f.read()
        if path.endswith(".py") or "python" in text.split("\n", 1)[0]:
            names = python_programs(text)
        else:
            funcs = shared | set(re.findall(r"^\s*([a-z_][a-z0-9_]*)\(\)", text, re.M))
            arrays = shell_arrays(text)
            names = {w for line in shell_code(text) for w in shell_commands(line, arrays)} - funcs - SHELL
        for n in names - NOT_PROGRAMS:
            found.setdefault(n, set()).add(os.path.relpath(path, REPO))
    return found


class EveryProgramIsListedTest(unittest.TestCase):
    """A program a tool runs has to be in needs.py's table, so hb install can say when it's missing.

    The scan reads the source, so a name counts only when it is a program on this host's PATH: a
    program the test host lacks goes unseen, and the second test makes sure the scan does see the
    table's programs that are here."""

    def table_programs(self):
        return {n for need in needs.TABLE if need.find is needs.program for n in need.names}

    def test_every_program_is_in_the_table(self):
        known = self.table_programs() | {"microk8s"}
        programs = on_path()
        unknown = {n: sorted(f) for n, f in scan().items() if n in programs and n not in known}
        self.assertEqual(unknown, {}, "programs the tools run that lib/hbkit/needs.py doesn't list")

    def test_the_scan_sees_the_tables_programs(self):
        # Fable review 3: a scan that misses programs passes whatever the table lacks
        seen, programs = set(scan()), on_path()
        exempt = {"mdadm"}       # hb runs the mdmonitor service it comes with, not mdadm itself
        unseen = sorted(n for n in self.table_programs() if n in programs and n not in seen and n not in exempt)
        files = {f for fs in scan().values() for f in fs}
        self.assertFalse({"lib/hbkit/needs.py", "lib/hbkit/config.py"} & files)   # their lists are data
        self.assertEqual(unseen, [], "programs in the table that the scan doesn't find in any tool")

    def test_the_scan_takes_shell_apart(self):
        # Fable review 4: assignments, case labels and messages are no commands
        line = shell_code('host="$(readlink -f x)"; links=1 ls -l | xargs -r -n1 basename\n'
                          '  check|status) timeout 3 nsenter --net=x -- ip route ;;\n'
                          'echo "will install: (curl later)"; ! grep -q x && { sort; }\n'
                          "unshare --mount -- bash -c '\n  mount --bind a b\n'\n"
                          'k() { "$MK" kubectl "$@"; }; "${PY[@]}" write x\n'
                          'ITEMS=(needs code link); env+=("x=1"); local -a a=(b c)\n')
        found = [w for ln in line for w in shell_commands(ln)]
        for w in ("readlink", "ls", "xargs", "basename", "timeout", "nsenter", "ip", "grep", "sort", "unshare",
                  "bash", "mount"):
            self.assertIn(w, found)
        for w in ("host", "links", "check", "status", "curl", "install", "kubectl", "write", "needs", "code", "b"):
            self.assertNotIn(w, found)
        # Codex follow-ups review: an array runs what it starts with; one over several lines is data
        text = ('CURL=(curl -fsS)\nPY=(/usr/bin/python3 -IB "$X")\nLIST=(\n  code\n  info\n)\n'
                'out="$("${CURL[@]}" https://example.test)"; timeout 5 "${PY[@]}" sub\n'
                'for x in "${LIST[@]}"; do :; done\n')
        arrays = shell_arrays(text)
        found = {w for ln in shell_code(text) for w in shell_commands(ln, arrays)} - SHELL
        self.assertEqual(sorted(found), ["curl", "python3", "timeout"])

    def test_the_scan_takes_python_apart(self):
        # Codex review 2: a list of words is no command until something runs it
        self.assertEqual(python_programs('LEVELS = ("info", "warn")\nlevel = ["info", "x"]\n'), set())
        self.assertEqual(python_programs('cmd = ["dnf", "x"]\nutil.run(*cmd, timeout=3)\n'), {"dnf"})
        self.assertEqual(python_programs('args = ["ls", "-l"]\nrestic.run(*args)\n'), set())
        self.assertEqual(python_programs('T = ("tmux", "new")\nos.execvp(T[0], T)\n'), {"tmux"})
        self.assertEqual(python_programs('K = ["/snap/bin/microk8s", "kubectl"]\nrun(*K, "get")\n'), {"microk8s"})
        self.assertEqual(python_programs('run_in(repo, uid, "make", "clean")\n'), {"make"})
        # Codex follow-ups review: unpacking data runs nothing; every run helper counts
        self.assertEqual(python_programs('LEVELS = ("info", "warn")\nprint(*LEVELS)\nx = {*LEVELS}\n'), set())
        self.assertEqual(python_programs('cmd = ["curl", "-f"]\nsubprocess.check_call(cmd)\n'), {"curl"})
        self.assertEqual(python_programs('KEYGEN = "ssh-keygen"\nsubprocess.run([KEYGEN, *args])\n'), {"ssh-keygen"})
        self.assertEqual(python_programs('subprocess.Popen([util.HB, "notify", "send"])\n'), set())
        self.assertEqual(python_programs('util.run(*cfg["sms_command"], "x")\n'), set())


if __name__ == "__main__":
    unittest.main()
