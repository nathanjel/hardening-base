"""Small helpers shared by hb's Python tools: running commands, state files, locks."""
import fcntl
import json
import os
import re
import signal
import subprocess
import tempfile

HB_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
HB = os.path.join(HB_ROOT, "hb")
STATE = os.environ.get("HB_STATE", "/var/lib/hb")


def run(*cmd, timeout=30, input=None, **kw):
    """(exit code, stdout, stderr) of a command; 127 when missing, 124 on timeout."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input, **kw)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout}s"


def run_read(*cmd, **kw):
    """run() for a command that only reads, so it may simply run again: once more when a signal
    ended it (run's own timeout is 124, not a signal). A negative exit code from here means both
    tries ended that way. The signal comes from snap: it runs each microk8s and kubectl command
    in a systemd scope, under root's user manager while one runs. Root's sessions start that
    manager (cron's root jobs; sudo or su run by a service: a sudo inside a login opens none), and
    it stops after the last of them ends, ending its scopes (SIGTERM). A second try gets a scope of
    its own. k8s.linger_root keeps that manager running (hb k8s); this stays as the backstop."""
    rc, out, err = run(*cmd, **kw)
    if rc < 0:
        rc, out, err = run(*cmd, **kw)
    return rc, out, err


def signal_name(rc):
    """SIGTERM, for a process that exit code rc (negative) says a signal ended."""
    try:
        return signal.Signals(-rc).name
    except ValueError:
        return f"signal {-rc}"


def boot_time():
    """When this box last booted (epoch seconds, from /proc/stat), or 0 when that can't be read."""
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def boot_id():
    """This boot's id, which the kernel draws at random at every boot; "" when it can't be read."""
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return ""


def in_this_boot(at, boot, current=None):
    """Whether something recorded at `at` (epoch seconds), in the boot whose id is `boot`, happened
    since this box last booted. The id decides, against `current` (this boot's, read when not
    given). Without both (state written before hb kept the id, or one that can't be read) the boot
    time does, but that is only the clock minus the uptime: it moves when the clock is stepped
    (chrony does at boot), so it can put the boot after `at`."""
    current = boot_id() if current is None else current
    if boot and current:
        return boot == current
    return at > boot_time()


# The kernel's own packages: kernel-core (and the kernel meta package) on Fedora; kernel,
# kernel6.12, kernel6.18 on Amazon Linux 2023, which has no kernel-core. Never -headers,
# -tools, -devel or -modules-extra. `rpm -qa --qf KERNEL_QF 'kernel*'` lists candidates.
KERNEL_RPM = re.compile(r"kernel(-core|[0-9]+[.][0-9]+)?")
KERNEL_QF = "%{INSTALLTIME} %{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n"


def kernel_rows(out):
    """[(install time, version)] of the kernel packages in rpm's KERNEL_QF output, oldest first."""
    rows = []
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3 and p[0].isdigit() and KERNEL_RPM.fullmatch(p[1]):
            rows.append((int(p[0]), p[2]))
    return sorted(rows)


def boot_kernel_version(out):
    """The kernel the next boot starts, from `grubby --default-kernel` (/boot/vmlinuz-VERSION),
    or None. The newest installed kernel isn't necessarily that one (AL2023 keeps kernel and
    kernel6.12 side by side, and the default is chosen with grubby). Without root, grubby
    can print just "/boot" and still exit 0, so anything but a whole path counts as no answer."""
    m = re.fullmatch(r"/boot/vmlinuz-([0-9][^/\s]*)", out.strip())
    return m.group(1) if m else None


def state_dir(name):
    """/var/lib/hb/<name>, created root-only."""
    d = os.path.join(STATE, name)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_atomic(path, text, mode=0o600):
    """Replace path with text in one step, so readers never see half a file. The temporary file
    is new and randomly named, and a link at path is replaced, not written through."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=f".{os.path.basename(path)}.")
    try:
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), mode)
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path, data, mode=0o600):
    write_atomic(path, json.dumps(data, indent=1) + "\n", mode)


class Lock:
    """An exclusive flock on a file, held for the duration of a with-block."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        os.close(self.fd)


def ask(question):
    """y/N from the terminal, even with stdin redirected; False without one."""
    try:
        with open("/dev/tty") as tty:
            print(f"{question} [y/N] ", end="", flush=True)
            return tty.readline().strip().lower().startswith("y")
    except OSError:
        return False


def notify(level, key, text):
    """hb notify send: the banner always, an SMS for fail."""
    run(HB, "notify", "send", level, key, text, timeout=120)


def busy():
    """Why the box is busy now: the first line of each busy.d check that says so (empty: idle)."""
    d = os.path.join(HB_ROOT, "busy.d")
    reasons = []
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        path = os.path.join(d, name)
        if name.startswith(".") or not os.access(path, os.X_OK):
            continue
        rc, out, err = run(path, timeout=60, env=dict(os.environ, HB_ROOT=HB_ROOT))
        if rc != 0:
            reasons.append(((out.strip() or err.strip() or name).splitlines() or [name])[0])
    return reasons


def sudo_user():
    """Who ran sudo, or None."""
    u = os.environ.get("SUDO_USER", "")
    return u if u and u != "root" else None


# --- events: what hb-notify records and hb-status shows in the login banner ---

def events_path():
    return os.path.join(STATE, "notify", "events.jsonl")


def read_events(limit=None):
    """Recorded events, oldest first: dicts with ts, level, key, text."""
    out = []
    try:
        with open(events_path()) as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out[-limit:] if limit else out
