"""Small helpers shared by hb's Python tools: running commands, state files, locks."""
import fcntl
import json
import os
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
