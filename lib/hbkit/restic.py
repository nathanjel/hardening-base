"""restic for hb's Python tools, always through `hb backup restic`, so the repository,
the password and the mount check live in one place (tools/hb-backup)."""
import json
import socket
import subprocess

from hbkit import util

COMMAND = [util.HB, "backup", "restic"]     # tests point this at restic itself


def host_args(host=None):
    """The filter for hb backup's snapshots: this host (or another), tag hb."""
    return ["--host", host or socket.gethostname().split(".")[0], "--tag", "hb"]


def run(*args, timeout=3600):
    return util.run(*COMMAND, *args, timeout=timeout)


def stream(*args):
    """Run with restic's own progress on the terminal; the exit code."""
    return subprocess.call(COMMAND + list(args))


def lines(*args):
    """Lines of output, read as they come (a snapshot listing can be large)."""
    p = subprocess.Popen(COMMAND + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        yield from p.stdout
    finally:
        p.stdout.close()
        err = p.stderr.read()
        p.stderr.close()
        if p.wait():
            raise RuntimeError(f"restic {args[0]} failed: {err.strip()[-300:]}")


def snapshot(spec="latest", host=None):
    """The snapshot named by spec (an ID, or latest for this host's newest), as restic's JSON."""
    args = ["snapshots", "--json"] + (["--latest", "1", *host_args(host)] if spec == "latest" else [spec])
    rc, out, err = run(*args, timeout=600)
    if rc:
        raise RuntimeError(f"restic snapshots failed: {(err or out).strip()[-300:]}")
    snaps = json.loads(out or "[]")
    if not snaps:
        raise RuntimeError("no snapshots yet (hb backup run)" if spec == "latest" else f"no snapshot {spec}")
    return snaps[-1]
