"""What every hb Python tool does first: run on Python 3.11 or newer, and end quietly when
the pipe it prints into closes.

Every Python tool imports this before anything else from hbkit.

Python: when the interpreter is older (Amazon Linux 2023 keeps /usr/bin/python3 at 3.9 for
its whole life, and its guide says not to repoint that link), the tool is re-run under the
newest /usr/bin/python3.N that is 3.11 or newer, with the same -I -B flags, arguments,
environment and open files. Nothing is looked up on PATH.

Closed pipe: `hb health status | head -3` closes the pipe while the tool still prints. The
tool then ends with exit 141 (as a shell tool killed by SIGPIPE would) and no traceback. Only
when its standard output is the pipe that closed: any other BrokenPipeError (a peer that hung
up) still shows its traceback. SIGPIPE itself stays ignored, as Python sets it, so writing to a
child process that has exited remains an error the tool sees, not a silent death.

This file must stay valid Python 3.9: it is the one part that runs there.
"""
import glob
import os
import re
import select
import sys

NEED = (3, 11)


def newest(pattern="/usr/bin/python3.*"):
    """The newest executable python3.N matching pattern with N >= NEED's minor, or None."""
    best = None
    for path in glob.glob(pattern):
        m = re.fullmatch(r"python3\.([0-9]+)", os.path.basename(path))
        if m and int(m.group(1)) >= NEED[1] and os.access(path, os.X_OK):
            if best is None or int(m.group(1)) > best[0]:
                best = (int(m.group(1)), path)
    return best[1] if best else None


if sys.version_info < NEED:
    _py = newest()
    if not _py:
        sys.stderr.write(f"hb needs Python {NEED[0]}.{NEED[1]} or newer and this is {sys.version.split()[0]}: "
                         "install one (on Amazon Linux 2023: dnf install python3.13)\n")
        sys.exit(2)
    os.execv(_py, [_py, "-I", "-B", os.path.abspath(sys.argv[0])] + sys.argv[1:])


def stdout_closed():
    """Is standard output a pipe nobody reads any more? (Linux reports POLLERR then.)"""
    try:
        poll = select.poll()
        poll.register(sys.stdout.fileno(), select.POLLOUT)
        return any(events & select.POLLERR for _, events in poll.poll(0))
    except (OSError, ValueError, AttributeError):
        return False


def _excepthook(kind, value, tb, _default=sys.excepthook):
    if issubclass(kind, BrokenPipeError) and stdout_closed():
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())   # nothing left to flush
        except (OSError, ValueError):
            pass
        os._exit(141)
    _default(kind, value, tb)


sys.excepthook = _excepthook
