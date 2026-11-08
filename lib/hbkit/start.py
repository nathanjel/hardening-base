"""What every hb Python tool does first: run on Python 3.11 or newer, and end quietly when
the reader of its output goes away.

Every Python tool imports this before anything else from hbkit.

Python: when the interpreter is older (Amazon Linux 2023 keeps /usr/bin/python3 at 3.9 for
its whole life, and its guide says not to repoint that link), the tool is re-run under the
newest /usr/bin/python3.N that is 3.11 or newer, with the same -I -B flags, arguments,
environment and open files. Nothing is looked up on PATH.

Closed output: `hb health status | head -3` closes the pipe while the tool still prints.
sys.stdout is wrapped so that a broken pipe while writing or flushing it, and only there,
raises StdoutClosed. The tool unwinds as for any error (its finally blocks run), then ends
with exit 141, as a shell tool killed by SIGPIPE would, and without a traceback. Output still
buffered at exit is flushed before Python shuts down, so the same holds for it. Any other
broken pipe (a peer that hung up) still shows its traceback and exit status. SIGPIPE itself
stays ignored, as Python sets it, so writing to a child process that has exited remains an
error the tool sees. Writes that go around sys.stdout (sys.stdout.buffer) are not covered.

This file must stay valid Python 3.9: it is the one part that runs there.
"""
import atexit
import glob
import os
import re
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


class StdoutClosed(BrokenPipeError):
    """Nobody reads this tool's standard output any more."""


class _Stdout:
    """sys.stdout, with a broken pipe on it told apart from any other."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        try:
            return self._stream.write(text)
        except BrokenPipeError as e:
            raise StdoutClosed(*e.args) from None

    def flush(self):
        try:
            return self._stream.flush()
        except BrokenPipeError as e:
            raise StdoutClosed(*e.args) from None

    def __getattr__(self, name):
        return getattr(self._stream, name)


_crashed = []          # set when another error ended the tool: its exit status stays


def _silence():
    """Point fd 1 at /dev/null, so what is still buffered can go nowhere quietly."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), 1)
    except OSError:
        pass


def _quit():
    try:
        sys.stderr.flush()
    except (OSError, ValueError):
        pass
    _silence()
    os._exit(141)


def _excepthook(kind, value, tb, _default=sys.excepthook):
    if issubclass(kind, StdoutClosed):
        _quit()
    _crashed.append(kind)
    _default(kind, value, tb)


def _flush_at_exit():
    """Before Python's own last flush, whose failure only says "Exception ignored" (exit 120)."""
    try:
        sys.stdout.flush()
    except StdoutClosed:
        if not _crashed:
            _quit()
        _silence()
    except (OSError, ValueError):
        pass


if sys.stdout is not None and not isinstance(sys.stdout, _Stdout):
    sys.stdout = _Stdout(sys.stdout)
sys.excepthook = _excepthook
atexit.register(_flush_at_exit)
