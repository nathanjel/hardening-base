"""Run hb's Python on 3.11 or newer, whatever /usr/bin/python3 is.

Every Python tool imports this first, before anything else from hbkit. When the
interpreter is older (Amazon Linux 2023 keeps /usr/bin/python3 at 3.9 for its whole
life, and its guide says not to repoint that link), the tool is re-run under the
newest /usr/bin/python3.N that is 3.11 or newer, with the same -I -B flags,
arguments, environment and open files. Nothing is looked up on PATH.

This file must stay valid Python 3.9: it is the one part that runs there.
"""
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
