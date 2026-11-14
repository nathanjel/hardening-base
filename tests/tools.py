"""Load a tool script (tools/hb-*) as a module, with hb's state in a temp dir.

Importing this also gives the test run a temp folder of its own: everything the tests make with
tempfile, and whatever the hb tools they start make in $TMPDIR, goes in it, and it is removed
when the run ends, so a run leaves nothing behind in /tmp."""
import atexit
import importlib.machinery
import importlib.util
import os
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(REPO, "lib"))
from hbkit import util  # noqa: E402

# a short name: tmux's socket path, under it, has to fit in 108 bytes
RUN_TMP = tempfile.mkdtemp(prefix="hb-tests-")
tempfile.tempdir = RUN_TMP
os.environ["TMPDIR"] = RUN_TMP


def _remove_run_tmp():
    def unblock(func, path, _exc):
        # a test may leave a folder without write or search permission for its owner
        try:
            os.chmod(os.path.dirname(path), 0o700)
            if os.path.isdir(path) and not os.path.islink(path):
                os.chmod(path, 0o700)
            func(path)
        except (OSError, TypeError):    # Python 3.14 may pass os.open, which needs flags: the next pass
            pass
    handler = {"onexc": unblock} if sys.version_info >= (3, 12) else {"onerror": unblock}
    shutil.rmtree(RUN_TMP, **handler)
    if os.path.isdir(RUN_TMP):      # what's still there (a folder chmod couldn't open): one more pass
        shutil.rmtree(RUN_TMP, ignore_errors=True)


atexit.register(_remove_run_tmp)


def load_tool(name):
    path = os.path.join(REPO, "tools", f"hb-{name}")
    loader = importlib.machinery.SourceFileLoader(f"hb_{name}", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def temp_state(testcase):
    """Point hbkit.util at a fresh state dir for the length of one test."""
    d = tempfile.mkdtemp()
    old = util.STATE
    util.STATE = d
    testcase.addCleanup(setattr, util, "STATE", old)
    return d
