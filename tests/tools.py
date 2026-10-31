"""Load a tool script (tools/hb-*) as a module, with hb's state in a temp dir."""
import importlib.machinery
import importlib.util
import os
import sys
import tempfile

sys.dont_write_bytecode = True
REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(REPO, "lib"))
from hbkit import util  # noqa: E402


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
