"""What root does next to a user it shouldn't trust, tested with two real uids.

A user namespace maps 0 to a subordinate uid and leaves the caller as itself, so root's files
really are out of the user's reach, as on a server. The tests re-run this file inside it
(--inner CASE ME GID), on a private tmpfs over /var/tmp; each case asserts what it expects.
Skipped where there are no subordinate uids. Plain tests of write_atomic run everywhere.
"""
import contextlib
import io
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tools import REPO, load_tool  # noqa: E402
from hbkit import util  # noqa: E402

ME, GID = os.getuid(), os.getgid()
OLD = int(time.time() - 40 * 86400)
TMP = "/var/tmp"


# --- outside the namespace -------------------------------------------------------------------

def subid(path):
    """The first subordinate id of this user, or None."""
    try:
        name = pwd.getpwuid(ME).pw_name
        with open(path) as f:
            for line in f:
                who, start, _ = line.strip().split(":")
                if who in (name, str(ME)):
                    return int(start)
    except (OSError, ValueError, KeyError):
        pass
    return None


def namespace(*cmd):
    sub, subg = subid("/etc/subuid"), subid("/etc/subgid")
    return ["unshare", "--user", f"--map-users=0:{sub}:1", f"--map-users={ME}:{ME}:1",
            f"--map-groups=0:{subg}:1", f"--map-groups={GID}:{GID}:1",
            "--setuid", "0", "--setgid", "0", "--mount", "--", *cmd]


def two_users():
    if ME == 0 or subid("/etc/subuid") is None or subid("/etc/subgid") is None:
        return False
    try:
        return subprocess.run(namespace("true"), capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class WriteAtomicTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.path = os.path.join(self.d, "f")

    def test_mode_is_exact_whatever_the_umask(self):
        old = os.umask(0o077)
        self.addCleanup(os.umask, old)
        util.write_atomic(self.path, "x", mode=0o644)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)

    def test_a_link_at_the_path_is_replaced_not_followed(self):
        other = os.path.join(self.d, "other")
        with open(other, "w") as f:
            f.write("keep")
        os.symlink(other, self.path)
        util.write_atomic(self.path, "new")
        self.assertFalse(os.path.islink(self.path))
        with open(other) as f:
            self.assertEqual(f.read(), "keep")

    def test_nothing_left_behind(self):
        util.write_atomic(self.path, "x")
        self.assertEqual(os.listdir(self.d), ["f"])
        real = os.replace
        self.addCleanup(setattr, os, "replace", real)

        def fail(*a):
            raise OSError("no")
        os.replace = fail
        with self.assertRaises(OSError):
            util.write_atomic(self.path, "y")
        self.assertEqual(os.listdir(self.d), ["f"])

    def test_bare_file_name(self):
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.d)
        util.write_atomic("f", "x")
        self.assertTrue(os.path.exists(self.path))


@unittest.skipUnless(two_users(), "needs subordinate uids (unshare, newuidmap)")
class TwoUsersTest(unittest.TestCase):
    def inner(self, case):
        p = subprocess.run(namespace(sys.executable, "-B", os.path.abspath(__file__), "--inner", case, str(ME), str(GID)),
                           capture_output=True, text=True, timeout=180, cwd="/")
        self.assertEqual(p.returncode, 0, f"\n{p.stdout}\n{p.stderr}")

    def test_write_atomic_ignores_planted_links(self):
        self.inner("write_atomic")

    def test_clean_leaves_swapped_repos_alone(self):
        self.inner("clean_swapped")

    def test_clean_keeps_the_owners_rights_even_past_the_check(self):
        self.inner("clean_rights")

    def test_clean_with_other_users_folders(self):
        self.inner("clean_foreign")

    def test_clean_skips_roots_repos(self):
        self.inner("clean_root_repo")

    def test_clean_caches(self):
        self.inner("clean_caches")

    @unittest.skipUnless(shutil.which("tmux"), "no tmux")
    def test_busy_tmux_still_sees_a_users_panes(self):
        self.inner("tmux_real")

    def test_busy_tmux_asks_as_the_socket_owner(self):
        self.inner("tmux_owner")

    def test_kit_folder_is_roots_until_handed_over(self):
        self.inner("kit")

    def test_kit_notices_its_folder_being_replaced(self):
        self.inner("kit_swapped")

    def test_kit_ignores_a_folder_above_being_replaced(self):
        self.inner("kit_ancestor")


# --- inside the namespace --------------------------------------------------------------------

def as_user(script):
    """Run a shell script as the ordinary user."""
    subprocess.run(["sh", "-ec", script], check=True, user=ME, group=GID, extra_groups=[], cwd="/",
                   env={"PATH": os.environ["PATH"], "HOME": f"{TMP}/nh"})


def root_file(path, text="root's\n", mode=0o600):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def assert_untouched(path, text="root's\n", mode=0o600):
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode) and st.st_uid == 0, f"{path}: uid {st.st_uid}, mode {st.st_mode:o}"
    assert stat.S_IMODE(st.st_mode) == mode, f"{path}: mode {st.st_mode:o}"
    with open(path) as f:
        got = f.read()
    assert got == text, f"{path} now holds {got!r}"


def user_dir(path):
    os.makedirs(path)
    os.chown(path, ME, GID)


def user_repo(path, extra=""):
    """A git repo of the user's with an ignored build/ folder, idle for 40 days."""
    as_user(f"mkdir -p {path}/build; cd {path}; git init -q; echo build/ > .gitignore; echo x > f; echo o > build/o;"
            f"git add .gitignore f; git -c user.email=t@t -c user.name=t commit -qm i; {extra}")


def age(*paths):
    as_user(f"find {' '.join(paths)} -exec touch -h -d @{OLD} {{}} + || true")     # root's files stay as they are


def clean_cfg(*roots):
    return {"project_roots": list(roots), "users": ["someone"], "idle_days": 14, "venv_idle_days": 90,
            "build_dirs": ["build"], "cache_idle_days": 30, "docker": False}


def case_write_atomic():
    target, d = f"{TMP}/secret", f"{TMP}/state"
    root_file(target)
    user_dir(d)
    path = f"{d}/public"
    as_user(f"ln -s {target} {path}; ln -s {target} {path}.tmp{os.getpid()}")
    util.write_json(path, {"until": 1}, mode=0o644)
    assert_untouched(target)
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o644


def case_clean_swapped():
    """An earlier repo's own cleanup script swaps the later repos, so the swap always lands in
    time: both must be refused, and nothing may run or go outside the user's own files."""
    clean = load_tool("clean")
    first, second, outside = f"{TMP}/first", f"{TMP}/second", f"{TMP}/outside"
    user_dir(first)
    user_dir(second)
    os.makedirs(f"{outside}/build")
    root_file(f"{outside}/build/keep")
    user_repo(f"{first}/a", extra=f"""cat > .hb-clean <<S
#!/bin/sh
cd {second}
mv b b.real; ln -s {outside} b
mv c c.real; ln -s {TMP} c
printf '#!/bin/sh\\nid -u > {TMP}/ran\\n' > {TMP}/.hb-clean; chmod 755 {TMP}/.hb-clean
S
chmod +x .hb-clean""")
    user_repo(f"{second}/b")
    user_repo(f"{second}/c", extra='printf "#!/bin/sh\\n" > .hb-clean; chmod +x .hb-clean')
    age(first, second)
    actions, _ = clean.plan_projects(clean_cfg(first, second), time.time())
    assert len(actions) == 3, [a.desc for a in actions]
    errors, _ = clean.apply(actions, yes=True)
    assert len(errors) == 2 and all("changed since the plan" in e for e in errors), errors
    assert_untouched(f"{outside}/build/keep")
    assert not os.path.exists(f"{TMP}/ran"), "a file from the swapped-in folder ran"


def case_clean_rights():
    """The check above is a courtesy; the real line is the uid. Take the check away and swap anyway."""
    clean = load_tool("clean")
    clean.unchanged = lambda path, uid: True
    base = f"{TMP}/base"
    user_dir(base)
    as_user(f"printf '#!/bin/sh\\nid -u > {TMP}/ran\\n' > {TMP}/.hb-clean; chmod 755 {TMP}/.hb-clean;"
            f"ln -s {TMP} {base}/r")
    clean.run_in(f"{base}/r", ME, f"{base}/r/.hb-clean")()
    with open(f"{TMP}/ran") as f:
        assert f.read().strip() == str(ME), "ran with someone else's uid"

    outside = f"{TMP}/outside"
    os.makedirs(f"{outside}/build")
    root_file(f"{outside}/build/keep")
    as_user(f"ln -s {outside} {base}/d")
    try:
        clean.remove([f"{base}/d/build"], f"{base}/d", ME)()
    except RuntimeError as e:
        assert "rm " in str(e), e
    else:
        raise AssertionError("rm reported success on root's folder")
    assert_untouched(f"{outside}/build/keep")


def case_clean_foreign():
    clean = load_tool("clean")
    root = f"{TMP}/projects"
    user_dir(root)
    user_repo(f"{root}/kept")
    os.mkdir(f"{root}/kept/build/from-a-container")
    root_file(f"{root}/kept/build/from-a-container/o")
    user_repo(f"{root}/goes", extra="mkdir build/ro; echo x > build/ro/f; chmod 555 build/ro")
    root_file(f"{root}/goes/build/made-by-root")       # a file, in a folder of the user's: theirs to delete
    age(root)
    actions, notes = clean.plan_projects(clean_cfg(root), time.time())
    assert [os.path.basename(a.desc.split(":")[0]) for a in actions] == ["goes"], [a.desc for a in actions]
    assert any(n.startswith(f"kept {root}/kept/build") and "from-a-container" in n for n in notes), notes
    assert clean.apply(actions, yes=True)[0] == []
    assert not os.path.exists(f"{root}/goes/build")
    assert_untouched(f"{root}/kept/build/from-a-container/o")


def case_clean_root_repo():
    clean = load_tool("clean")
    root = f"{TMP}/projects"
    user_dir(root)
    os.makedirs(f"{root}/roots/.git")
    root_file(f"{root}/roots/.hb-clean", "#!/bin/sh\n", 0o755)
    actions, notes = clean.plan_projects(clean_cfg(root), time.time())
    assert actions == [], [a.desc for a in actions]
    assert any("owned by root" in n for n in notes), notes


def case_clean_caches():
    clean = load_tool("clean")
    home = f"{TMP}/home"
    user_dir(home)
    as_user(f"mkdir -p {home}/.cache/old/ro; echo x > {home}/.cache/old/ro/f; chmod 555 {home}/.cache/old/ro;"
            f"mkdir {home}/.cache/mixed")
    os.mkdir(f"{home}/.cache/mixed/roots")
    root_file(f"{home}/.cache/mixed/roots/f")
    age(f"{home}/.cache/old")
    os.utime(f"{home}/.cache/mixed/roots/f", (OLD, OLD))
    os.utime(f"{home}/.cache/mixed/roots", (OLD, OLD))
    os.utime(f"{home}/.cache/mixed", (OLD, OLD))
    real = clean.pwd

    class FakePwd:
        getpwuid = staticmethod(real.getpwuid)

        @staticmethod
        def getpwnam(name):
            return type("pw", (), {"pw_dir": home, "pw_uid": ME})

    clean.pwd = FakePwd
    actions, notes = clean.plan_caches(clean_cfg(), time.time())
    assert [a.desc.split(" ")[0] for a in actions] == [f"{home}/.cache/old"], [a.desc for a in actions]
    assert any(n.startswith(f"kept {home}/.cache/mixed") for n in notes), notes
    assert clean.apply(actions, yes=True)[0] == []
    assert not os.path.exists(f"{home}/.cache/old")
    assert_untouched(f"{home}/.cache/mixed/roots/f")


def run_busy_tmux(**env):
    return subprocess.run([os.path.join(REPO, "busy.d", "tmux")], capture_output=True, text=True, timeout=30,
                          env={**os.environ, "HB_TMUX_DIR": f"{TMP}/tm", **env})


def case_tmux_real():
    d = f"{TMP}/tm/tmux-u"
    os.makedirs(f"{TMP}/tm")
    user_dir(d)
    user_dir(f"{TMP}/nh")
    sock = f"{d}/default"
    as_user(f"tmux -S {sock} -f /dev/null new-session -d -s web sleep 60")
    try:
        p = run_busy_tmux()
        assert (p.returncode, p.stdout.strip()) == (1, "tmux session web runs sleep"), (p.returncode, p.stdout, p.stderr)
    finally:
        as_user(f"tmux -S {sock} kill-server || true")


def case_tmux_owner():
    """Who runs the client, with a stand-in for tmux that records it."""
    shim, log = f"{TMP}/shim", f"{TMP}/shim.log"
    os.mkdir(shim)
    root_file(f"{shim}/tmux", f'#!/bin/sh\necho "$(id -u) $(id -G) $2 ${{LEAK:-clean}}" >> {log}\n', 0o755)
    root_file(log, "", 0o666)
    os.makedirs(f"{TMP}/tm/tmux-r")
    user_dir(f"{TMP}/tm/tmux-u")
    for path, owner in ((f"{TMP}/tm/tmux-r/default", 0), (f"{TMP}/tm/tmux-u/default", ME)):
        s = socket.socket(socket.AF_UNIX)
        s.bind(path)
        s.close()
        os.lchown(path, owner, 0 if owner == 0 else GID)
    os.chmod(f"{TMP}/tm/tmux-r", 0o755)
    as_user(f"ln -s {TMP}/tm/tmux-r/default {TMP}/tm/tmux-u/link")   # a link isn't a socket of the user's
    p = run_busy_tmux(PATH=f"{shim}:{os.environ['PATH']}", LEAK="leaked")
    assert p.returncode == 0, p.stderr
    with open(log) as f:
        lines = f.read().splitlines()
    assert lines == [f"0 0 {TMP}/tm/tmux-r/default clean", f"{ME} {GID} {TMP}/tm/tmux-u/default clean"], lines


def kit_tool(sleep=0.0):
    bg = load_tool("breakglass")
    util.STATE = f"{TMP}/state"
    os.makedirs(util.STATE, exist_ok=True)
    keydir = f"{TMP}/keys"
    os.makedirs(keydir, exist_ok=True)

    def fake_run(*cmd, **kw):
        if cmd[:2] == ("sshd", "-T"):
            return 0, f"authorizedkeysfile {keydir}/%u\n", ""
        if cmd[0].endswith("/hb") and cmd[1:3] == ("totp", "codes"):
            time.sleep(sleep)
            return 0, "\n".join(f"CODE{i}-XXXXX" for i in range(10)), ""
        if cmd[0] == "ssh-keygen":
            return 0, "256 SHA256:hostkey root@x (ED25519)", ""
        return 0, "", ""

    util.run, util.ask, util.notify = fake_run, (lambda q: True), (lambda *a: None)
    util.sudo_user = lambda: pwd.getpwuid(ME).pw_name
    bg.KEYDIR, bg.ITEMS = keydir, (("account", lambda c: (0, "ok"), None),)
    return bg, {"breakglass": {"user": "rescue", "uid": 4700, "host": "h", "note": "", "test_days": 180},
                "backup": {"repo": "", "password_file": "/dev/null"}, "probe": {"host": ""}}


PLANTER = """
import os, sys, time
to, target = sys.argv[1:3]
refused, end = 0, time.time() + 30
while time.time() < end:
    try:
        if os.stat(to).st_uid == os.getuid():
            break
        os.symlink(target, to + "/planted")
        # in: still root's means early. Handed over between the two looks, it was theirs already
        if os.stat(to).st_uid != os.getuid():
            print("early")
            break
        os.unlink(to + "/planted")
        break
    except PermissionError:
        refused += 1
    except FileNotFoundError:
        pass
    time.sleep(0.005)
print(refused)
"""


def case_kit():
    bg, cfg = kit_tool(sleep=0.5)
    user_dir(f"{TMP}/nh")
    target, to = f"{TMP}/shadow", f"{TMP}/nh/kit"
    root_file(target)
    planter = subprocess.Popen([sys.executable, "-B", "-c", PLANTER, to, target], stdout=subprocess.PIPE, text=True,
                               user=ME, group=GID, extra_groups=[], cwd="/")
    time.sleep(0.2)
    rc = bg.do_kit(cfg, to)
    out = planter.communicate(timeout=40)[0]
    assert rc == 0, rc
    assert "early" not in out, "the user got a link into the kit's folder before it was theirs"
    assert not os.path.lexists(f"{to}/planted"), "the user got a link into the kit's folder before it was theirs"
    assert_untouched(target)
    st = os.stat(to)
    assert st.st_uid == ME and stat.S_IMODE(st.st_mode) == 0o700, st
    want = {"rescue.key": 0o600, "rescue.key.pub": None, "kit.txt": 0o600, "kit.html": 0o600}
    for name, mode in want.items():
        st = os.lstat(f"{to}/{name}")
        assert stat.S_ISREG(st.st_mode) and st.st_uid == ME, name
        assert mode is None or stat.S_IMODE(st.st_mode) == mode, (name, oct(st.st_mode))


def after_mkdir(name, script):
    """Run script as the user right after root creates a folder called name (by path or by descriptor)."""
    real = os.mkdir

    def mkdir(path, *a, **kw):
        real(path, *a, **kw)
        if os.path.basename(path) == name:
            as_user(script)
    os.mkdir = mkdir
    return lambda: setattr(os, "mkdir", real)


def case_kit_swapped():
    bg, cfg = kit_tool()
    user_dir(f"{TMP}/nh")
    elsewhere = f"{TMP}/elsewhere"
    os.mkdir(elsewhere)
    for name, swap in (("link", "mv {to} {to}.orig; ln -s %s {to}" % elsewhere),
                       ("own", "mv {to} {to}.orig; mkdir {to}")):
        to = f"{TMP}/nh/{name}"
        undo = after_mkdir(name, swap.format(to=to))
        assert bg.do_kit(cfg, to) == 2
        undo()
        assert os.listdir(elsewhere) == [], "kit files landed in the swapped-in folder"
        if name == "own":
            assert os.listdir(to) == [], "kit files landed in the user's replacement folder"


def case_kit_ancestor():
    """A folder of the user's above the kit is swapped for a link to a folder of root's, right after the
    kit's folder is made; and a link already in the path. Root's folders keep their owner and contents."""
    bg, cfg = kit_tool()
    user_dir(f"{TMP}/nh")
    rootdir = f"{TMP}/rootdir"                               # what the link points at: root's, with a kit inside
    os.makedirs(f"{rootdir}/b/kit")
    root_file(f"{rootdir}/b/kit/root-file")
    as_user(f"mkdir -p {TMP}/nh/a/b")
    undo = after_mkdir("kit", f"mv {TMP}/nh/a {TMP}/nh/a.old; ln -s {rootdir} {TMP}/nh/a")
    rc = bg.do_kit(cfg, f"{TMP}/nh/a/b/kit")
    undo()
    assert_untouched(f"{rootdir}/b/kit/root-file")
    for d in (rootdir, f"{rootdir}/b", f"{rootdir}/b/kit"):
        assert os.lstat(d).st_uid == 0, f"{d} was given away"
    assert sorted(os.listdir(f"{rootdir}/b/kit")) == ["root-file"], os.listdir(f"{rootdir}/b/kit")
    assert rc == 0, rc                                       # the kit went where the path pointed when it was opened
    assert os.lstat(f"{TMP}/nh/a.old/b/kit").st_uid == ME
    assert sorted(os.listdir(f"{TMP}/nh/a.old/b/kit")) == ["kit.html", "kit.txt", "rescue.key", "rescue.key.pub"]

    # a link already in the path: refused before anything is written
    rc = bg.do_kit(cfg, f"{TMP}/nh/a/b/kit2")               # nh/a is now the link to rootdir
    assert rc == 2, rc
    assert not os.path.lexists(f"{rootdir}/b/kit2"), "the kit followed a link of the user's"


def inner(case, me, gid):
    global ME, GID
    ME, GID = int(me), int(gid)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=1777", "tmpfs", TMP], check=True)
    # Only the groups the namespace can map, or setgroups() would refuse the user's real list.
    name = pwd.getpwuid(ME).pw_name
    with open(f"{TMP}/.group", "w") as f:
        f.write(f"{name}:x:{GID}:\n")
    subprocess.run(["mount", "--bind", f"{TMP}/.group", "/etc/group"], check=True)
    with contextlib.redirect_stdout(io.StringIO()) as out:
        try:
            globals()[f"case_{case}"]()
        except BaseException:
            print(out.getvalue(), file=sys.stderr)
            raise


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(*sys.argv[2:5])
    else:
        unittest.main()
